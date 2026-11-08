#!/usr/bin/env python3
"""Local operator-managed TLS generations. No CA issuance or remote administration."""

import argparse, datetime, fcntl, hashlib, json, os, re, ssl, stat, uuid
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

VERSION = "openproof-tls-generation/1"


def read_regular(path, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        s = os.fstat(f.fileno())
        if (
            not stat.S_ISREG(s.st_mode)
            or s.st_size > 1024 * 1024
            or (private and s.st_mode & 0o077)
        ):
            raise ValueError(
                "Expected bounded regular file; TLS key must be owner-only"
            )
        raw = f.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("Certificate input limit")
    return raw


def inspect_certificate(path, warning_days=30, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cert = x509.load_pem_x509_certificate(read_regular(path))
    start = cert.not_valid_before_utc
    end = cert.not_valid_after_utc
    status = (
        "not_yet_valid"
        if now < start
        else (
            "expired"
            if now >= end
            else (
                "expiring"
                if (end - now).total_seconds() <= warning_days * 86400
                else "valid"
            )
        )
    )
    return {
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "not_before": start.isoformat(),
        "not_after": end.isoformat(),
        "seconds_remaining": int((end - now).total_seconds()),
        "status": status,
        "scope": "Local certificate inspection; chain/hostname authorization is checked during TLS, not established by this report.",
    }


def context(cert, key, ca, clients):
    if (
        not isinstance(clients, list)
        or not clients
        or len(clients) > 100
        or len(set(clients)) != len(clients)
        or any(
            not isinstance(x, str) or not re.fullmatch("[0-9a-f]{64}", x)
            for x in clients
        )
    ):
        raise ValueError("Explicit unique client fingerprints required")
    raw = read_regular(cert)
    leaf = x509.load_pem_x509_certificate(raw)
    read_regular(key, True)
    roots = x509.load_pem_x509_certificates(read_regular(ca))
    now = datetime.datetime.now(datetime.timezone.utc)
    if not roots or any(
        not c.not_valid_before_utc <= now < c.not_valid_after_utc
        for c in [leaf, *roots]
    ):
        raise ValueError("Certificate validity window rejected")
    if (
        ExtendedKeyUsageOID.SERVER_AUTH
        not in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    ):
        raise ValueError("Server authentication usage required")
    if any(
        not c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        for c in roots
    ):
        raise ValueError("CA bundle contains a non-CA certificate")
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.verify_mode = ssl.CERT_REQUIRED
    c.load_cert_chain(cert, key, password="")
    c.load_verify_locations(cafile=ca)
    return c, frozenset(clients)


def save(path, raw):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_generation(directory, generation):
    if not isinstance(generation, str) or not re.fullmatch("[0-9a-f]{32}", generation):
        raise ValueError("Invalid TLS generation")
    base = Path(directory) / "generations" / generation
    for folder in [Path(directory), base.parent, base]:
        if folder.is_symlink() or not folder.is_dir() or folder.stat().st_mode & 0o077:
            raise ValueError("TLS directories must be private and not symlinks")
    if base.is_symlink() or base.parent.is_symlink():
        raise ValueError("Symlink generation directory")
    m = json.loads(read_regular(base / "manifest.json"))
    if (
        set(m) != {"version", "generation", "files", "clients"}
        or m["version"] != VERSION
        or m["generation"] != generation
        or set(m["files"]) != {"server.pem", "server.key", "ca.pem"}
    ):
        raise ValueError("Invalid TLS manifest")
    for name, digest in m["files"].items():
        if (
            hashlib.sha256(read_regular(base / name, name == "server.key")).hexdigest()
            != digest
        ):
            raise ValueError("TLS generation changed")
    policy = context(
        base / "server.pem", base / "server.key", base / "ca.pem", m["clients"]
    )
    return m, policy


def current(directory):
    p = Path(directory) / "current.json"
    if not p.exists() and not p.is_symlink():
        return None
    value = json.loads(read_regular(p))
    if set(value) != {"version", "generation"} or value["version"] != VERSION:
        raise ValueError("Invalid TLS pointer")
    return value["generation"]


def active_policy(directory):
    g = current(directory)
    if g is None:
        raise ValueError("No active TLS generation")
    return g, load_generation(directory, g)[1]


def stage(directory, cert, key, ca, clients):
    context(cert, key, ca, clients)
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.stat().st_mode & 0o077:
        raise ValueError("TLS directory must be owner-only")
    generations = directory / "generations"
    generations.mkdir(exist_ok=True, mode=0o700)
    if generations.is_symlink() or generations.stat().st_mode & 0o077:
        raise ValueError("TLS generations directory must be private and not a symlink")
    generation = uuid.uuid4().hex
    base = generations / generation
    base.mkdir(mode=0o700)
    files = {}
    for source, name in [(cert, "server.pem"), (key, "server.key"), (ca, "ca.pem")]:
        raw = read_regular(source, name == "server.key")
        save(base / name, raw)
        files[name] = hashlib.sha256(raw).hexdigest()
    save(
        base / "manifest.json",
        (
            json.dumps(
                {
                    "version": VERSION,
                    "generation": generation,
                    "files": files,
                    "clients": clients,
                },
                indent=2,
            )
            + "\n"
        ).encode(),
    )
    sync_dir(base)
    sync_dir(generations)
    load_generation(directory, generation)
    return {
        "generation": generation,
        "activated": False,
        "expected_current": current(directory),
    }


def activate(directory, generation, expected_current):
    directory = Path(directory).resolve()
    fd = os.open(directory / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        if current(directory) != expected_current:
            raise ValueError("Active generation changed; inspect before activating")
        load_generation(directory, generation)
        temp = directory / (".current-" + uuid.uuid4().hex)
        save(
            temp,
            (
                json.dumps({"version": VERSION, "generation": generation}) + "\n"
            ).encode(),
        )
        os.replace(temp, directory / "current.json")
        sync_dir(directory)
    finally:
        os.close(fd)
    return {
        "generation": generation,
        "activated": True,
        "scope": "Local TLS configuration only; not role-signing key rotation",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="operation", required=True)
    i = sub.add_parser("inspect")
    i.add_argument("certificates", nargs="+")
    i.add_argument("--warning-days", type=int, default=30)
    c = sub.add_parser("check")
    c.add_argument("--directory", required=True)
    s = sub.add_parser("stage")
    s.add_argument("--directory", required=True)
    for name in ["cert", "key", "ca"]:
        s.add_argument("--" + name, required=True)
    s.add_argument("--client-fingerprint", action="append", required=True)
    a = sub.add_parser("activate")
    a.add_argument("--directory", required=True)
    a.add_argument("--generation", required=True)
    a.add_argument(
        "--expected-current",
        required=True,
        help="Exact previous generation, or none for first activation",
    )
    x = p.parse_args()
    if x.operation == "inspect":
        if not 0 <= x.warning_days <= 3650:
            p.error("warning-days must be 0..3650")
        result = [
            dict(certificate=str(path), **inspect_certificate(path, x.warning_days))
            for path in x.certificates
        ]
        print(json.dumps(result, indent=2))
        return int(any(r["status"] != "valid" for r in result))
    if x.operation == "check":
        g, policy = active_policy(x.directory)
        r = inspect_certificate(Path(x.directory) / "generations" / g / "server.pem")
        print(
            json.dumps(
                dict(generation=g, authorized_client_count=len(policy[1]), **r),
                indent=2,
            )
        )
        return int(r["status"] != "valid")
    result = (
        stage(x.directory, x.cert, x.key, x.ca, x.client_fingerprint)
        if x.operation == "stage"
        else activate(
            x.directory,
            x.generation,
            None if x.expected_current == "none" else x.expected_current,
        )
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
