#!/usr/bin/env python3
"""Original signed local build evidence; no SLSA level or independent builder claim."""

import argparse, hashlib, json, os, stat, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference/python"))
import openproof_ref as ref
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DOMAIN = b"OpenProof/v1/local-build-evidence/2\0"
OLD_DOMAIN = b"OpenProof/v1/local-build-evidence/1\0"
FILES = [
    "openproof",
    "openproof-witness",
    "provenance.json",
    "source-manifest.json",
    "steps.json",
    "openproof-go-verify",
]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def payload(validation, builder, version=2):
    v = Path(validation)
    ref.text(builder)
    steps = ref.read(v / "steps.json")
    if not steps or any(s["exit_code"] != 0 for s in steps):
        raise ValueError("validation failed")
    if version not in [1, 2]:
        raise ValueError("Unknown build evidence version")
    files = FILES if version == 2 else FILES[:-1]
    return dict(
        version="openproof-local-build/" + str(version),
        builder=builder,
        artifacts={n: digest(v / n) for n in files},
    )


def sign(validation, key, builder, out):
    fd = os.open(key, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        m = os.fstat(f.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_mode & 0o077:
            raise ValueError("private regular key required")
        raw = f.read(257)
    seed = ref.hx(raw.decode().strip(), 32)
    p = payload(validation, builder)
    result = dict(
        payload=p,
        signature=Ed25519PrivateKey.from_private_bytes(seed)
        .sign(DOMAIN + ref.canonical(p))
        .hex(),
    )
    with Path(out).open("x") as f:
        json.dump(result, f, indent=2)
    return result


def verify(validation, envelope, key, builder, source):
    s = ref.read(envelope)
    ref.fields(s, ["payload", "signature"])
    version = {"openproof-local-build/1": 1, "openproof-local-build/2": 2}.get(
        s["payload"].get("version")
    )
    expected = payload(validation, builder, version)
    ref.hx(source, 32)
    if (
        expected["artifacts"]["source-manifest.json"] != source
        or s["payload"] != expected
    ):
        raise ValueError("build identity or artifacts mismatch")
    signature = ref.hx(s["signature"], 64)
    ref.public(key).verify(
        signature, (DOMAIN if version == 2 else OLD_DOMAIN) + ref.canonical(expected)
    )
    return {
        "status": "local_build_signature_verified",
        "builder": builder,
        "independent_builder": False,
        "slsa_level_claimed": False,
    }


def main():
    a = argparse.ArgumentParser()
    sub = a.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("sign")
    p.add_argument("--key", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("verify")
    p.add_argument("--evidence", required=True)
    p.add_argument("--public-key", required=True)
    p.add_argument("--source-sha256", required=True)
    for p in sub.choices.values():
        p.add_argument("--validation", required=True)
        p.add_argument("--builder", required=True)
    x = a.parse_args()
    if x.cmd == "sign":
        sign(x.validation, x.key, x.builder, x.out)
        print("Signed local evidence")
    else:
        print(
            json.dumps(
                verify(
                    x.validation, x.evidence, x.public_key, x.builder, x.source_sha256
                )
            )
        )


if __name__ == "__main__":
    main()
