#!/usr/bin/env python3
"""Python bindings for the OpenProof binary, for tests, tools and the legacy
trust upgrade. The broker, the owner app, the agent tools and the role
services are in Rust (`openproof-witness`); this module only calls them.
"""

import argparse, json, os, re, subprocess, sys, time, uuid, fcntl
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target/debug/openproof-witness"
sys.path.insert(0, str(ROOT / "reference/python"))
import openproof_ref as ref

# The binary gets no inherited secrets: only the search path and home.
ENV = {k: v for k, v in os.environ.items() if k in {"PATH", "HOME"}}


def call(args, value=None):
    # The binary sends role commands to the owner-configured role services
    # itself when the home has a service-client.json.
    raw = (
        None
        if value is None
        else json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    )
    if raw and len(raw) > ref.MAX:
        raise ValueError("input limit")
    r = subprocess.run(
        [str(BINARY), *map(str, args)],
        input=raw,
        # Never pass a terminal through: a command without input reads nothing.
        stdin=None if raw is not None else subprocess.DEVNULL,
        capture_output=True,
        env=ENV,
        timeout=20,
    )
    if r.returncode:
        raise RuntimeError(r.stderr.decode(errors="replace")[:1000])
    return ref.load_bytes(r.stdout)


def save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(value, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())


def initialize(home):
    return call(["init-home", Path(home)])


@contextmanager
def home_lock(home):
    # One lock inode per private home; never unlink it. All broker processes cooperate.
    fd = os.open(
        Path(home) / ".broker.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def serialized(method):
    @wraps(method)
    def run(self, *args, **kwargs):
        with home_lock(self.home):
            return method(self, *args, **kwargs)

    return run


def checked(identity):
    if not isinstance(identity, str) or not re.fullmatch("[0-9a-f]{64}", identity):
        raise ValueError("invalid proposal id")
    return identity


def gate_list(home):
    """Proposals, passkey-pending and approved entries in the gate (no content)."""
    return call(["gate-list", Path(home)])


def approved_request(home, identity):
    """The gate's approved request, checked by the gate when read."""
    home = Path(home)
    r = call(["gate-approved", home, home / "trust.json", checked(identity)])
    if r["state"] != "approved":
        raise FileNotFoundError("proposal is not approved")
    return r["request"]


class Broker:
    """Calls the Rust broker. Only `approve` (terminal approval) stays here."""

    def __init__(self, home):
        self.home = Path(home).resolve()
        if self.home.stat().st_mode & 0o077:
            raise ValueError("broker directory must be private")

    def propose(self, document, expected_version, content):
        value = dict(document=document, expected_version=expected_version)
        try:
            return call(["broker-propose", self.home], dict(value, content=content))
        except RuntimeError as e:
            raise ValueError(str(e)) from None

    def review(self, identity):
        """The exact proposal, its content SHA-256 and its review binding."""
        return call(["broker-review", self.home, checked(identity)])

    def request(self, identity):
        return approved_request(self.home, identity)

    def approve(self, identity, *, reader=None):
        # Capture exactly what is reviewed, then release the lock during input.
        # The gate signs only if the stored proposal still has this review binding.
        r = self.review(identity)
        digest = r["content_sha256"]
        if reader is None:
            if not sys.stdin.isatty():
                raise RuntimeError("owner approval requires interactive terminal")
            reader = input
        print(
            "DOCUMENT UPDATE REVIEW\n"
            + json.dumps(r["proposal"], ensure_ascii=True, indent=2)
        )
        print(
            "Receiver-owned document database; no caller-selected filesystem path. SHA-256: "
            + digest
        )
        if reader("Type APPROVE " + digest[:12] + ": ") != "APPROVE " + digest[:12]:
            raise RuntimeError("approval declined")
        with home_lock(self.home):
            require_admission(self.home)
            # Refused when the trust has an owner passkey: approve in the owner app.
            q = call(
                [
                    "gate-approve-terminal",
                    self.home,
                    self.home / "trust.json",
                    identity,
                    r["review_sha256"],
                ]
            )
        return {
            "proposal_id": identity,
            "state": "approved",
            "expires_at": q["expires_at"],
        }

    def commit(self, identity, *, recover_only=False):
        command = "broker-recover" if recover_only else "broker-commit"
        try:
            return call([command, self.home, checked(identity)])
        except RuntimeError as e:
            if "not approved" in str(e):
                raise FileNotFoundError("proposal is not approved") from None
            if "cannot execute" in str(e):
                raise ValueError(str(e)) from None
            raise


def require_admission(home):
    if (Path(home) / "rotation-pending.json").exists():
        raise RuntimeError("planned key handover in progress; admission paused")


def install_trust(home, configuration):
    return call(["install-trust", Path(home).resolve(), Path(configuration).resolve()])


def _install_trust(home, configuration):
    """Staged update for the legacy upgrade path only (caller holds the lock)."""
    home = Path(home).resolve()
    new = ref.read(configuration)
    old = ref.read(home / "trust.json")
    if new["receiver"] != old["receiver"] or new["witness"] != old["witness"]:
        raise ValueError(
            "receiver/witness key rotation requires a future migration protocol"
        )
    # The receiver, witness and verifier states refuse this too; fail before signing.
    if "owner_passkey" in old and new.get("owner_passkey") != old["owner_passkey"]:
        raise ValueError("an installed owner passkey cannot be removed or replaced")
    signed = call(["sign-trust", home / "root/key.secret", home / "root/signer"], new)
    root = ref.read(home / "root-public.json")["public_key"]
    for role in ["receiver", "witness"]:
        call(["install-signed", home / role / "state", root], signed)
    call(["verifier-install", home / "verifier"], signed)
    signed_pending = home / ("signed-trust-publish-" + uuid.uuid4().hex + ".json")
    save(signed_pending, signed)
    os.replace(signed_pending, home / "trust-signed.json")
    pending = home / ("trust-publish-" + uuid.uuid4().hex + ".json")
    save(pending, new)
    os.replace(pending, home / "trust.json")
    return {"installed_epoch": new["epoch"], "expires_at": new["expires_at"]}


def renew(home):
    return call(["renew", Path(home).resolve()])


def enroll_passkey(home, passkey):
    """A new root-signed trust epoch that requires the owner's passkey."""
    return call(["enroll-passkey", Path(home).resolve()], passkey)


def authenticated_trust(home):
    root = ref.read(Path(home) / "root-public.json")["public_key"]
    return call(["trust-payload", root], ref.read(Path(home) / "trust-signed.json"))


def upgrade_trust(home):
    """Explicit owner migration; retain roles/state and a retryable candidate."""
    home = Path(home).resolve()
    with home_lock(home):
        (home / "root").mkdir(mode=0o700, exist_ok=True)
        secret = home / "root/key.secret"
        if not secret.exists() and (
            (home / "root-public.json").exists()
            or any(
                call(["role-status", home / role / "state"])["root"] is not None
                for role in ["receiver", "witness"]
            )
        ):
            raise RuntimeError("restore the existing root key; refusing replacement")
        root = call(["key-public", secret] if secret.exists() else ["keygen", secret])[
            "public_key"
        ]
        if (home / "root-public.json").exists():
            if ref.read(home / "root-public.json")["public_key"] != root:
                raise ValueError("root mismatch")
        else:
            save(home / "root-public.json", {"public_key": root})
        if not (home / "verifier").exists():
            call(["verifier-init", home / "verifier", root])
        if not (home / "root/signer").exists():
            call(["signer-init", home / "root/signer", root])
        for role in ["receiver", "witness"]:
            call(["role-pin", home / role / "state", root])
        candidate = home / "trust-upgrade.json"
        current = (
            authenticated_trust(home)
            if (home / "trust-signed.json").exists()
            else ref.read(home / "trust.json")
        )
        now = int(time.time())
        if (
            (home / "trust-signed.json").exists()
            and current["expires_at"] >= now
            and (
                not candidate.exists()
                or ref.read(candidate)["epoch"] <= current["epoch"]
            )
        ):
            snapshot = home / ("upgrade-current-" + uuid.uuid4().hex + ".json")
            save(snapshot, current)
            try:
                result = _install_trust(home, snapshot)
            finally:
                snapshot.unlink(missing_ok=True)
            candidate.unlink(missing_ok=True)
            return result
        floors = [
            current["epoch"],
            call(["signer-floor", home / "root/signer"])["epoch"],
        ]
        floors.extend(
            call(["trust-floor", home / role / "state"])["epoch"]
            for role in ["receiver", "witness"]
        )
        floors.append(call(["trust-floor", home / "verifier"])["epoch"])
        if candidate.exists():
            pending = ref.read(candidate)
            if (
                pending["expires_at"] < now
                or pending["epoch"] < max(floors)
                or (pending["epoch"] == current["epoch"] and pending != current)
            ):
                candidate.rename(
                    home / ("trust-upgrade-abandoned-" + uuid.uuid4().hex + ".json")
                )
        if not candidate.exists():
            current["epoch"] = max(floors) + 1
            current["expires_at"] = now + 86400
            save(candidate, current)
        result = _install_trust(home, candidate)
        candidate.unlink(missing_ok=True)
        return result


def timeline(package_path, trust_path, pin_path, out):
    import html

    package = ref.read(package_path)
    result = call(["verify", trust_path, pin_path], package)
    result["evidence_status"] = result["status"]
    if result["status"] != "unknown_due_to_disclosed_gap":
        result["status"] = "stateless_consistency_check"
    result.update(
        verification_scope="stateless_inspection",
        verification_status="stateless_consistency_verified",
        independent_operators=False,
    )
    e = lambda s: html.escape(str(s), quote=True)
    rows = "".join(
        "<tr><td>"
        + str(r["payload"]["sequence"])
        + "</td><td>"
        + e(r["payload"]["kind"])
        + "</td><td>"
        + e(r["payload"]["document"])
        + "</td><td>"
        + str(r["payload"]["document_version"])
        + "</td><td>"
        + e(r["payload"]["content_sha256"])
        + "</td></tr>"
        for r in package["receipts"]
    )
    body = (
        '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>OpenProof witnessed timeline</title><style>body{background:#0b1221;color:#e8eff8;font:16px/1.6 system-ui;margin:3rem;max-width:1100px}h1{font-size:3rem}table{width:100%;border-collapse:collapse}td,th{padding:12px;border-bottom:1px solid #35465b;text-align:left;overflow-wrap:anywhere}pre{white-space:pre-wrap}strong{color:#70ddc0}</style><h1>Authorization → receipt → witness</h1><strong>'
        + e(result["status"])
        + "</strong><p>Stateless inspection against caller-supplied trust and checkpoint. This view does not authenticate trust provisioning, establish independent operators, or persist freshness/rollback checks. Receiver assertions concern its document database; physical effects and model truth are not proven.</p><table><tr><th>Sequence</th><th>Event</th><th>Document</th><th>Version</th><th>Stored content digest</th></tr>"
        + rows
        + "</table><pre>"
        + e(json.dumps(result, indent=2))
        + "</pre>"
    )
    with Path(out).open("x") as f:
        f.write(body)


def main():
    a = argparse.ArgumentParser(description=__doc__)
    s = a.add_subparsers(dest="cmd", required=True)
    for name in ["init", "approve", "commit", "propose"]:
        p = s.add_parser(name)
        p.add_argument("home")
        p.add_argument("id", nargs="?" if name == "init" else None)
    p = s.add_parser("renew")
    p.add_argument("home")
    p = s.add_parser("upgrade-trust")
    p.add_argument("home")
    p = s.add_parser("install-trust")
    p.add_argument("home")
    p.add_argument("configuration")
    p = s.add_parser("timeline")
    p.add_argument("package")
    p.add_argument("--trust", required=True)
    p.add_argument("--checkpoint", required=True)
    p.add_argument("--out", required=True)
    args = a.parse_args()
    if args.cmd == "init":
        result = initialize(args.home)
    elif args.cmd == "renew":
        result = renew(args.home)
    elif args.cmd == "upgrade-trust":
        result = upgrade_trust(args.home)
    elif args.cmd == "install-trust":
        result = install_trust(args.home, args.configuration)
    elif args.cmd == "timeline":
        timeline(args.package, args.trust, args.checkpoint, args.out)
        return
    elif args.cmd == "propose":
        result = Broker(args.home).propose(**ref.read(args.id))
    else:
        result = getattr(Broker(args.home), args.cmd)(args.id)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("OpenProof: " + str(e), file=sys.stderr)
        sys.exit(1)
