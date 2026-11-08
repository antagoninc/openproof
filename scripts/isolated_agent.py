#!/usr/bin/env python3
"""Trusted host broker: bounded report policy, isolated actor, Rust trusted executor."""

import argparse, base64, hashlib, json, os, subprocess, sys, time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference/python"))
import openproof_ref as ref
from isolation_runner import worker, ENV
from claude_report import generate, MODEL

sha = lambda b: hashlib.sha256(b).hexdigest()
pk = lambda k: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
seed = lambda k: k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--out", required=True)
    a.add_argument("--image-id-file", required=True)
    a.add_argument("--provider", choices=["fixture", "claude"], required=True)
    a.add_argument("--model", default=MODEL)
    a.add_argument("--approval", choices=["interactive", "demo"], default="demo")
    args = a.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    out.chmod(0o700)
    image = Path(args.image_id_file).read_text().strip()
    binary = ROOT / "target/debug/openproof"

    def save(name, obj):
        p = out / name
        p.write_text(json.dumps(obj, indent=2) + "\n")
        return p

    def run(command, ok=True):
        r = subprocess.run(
            [binary, *map(str, command)],
            capture_output=True,
            text=True,
            timeout=20,
            env=ENV,
        )
        if (r.returncode == 0) != ok:
            raise RuntimeError("executor result unexpected: " + r.stderr[:300])
        return (
            (json.loads(r.stdout) if r.stdout.strip() else None)
            if ok
            else r.stderr.strip()
        )

    if args.provider == "claude":
        report, metadata = generate(args.model)
    else:
        report = b"OpenProof offline fixture report. No model was called.\n"
        metadata = {
            "provider": "fixture",
            "external_call": False,
            "report_sha256": sha(report),
        }
    (out / "proposal.txt").write_bytes(report)
    save("provider.json", metadata)
    if not report or len(report) > 8192:
        raise ValueError("proposal outside fixed report policy")
    if args.approval == "interactive":
        from approval import approve

        save("approval.json", approve(report, out))
    root, authority, actor, executor = [Ed25519PrivateKey.generate() for _ in range(4)]
    t = int(time.time())
    audience = "isolated-report-pilot"
    policy = dict(
        version="openproof-policy/1",
        audience=audience,
        executor_key=pk(executor),
        max_validity_seconds=600,
        allow=[
            dict(
                tool="artifact.write",
                resource="urn:openproof:artifact",
                max_argument_bytes=8192,
            )
        ],
    )
    pp = save("policy.json", policy)
    scope = dict(
        tool="artifact.write",
        resource="urn:openproof:artifact",
        arguments_sha256=sha(report),
    )
    context = dict(
        authority_key=pk(authority),
        actor_key=pk(actor),
        executor_key=pk(executor),
        run_id="isolated-report",
        nonce=os.urandom(32).hex(),
        audience=audience,
        policy_sha256=sha(pp.read_bytes()),
        expected_action=scope,
        now=t,
    )
    cp = save("context.json", context)

    def signed(kind, p, k):
        return dict(payload=p, signature=k.sign(ref.preimage(kind, p)).hex())

    auth = dict(
        version="openproof/1",
        run_id=context["run_id"],
        nonce=context["nonce"],
        audience=audience,
        actor_key=pk(actor),
        policy_sha256=context["policy_sha256"],
        action=scope,
        not_before=t - 1,
        expires_at=t + 540,
    )
    au = signed("authorization", auth, authority)
    save("authorization.json", au)
    trust = dict(
        version="openproof-trust/1",
        audience=audience,
        revision=1,
        issued_at=t - 5,
        expires_at=t + 3600,
        keys=[
            dict(
                public_key=pk(k),
                role=role,
                not_before=t - 10,
                expires_at=t + 3600,
                revoked_at=None,
            )
            for k, role in [
                (authority, "authority"),
                (actor, "actor"),
                (executor, "executor"),
            ]
        ],
    )
    tp = save(
        "trust.json",
        dict(
            payload=trust,
            signature=root.sign(
                b"OpenProof/v1/trust-bundle\0" + ref.canonical(trust)
            ).hex(),
        ),
    )
    ap = save(
        "anchor.json", dict(root_key=pk(root), audience=audience, minimum_revision=1)
    )
    secret = out / "executor.secret"
    state = out / "state"
    canary = out / "host-only-canary"
    try:
        fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(seed(executor))
        canary.write_text("Synthetic isolation test value")
        canary.chmod(0o600)
        run(["init-state", state])
        run(["install-trust", state, tp, ap])
        checks = {}
        probe, config = worker(
            image,
            dict(
                mode="probe",
                canary_path=str(canary),
                executor_path=str(secret),
                state_path=str(state / "replay.sqlite3"),
            ),
        )
        if not all(v is True for v in probe.values()):
            raise RuntimeError("isolation probe failed")
        save("isolation.json", dict(config=config, probes=probe))
        checks["isolation"] = probe
        try:
            worker(image, dict(mode="flood"))
        except RuntimeError as e:
            if str(e) != "worker output exceeds limit":
                raise
            checks["output_flood"] = dict(rejected=True, reason=str(e))
        else:
            raise RuntimeError("worker output flood was not rejected")
        for mode in ["destination", "altered", "stale", "allowed"]:
            authorization = au
            if mode == "stale":
                expired = dict(auth, not_before=t - 500, expires_at=t - 1)
                authorization = signed("authorization", expired, authority)
            proposed, _ = worker(
                image,
                dict(
                    mode=mode,
                    authorization=authorization,
                    actor_seed=seed(actor),
                    arguments=base64.b64encode(report).decode(),
                    time=t,
                ),
            )
            data = base64.b64decode(proposed["arguments"], validate=True)
            af = out / (mode + "-arguments.bin")
            af.write_bytes(data)
            bp = save(
                mode + "-request.json",
                dict(
                    authorization=authorization, action=proposed["action"], receipt=None
                ),
            )
            command = ["execute-trusted", bp, cp, pp, af, secret, state, tp, ap]
            if mode != "allowed":
                checks[mode] = dict(rejected=True, reason=run(command, False))
                assert run(["state", state]) == []
            else:
                execution = run(command)
                save("execution.json", execution)
                checks["replay"] = dict(rejected=True, reason=run(command, False))
                job = Path(execution["artifact_directory"])
                checks["receipt"] = run(
                    [
                        "verify-trusted",
                        job / "bundle.json",
                        job / "context.json",
                        tp,
                        ap,
                        "current",
                    ]
                )
                checks["artifact"] = run(
                    [
                        "verify-artifact",
                        job / "bundle.json",
                        job / "context.json",
                        job / "output.bin",
                    ]
                )
                acknowledgement, _ = worker(
                    image,
                    dict(
                        mode="receipt",
                        bundle=execution["bundle"],
                        context=execution["context"],
                        snapshot=ref.read(tp),
                        anchor=ref.read(ap),
                        output=base64.b64encode(
                            (job / "output.bin").read_bytes()
                        ).decode(),
                    ),
                )
                if acknowledgement.get("receipt_verified") is not True:
                    raise RuntimeError("actor did not verify receipt")
                checks["agent_receipt_ack"] = acknowledgement
                modified = out / "tampered-output.bin"
                modified.write_bytes(report + b"\ntamper")
                checks["artifact_tamper"] = dict(
                    rejected=True,
                    reason=run(
                        [
                            "verify-artifact",
                            job / "bundle.json",
                            job / "context.json",
                            modified,
                        ],
                        False,
                    ),
                )
        save("checks.json", checks)
        from render_evidence import render

        if not render(out, out / "viewer.html"):
            raise RuntimeError("viewer verification failed")
        print(
            "PASS: "
            + args.provider
            + " report; isolated actor; denied destination/alteration/stale authorization; one execution; replay and tamper rejected; viewer saved"
        )
    finally:
        secret.unlink(missing_ok=True)
        canary.unlink(missing_ok=True)


if __name__ == "__main__":
    import signal

    def interrupted(signum, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        print(
            "Interrupted. Inspect existing state; never automatically retry.",
            file=sys.stderr,
        )
        sys.exit(130)
    except Exception as e:
        print("openproof pilot: " + str(e), file=sys.stderr)
        sys.exit(1)
