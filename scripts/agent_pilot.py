#!/usr/bin/env python3
"""Local end-to-end supervisor/agent/gate pilot with ephemeral, nonproduction keys."""

import base64, hashlib, json, os, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference/python"))
import openproof_ref as ref
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=False)
binary = ROOT / "target/debug/openproof"
keys = [Ed25519PrivateKey.generate() for _ in range(4)]
root, authority, actor, executor = keys
pk = lambda k: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
seed = lambda k: k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
sha = lambda b: hashlib.sha256(b).hexdigest()


def save(name, obj):
    p = out / name
    p.write_text(json.dumps(obj, indent=2))
    return p


def run(args, ok=True):
    r = subprocess.run(
        [binary, *map(str, args)], capture_output=True, text=True, timeout=20
    )
    assert (r.returncode == 0) == ok, (args, r.stderr)
    return json.loads(r.stdout) if ok else r.stderr.strip()


def signed(kind, p, k):
    return dict(payload=p, signature=k.sign(ref.preimage(kind, p)).hex())


def trust_signed(p):
    return dict(
        payload=p,
        signature=root.sign(b"OpenProof/v1/trust-bundle\0" + ref.canonical(p)).hex(),
    )


t = int(time.time())
audience = "local-agent-pilot"
goal = "Create a local evidence-backed project status artifact."
arguments = ("OpenProof agent report\n\n" + goal + "\n").encode()
policy = dict(
    version="openproof-policy/1",
    audience=audience,
    executor_key=pk(executor),
    max_validity_seconds=300,
    allow=[
        dict(
            tool="artifact.write",
            resource="urn:openproof:artifact",
            max_argument_bytes=4096,
        )
    ],
)
pp = save("policy.json", policy)
scope = dict(
    tool="artifact.write",
    resource="urn:openproof:artifact",
    arguments_sha256=sha(arguments),
)
ctx = dict(
    authority_key=pk(authority),
    actor_key=pk(actor),
    executor_key=pk(executor),
    run_id="agent-run",
    nonce=os.urandom(32).hex(),
    audience=audience,
    policy_sha256=sha(pp.read_bytes()),
    expected_action=scope,
    now=t,
)
cp = save("context.json", ctx)
auth = dict(
    version="openproof/1",
    run_id=ctx["run_id"],
    nonce=ctx["nonce"],
    audience=audience,
    actor_key=pk(actor),
    policy_sha256=ctx["policy_sha256"],
    action=scope,
    not_before=t - 1,
    expires_at=t + 180,
)
au = signed("authorization", auth, authority)
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
tp = save("trust.json", trust_signed(trust))
ap = save("anchor.json", dict(root_key=pk(root), audience=audience, minimum_revision=1))
secret = out / "executor.secret"
fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(seed(executor))
state = out / "state"
try:
    subprocess.run([binary, "init-state", state], check=True)
    subprocess.run([binary, "install-trust", state, tp, ap], check=True)
    results = {}
    for mode in ["denied", "allowed"]:
        job = dict(
            goal=goal, authorization=au, actor_seed=seed(actor), time=t, mode=mode
        )
        response = subprocess.run(
            [sys.executable, ROOT / "examples/agent/worker.py"],
            input=json.dumps(job),
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        )
        proposed = json.loads(response.stdout)
        args = base64.b64decode(proposed["arguments"], validate=True)
        argfile = out / (mode + "-arguments.bin")
        argfile.write_bytes(args)
        bp = save(
            mode + "-request.json",
            dict(authorization=au, action=proposed["action"], receipt=None),
        )
        command = ["execute-trusted", bp, cp, pp, argfile, secret, state, tp, ap]
        if mode == "denied":
            results["denied_scope"] = run(command, False)
            assert run(["state", state]) == []
        else:
            executed = run(command)
            save("execution.json", executed)
            results["allowed"] = "executed"
            results["replay"] = run(command, False)
            jobdir = Path(executed["artifact_directory"])
            results["receipt"] = run(
                [
                    "verify-trusted",
                    jobdir / "bundle.json",
                    jobdir / "context.json",
                    tp,
                    ap,
                    "current",
                ]
            )
            results["artifact"] = run(
                [
                    "verify-artifact",
                    jobdir / "bundle.json",
                    jobdir / "context.json",
                    jobdir / "output.bin",
                ]
            )
            trust["revision"] = 2
            trust["keys"][1]["revoked_at"] = int(time.time())
            revoked = save("revoked-trust.json", trust_signed(trust))
            subprocess.run([binary, "install-trust", state, revoked, ap], check=True)
            results["old_snapshot"] = run(command, False)
            results["revocation"] = run(
                [
                    "verify-trusted",
                    jobdir / "bundle.json",
                    jobdir / "context.json",
                    revoked,
                    ap,
                    "historical",
                ],
                False,
            )
    save("pilot-report.json", results)
    print(
        "PASS: separate agent process; denied scope; allowed dispatch; replay rejection; trusted receipt; matching artifact; revocation rejection"
    )
finally:
    secret.unlink(missing_ok=True)
