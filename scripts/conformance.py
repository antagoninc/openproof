#!/usr/bin/env python3
"""Fixed v1 vectors and Rust/Python differential verification; deterministic test keys only."""

import copy, hashlib, json, random, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference/python"))
import openproof_ref as ref
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KEYS = [Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32) for n in [1, 2, 3]]
PK = [k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for k in KEYS]


def signed(kind, p, key):
    return {"payload": p, "signature": key.sign(ref.preimage(kind, p)).hex()}


def fixture():
    scope = {
        "tool": "artifact.write",
        "resource": "urn:openproof:artifact",
        "arguments_sha256": hashlib.sha256(b"golden input\n").hexdigest(),
    }
    c = dict(
        authority_key=PK[0],
        actor_key=PK[1],
        executor_key=PK[2],
        run_id="golden-run",
        nonce="golden-nonce",
        audience="golden-audience",
        policy_sha256="bb" * 32,
        expected_action=scope,
        now=100,
    )
    a = dict(
        version="openproof/1",
        run_id=c["run_id"],
        nonce=c["nonce"],
        audience=c["audience"],
        actor_key=PK[1],
        policy_sha256=c["policy_sha256"],
        action=scope,
        not_before=90,
        expires_at=110,
    )
    x = dict(
        version="openproof/1",
        authorization_sha256=ref.digest("authorization", a),
        action=scope,
        claimed_at=95,
    )
    r = dict(
        version="openproof/1",
        action_sha256=ref.digest("action", x),
        observed_at=99,
        outcome="succeeded",
        output_sha256=hashlib.sha256(b"golden output\n").hexdigest(),
    )
    b = {
        "authorization": signed("authorization", a, KEYS[0]),
        "action": signed("action", x, KEYS[1]),
        "receipt": signed("receipt", r, KEYS[2]),
    }
    return b, c


b, c = fixture()
base = ROOT / "fixtures/v1"
base.mkdir(exist_ok=True, parents=True)
vectors = {
    kind: {
        "signing_bytes_hex": ref.preimage(kind, b[kind]["payload"]).hex(),
        "sha256": ref.digest(kind, b[kind]["payload"]),
        "signature": b[kind]["signature"],
    }
    for kind in ["authorization", "action", "receipt"]
}
for name, value in [("bundle.json", b), ("context.json", c), ("vectors.json", vectors)]:
    data = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()
    file = base / name
    if file.exists():
        assert file.read_bytes() == data, "immutable fixture changed: " + name
    else:
        file.write_bytes(data)
manifest = {
    f.name: hashlib.sha256(f.read_bytes()).hexdigest()
    for f in sorted(base.glob("*.json"))
    if f.name != "sha256.json"
}
manifest_file = base / "sha256.json"
if manifest_file.exists():
    assert json.loads(manifest_file.read_text()) == manifest
else:
    manifest_file.write_text(json.dumps(manifest, indent=2) + "\n")
cases = []


def add(name, bb, cc, ok):
    cases.append(
        (
            name,
            json.dumps(bb, ensure_ascii=False).encode(),
            json.dumps(cc, ensure_ascii=False).encode(),
            ok,
        )
    )


add("valid", b, c, True)
x = copy.deepcopy(b)
x.pop("receipt")
add("missing-receipt", x, c, True)
x = copy.deepcopy(b)
x["receipt"] = None
add("null-receipt", x, c, True)
x = copy.deepcopy(b)
x["receipt"]["payload"]["outcome"] = "failed"
x["receipt"] = signed("receipt", x["receipt"]["payload"], KEYS[2])
add("reported-failure", x, c, True)
for name in [
    "run_id",
    "nonce",
    "audience",
    "policy_sha256",
    "authority_key",
    "actor_key",
    "executor_key",
]:
    cc = copy.deepcopy(c)
    cc[name] = "dd" * 32 if "key" in name or "sha256" in name else "wrong"
    add("wrong-" + name, b, cc, False)
for kind, field in [
    ("authorization", "audience"),
    ("action", "authorization_sha256"),
    ("receipt", "action_sha256"),
]:
    x = copy.deepcopy(b)
    x[kind]["payload"][field] = "aa" * 32
    x[kind] = signed(
        kind,
        x[kind]["payload"],
        KEYS[["authorization", "action", "receipt"].index(kind)],
    )
    add("resigned-splice-" + kind, x, c, False)
for time in [0, 89, 111, 2**64 - 1]:
    cc = copy.deepcopy(c)
    cc["now"] = time
    add("time-" + str(time), b, cc, False)
for kind in ["authorization", "action", "receipt"]:
    for position in range(64):
        x = copy.deepcopy(b)
        sig = bytearray.fromhex(x[kind]["signature"])
        sig[position] ^= 1
        x[kind]["signature"] = sig.hex()
        add(f"signature-{kind}-{position}", x, c, False)
for field, value in [("extra", True), ("version", "openproof/999")]:
    x = copy.deepcopy(b)
    x["authorization"]["payload"][field] = value
    add("invalid-" + field, x, c, False)
raw = json.dumps(b).encode()
ctx = json.dumps(c).encode()
cases.extend(
    [
        (
            "duplicate",
            raw.replace(b'"version":', b'"version":"openproof/1","version":', 1),
            ctx,
            False,
        ),
        ("unknown-root", raw.replace(b"{", b'{"unexpected":0,', 1), ctx, False),
        (
            "float-time",
            raw.replace(b'"not_before": 90', b'"not_before": 90.0'),
            ctx,
            False,
        ),
        ("trailing-json", raw + b" {}", ctx, False),
        ("oversized", b" " * (ref.MAX + 1), ctx, False),
    ]
)
# Valid signed Unicode variants generated in Python, to exercise cross-language preimages.
for i, value in enumerate(
    ["é", "e\u0301", "漢字", "😀", "𝄞", "line separator\u2028", "a/b\\c"]
):
    bb, cc = fixture()
    bb = copy.deepcopy(bb)
    cc = copy.deepcopy(cc)
    bb["authorization"]["payload"]["run_id"] = value
    cc["run_id"] = value
    bb["authorization"] = signed(
        "authorization", bb["authorization"]["payload"], KEYS[0]
    )
    bb["action"]["payload"]["authorization_sha256"] = ref.digest(
        "authorization", bb["authorization"]["payload"]
    )
    bb["action"] = signed("action", bb["action"]["payload"], KEYS[1])
    bb["receipt"]["payload"]["action_sha256"] = ref.digest(
        "action", bb["action"]["payload"]
    )
    bb["receipt"] = signed("receipt", bb["receipt"]["payload"], KEYS[2])
    add("unicode-" + str(i), bb, cc, True)
passed = 0
with tempfile.TemporaryDirectory(prefix="conformance-", dir=ROOT / "outputs") as tmp:
    tmp = Path(tmp)
    for name, bbytes, cbytes, expected in cases:
        try:
            py = ref.verify(ref.load_bytes(bbytes), ref.load_bytes(cbytes))
            accepted = True
        except Exception:
            accepted = False
            py = None
        bp = tmp / "bundle.json"
        cp = tmp / "context.json"
        bp.write_bytes(bbytes)
        cp.write_bytes(cbytes)
        run = subprocess.run(
            [ROOT / "target/debug/openproof", "verify", bp, cp],
            text=True,
            capture_output=True,
        )
        assert accepted == expected == (run.returncode == 0), (
            name,
            accepted,
            expected,
            run.stderr,
        )
        if accepted:
            assert json.loads(run.stdout) == py, name
        passed += 1
    # Compare exact Rust preimages and signatures against fixed Python-generated vectors.
    for kind in ["authorization", "action", "receipt"]:
        ip = tmp / (kind + ".json")
        op = tmp / (kind + ".bin")
        ip.write_text(json.dumps(b[kind]["payload"]))
        subprocess.run(
            [ROOT / "target/debug/openproof", "canonical", kind, ip, op],
            check=True,
            capture_output=True,
        )
        assert op.read_bytes().hex() == vectors[kind]["signing_bytes_hex"]
print(
    f"PASS: {passed} differential cases; 3 fixed signing-byte/signature vectors; immutable fixture hashes checked"
)
