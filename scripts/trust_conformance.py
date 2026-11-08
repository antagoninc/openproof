#!/usr/bin/env python3
"""Shared trust vectors: Python/OpenSSL versus Rust/dalek, including freshly signed negatives."""

import copy, json, subprocess, sys, tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference/python"))
import openproof_ref as ref
import openproof_trust as trust

b = ref.read(ROOT / "fixtures/v1/bundle.json")
c = ref.read(ROOT / "fixtures/v1/context.json")
s = ref.read(ROOT / "fixtures/trust-v1/snapshot.json")
a = ref.read(ROOT / "fixtures/trust-v1/anchor.json")
key = Ed25519PrivateKey.from_private_bytes(bytes([9]) * 32)
cases = []


def add(
    name,
    snapshot=s,
    anchor=a,
    time=100,
    mode="current",
    expected=True,
    bundle=b,
    context=c,
):
    cases.append(
        dict(
            name=name,
            snapshot=copy.deepcopy(snapshot),
            anchor=copy.deepcopy(anchor),
            time=time,
            mode=mode,
            expected=expected,
            bundle=copy.deepcopy(bundle),
            context=copy.deepcopy(context),
        )
    )


def resign(t):
    return dict(payload=t, signature=key.sign(trust.preimage(t)).hex())


add("valid")
add("historical", time=200, mode="historical")
add("expired-current", time=200, expected=False)
for time in [0, 79, 1001, 2**64 - 1]:
    add("freshness-" + str(time), time=time, expected=False)
for field, value in [
    ("minimum_revision", 999),
    ("root_key", c["actor_key"]),
    ("audience", "wrong"),
]:
    aa = copy.deepcopy(a)
    aa[field] = value
    add("anchor-" + field, anchor=aa, expected=False)
for i in range(3):
    for field, value in [("revoked_at", 100), ("not_before", 101), ("expires_at", 89)]:
        t = copy.deepcopy(s["payload"])
        t["keys"][i][field] = value
        # Invalid windows are deliberately signed without validation to test parsing and validation.
        ss = dict(
            payload=t,
            signature=key.sign(b"OpenProof/v1/trust-bundle\0" + ref.canonical(t)).hex(),
        )
        add(f"key-{i}-{field}", snapshot=ss, expected=False)
    t = copy.deepcopy(s["payload"])
    t["keys"][i]["revoked_at"] = 150
    add(
        "historical-revocation-" + str(i),
        snapshot=resign(t),
        time=200,
        mode="historical",
        expected=False,
    )
for field, value in [
    ("revision", 0),
    ("revision", 2**63),
    ("version", "unknown"),
    ("audience", "wrong"),
    ("keys", []),
]:
    t = copy.deepcopy(s["payload"])
    t[field] = value
    add(
        "invalid-" + field + str(value),
        snapshot=dict(
            payload=t,
            signature=key.sign(b"OpenProof/v1/trust-bundle\0" + ref.canonical(t)).hex(),
        ),
        expected=False,
    )
for i in range(64):
    ss = copy.deepcopy(s)
    sig = bytearray.fromhex(ss["signature"])
    sig[i] ^= 1
    ss["signature"] = sig.hex()
    add("signature-" + str(i), snapshot=ss, expected=False)
ss = copy.deepcopy(s)
for k in ss["payload"]["keys"]:
    k.pop("revoked_at", None)
add("omitted-null", snapshot=ss)
cc = copy.deepcopy(c)
cc["now"] = 101
add("future-context", context=cc, expected=False)
bb = copy.deepcopy(b)
bb.pop("receipt")
add("claim-only", bundle=bb)
# Retained shared test inputs; never regenerate during validation.
path = ROOT / "fixtures/trust-v1/conformance.json"
if "--generate" in sys.argv:
    path.write_text(json.dumps(cases, indent=2) + "\n")
    sys.exit(0)
assert json.loads(path.read_text()) == cases, "trust vector drift"
with tempfile.TemporaryDirectory(
    dir=ROOT / "outputs", prefix="trust-conformance-"
) as tmp:
    tmp = Path(tmp)
    for case in cases:
        try:
            result = trust.verify(
                case["bundle"],
                case["context"],
                case["snapshot"],
                case["anchor"],
                case["time"],
                case["mode"],
            )
            accepted = True
        except Exception:
            accepted = False
            result = None
        paths = []
        for n in ["bundle", "context", "snapshot", "anchor"]:
            p = tmp / (n + ".json")
            p.write_text(json.dumps(case[n]))
            paths.append(str(p))
        run = subprocess.run(
            [
                str(ROOT / "target/debug/openproof"),
                "verify-trusted-at",
                *paths,
                case["mode"],
                str(case["time"]),
            ],
            text=True,
            capture_output=True,
        )
        assert accepted == case["expected"] == (run.returncode == 0), (
            case["name"],
            accepted,
            case["expected"],
            run.stderr,
        )
        if accepted:
            assert result == json.loads(run.stdout), case["name"]
print(f"PASS: {len(cases)} shared trust differential vectors")
