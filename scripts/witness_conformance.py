#!/usr/bin/env python3
"""Compare independently implemented Go and Rust v1 witness verifiers."""

import argparse, base64, copy, hashlib, json, subprocess, time
from pathlib import Path
from witness_workflow import ROOT, BINARY, Broker, initialize, save, ref, enroll_passkey

ORIGIN = "http://localhost:8765"


def run_both(out, go_binary, now, trust, pin, raw):
    """Run the Rust and Go verifiers on one package; both must agree."""
    (out / "case.json").write_bytes(raw)
    rust = subprocess.run(
        [str(BINARY), "verify", str(trust), str(pin)],
        input=raw,
        capture_output=True,
        timeout=20,
    )
    go = subprocess.run(
        [go_binary, "verify", str(trust), str(pin), str(out / "case.json"), now],
        capture_output=True,
        timeout=20,
    )
    accepted = rust.returncode == 0
    assert accepted == (go.returncode == 0), (rust.stderr, go.stderr)
    if accepted:
        left = json.loads(rust.stdout)
        right = json.loads(go.stdout)
        for k in ["status", "complete_history", "physical_effects_proven"]:
            assert left[k] == right[k], (k, left, right)
    return accepted


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument(
        "--go-binary", default=str(ROOT / "outputs/v0.8/openproof-go-verify")
    )
    a = p.parse_args()
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    home = out / "home"
    initialize(home)
    b = Broker(home)
    q = b.propose("report", 0, "Public synthetic report: café — verified bytes.")
    b.approve(q["proposal_id"], reader=lambda _: "APPROVE " + q["content_sha256"][:12])
    r = b.commit(q["proposal_id"])
    assert r["verification_status"] == "local_consistency_verified", r
    package = json.loads((Path(r["evidence_directory"]) / "package.json").read_text())
    trust = json.loads((home / "trust.json").read_text())
    pin = package["checkpoint"]
    cases = []

    def add(name, path, value):
        x = copy.deepcopy(package)
        node = x
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
        cases.append((name, x))

    cases.append(("valid", package))
    for name, path in [
        ("approval", ["requests", 0, "approval", "payload"]),
        ("receipt", ["receipts", 0, "payload"]),
        ("checkpoint", ["checkpoint", "payload"]),
    ]:
        node = package
        for k in path:
            node = node[k]
        for field in node:
            for i, value in enumerate([None, False, [], {}, "changed", 0, 2**64 - 1]):
                add(f"{name}-{field}-{i}", path + [field], value)
        sigpath = path[:-1] + ["signature"]
        node = package
        for k in sigpath:
            node = node[k]
        for i in range(0, len(node), 16):
            add(
                f"{name}-signature-{i}",
                sigpath,
                node[:i] + ("0" if node[i] != "0" else "1") + node[i + 1 :],
            )
    add("content", ["requests", 0, "content"], "tampered")
    add("missing-receipts", ["receipts"], [])
    add("missing-requests", ["requests"], [])
    add("duplicate-receipt", ["receipts"], package["receipts"] * 2)
    add("duplicate-request", ["requests"], package["requests"] * 2)
    results = []
    now = str(int(time.time()))
    save(out / "trust.json", trust)
    save(out / "pin.json", pin)

    go_binary = str(Path(a.go_binary).resolve())

    def check(name, raw):
        try:
            accepted = run_both(
                out, go_binary, now, out / "trust.json", out / "pin.json", raw
            )
        except AssertionError as e:
            raise AssertionError(name, *e.args) from None
        results.append({"case": name, "accepted": accepted})

    for name, data in cases:
        check(name, json.dumps(data, ensure_ascii=False).encode())
    raw = json.dumps(package).encode()
    for name, bad in [
        ("trailing", raw + b" {}"),
        ("duplicate", b'{"version":"bad",' + raw[1:]),
        ("surrogate", raw.replace(b"Public", b"\\ud800")),
        ("float", raw.replace(b'"sequence": 1', b'"sequence": 1.0')),
    ]:
        check(name, bad)
        assert not results[-1]["accepted"], name
    for name, expected, accepted in passkey_cases(out / "passkey", go_binary):
        assert accepted == expected, (name, expected, accepted)
        results.append({"case": "passkey-" + name, "accepted": accepted})
    save(
        out / "results.json",
        {
            "cases": len(results),
            "results": results,
            "scope": "stateless v1 full packages, with and without owner passkey assertions; shared author, separate implementation",
        },
    )
    print(f"PASS {len(results)} Go/Rust differential cases")


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def digest(request):
    payload = request["approval"]["payload"]
    preimage = b"OpenProof/v1/document-approval/1\0" + ref.canonical(payload)
    return hashlib.sha256(preimage).hexdigest()


def passkey_cases(out, go_binary):
    """Owner passkey assertions, made with a software P-256 key: each case is
    checked by both verifiers. Yields (name, expected, accepted)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )
    from owner_app import Owner

    out.mkdir()
    home = out / "home"
    initialize(home)
    b = Broker(home)
    # Receipt 1 is approved before the passkey exists and must not carry one.
    q = b.propose("report", 0, "Approved before the passkey.")
    b.approve(q["proposal_id"], reader=lambda _: "APPROVE " + q["content_sha256"][:12])
    b.commit(q["proposal_id"])
    key = ec.generate_private_key(ec.SECP256R1())
    point = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    enroll_passkey(home, dict(public_key=point.hex(), rp_id="localhost", origin=ORIGIN))

    def assertion(hex_digest, signer=key, rp="localhost", flags=0x05, **client):
        challenge = b64(bytes.fromhex(hex_digest))
        data = dict(type="webauthn.get", challenge=challenge, origin=ORIGIN)
        data.update(client)
        client_json = json.dumps(data, separators=(",", ":")).encode()
        auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + b"\0" * 4
        signed = auth + hashlib.sha256(client_json).digest()
        return dict(
            authenticator_data=b64(auth),
            client_data_json=b64(client_json),
            signature=b64(signer.sign(signed, ec.ECDSA(hashes.SHA256()))),
        )

    owner = Owner(home)
    owner.origin = ORIGIN
    identity = owner.broker.propose("report", 1, "Approved with the passkey.")[
        "proposal_id"
    ]
    challenge = owner.approve(identity, owner.review(identity)["review_token"])
    owner.approve_passkey(
        identity,
        challenge["assertion_token"],
        assertion(challenge["approval_sha256"]),
    )
    r = b.commit(identity)
    assert r["verification_status"] == "local_consistency_verified", r
    package = json.loads((Path(r["evidence_directory"]) / "package.json").read_text())
    trust = out / "trust.json"
    plain = out / "trust-without-passkey.json"
    pin = out / "pin.json"
    configured = json.loads((home / "trust.json").read_text())
    save(trust, configured)
    save(plain, {k: v for k, v in configured.items() if k != "owner_passkey"})
    save(pin, package["checkpoint"])
    now = str(int(time.time()))
    first, second = package["requests"]
    assert "owner_assertion" not in first and "owner_assertion" in second
    d = digest(second)

    def high_s():
        good = assertion(d)
        der = base64.urlsafe_b64decode(good["signature"] + "==")
        r, s = decode_dss_signature(der)
        n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        return dict(
            good, signature=b64(encode_dss_signature(r, n - s if s < n // 2 else s))
        )

    def flipped():
        good = assertion(d)
        der = bytearray(base64.urlsafe_b64decode(good["signature"] + "=="))
        der[-1] ^= 1
        return dict(good, signature=b64(bytes(der)))

    other = ec.generate_private_key(ec.SECP256R1())
    replaced = [
        ("valid", True, second["owner_assertion"]),
        ("fresh-assertion", True, assertion(d)),
        ("high-s-signature", True, high_s()),
        ("wrong-challenge", False, assertion(hashlib.sha256(b"other").hexdigest())),
        ("other-approval-digest", False, assertion(digest(first))),
        ("wrong-origin", False, assertion(d, origin="http://localhost:1")),
        ("wrong-type", False, assertion(d, type="webauthn.create")),
        ("cross-origin", False, assertion(d, crossOrigin=True)),
        ("wrong-rp-id", False, assertion(d, rp="example.com")),
        ("user-verification-missing", False, assertion(d, flags=0x01)),
        ("user-presence-missing", False, assertion(d, flags=0x04)),
        ("bad-signature", False, flipped()),
        ("other-key", False, assertion(d, signer=other)),
        ("missing-when-required", False, None),
    ]
    for name, expected, value in replaced:
        x = copy.deepcopy(package)
        if value is None:
            del x["requests"][1]["owner_assertion"]
        else:
            x["requests"][1]["owner_assertion"] = value
        raw = json.dumps(x).encode()
        try:
            accepted = run_both(out, go_binary, now, trust, pin, raw)
        except AssertionError as e:
            raise AssertionError(name, *e.args) from None
        yield name, expected, accepted
    # Before from_sequence an assertion is unexpected, even a valid one.
    x = copy.deepcopy(package)
    x["requests"][0]["owner_assertion"] = assertion(digest(first))
    raw = json.dumps(x).encode()
    yield "unexpected-before-passkey", False, run_both(
        out, go_binary, now, trust, pin, raw
    )
    # A trust without a passkey accepts no assertion at all.
    raw = json.dumps(package).encode()
    yield "unexpected-not-configured", False, run_both(
        out, go_binary, now, plain, pin, raw
    )


if __name__ == "__main__":
    main()
