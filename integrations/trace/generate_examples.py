#!/usr/bin/env python3
"""Generate the OpenProof `approval-outcome` example set for TRACE.

Runs a real OpenProof home (the Rust binary): an owner passkey (a software
P-256 key standing in for Touch ID), two approvals of the same document
version, one executed and witnessed, one refused because the document moved
on, and one approval forged with a key outside the trust. Then writes TRACE
Trust Records that point at those approvals, the resolver's store, an altered
copy of the store, and the expected verdicts.

    python integrations/trace/generate_examples.py --out integrations/trace/examples

A new run makes new keys and identifiers and replaces every file.
"""

import argparse, hashlib, json, shutil, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(HERE))
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from witness_workflow import Broker, call, enroll_passkey, initialize, ref
import openproof_trace as ot

ORIGIN = "http://localhost:8765"
RESOLVER = "https://openproof.example.org/owners/release-desk"


def soft_passkey(home):
    key = ec.generate_private_key(ec.SECP256R1())
    point = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    enroll_passkey(home, dict(public_key=point.hex(), rp_id="localhost", origin=ORIGIN))

    def assertion(digest_hex):
        client = json.dumps(
            dict(
                type="webauthn.get",
                challenge=ot.b64u(bytes.fromhex(digest_hex)),
                origin=ORIGIN,
            ),
            separators=(",", ":"),
        ).encode()
        auth = hashlib.sha256(b"localhost").digest() + b"\x05" + b"\0" * 4
        sig = key.sign(
            auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
        )
        return dict(
            authenticator_data=ot.b64u(auth),
            client_data_json=ot.b64u(client),
            signature=ot.b64u(sig),
        )

    return assertion


def approve(home, b, assertion, document, version, content):
    identity = b.propose(document, version, content)["proposal_id"]
    review = b.review(identity)
    pending = call(
        ["gate-approve", home, home / "trust.json", identity, review["review_sha256"]]
    )
    call(
        [
            "gate-approve-passkey",
            home,
            home / "trust.json",
            identity,
            pending["approval_sha256"],
        ],
        assertion(pending["approval_sha256"]),
    )
    return identity


def trace_record(key, reference, iat):
    """A synthetic Trust Record for the agent run that acted under the approval."""
    record = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": iat,
        "subject": "spiffe://trust.example.org/agent/release-writer",
        "model": {"provider": "example", "model_id": "example-model"},
        "runtime": {
            "platform": "software-only",
            "measurement": "sha256:" + "0" * 64,
        },
        "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "data_class": "internal",
        "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
        "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
        "references": [reference],
    }
    return ot.sign_trace_record(record, key)


def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "home"
        initialize(home)
        b = Broker(home)
        assertion = soft_passkey(home)
        first = approve(
            home,
            b,
            assertion,
            "release-notes",
            0,
            "Release 1.4: fixes the export retry.",
        )
        second = approve(
            home, b, assertion, "release-notes", 0, "Release 1.4: no changes."
        )
        executed = b.commit(first)
        if executed.get("verification_status") != "local_consistency_verified":
            raise SystemExit("first approval did not execute: " + json.dumps(executed))
        refused = b.commit(second)
        if refused.get("error_code") != "admission_failed":
            raise SystemExit("second approval was not refused: " + json.dumps(refused))
        seq = call(["head", home / "receiver/state"])["count"]
        receipt = call(["receipt", home / "receiver/state", seq])
        checkpoint = call(
            [
                "checkpoint",
                home / "witness/state",
                home / "witness/key.secret",
                home / "trust.json",
            ]
        )
        req_first, req_second = b.request(first), b.request(second)
        # An approval signed by a key the owner's trust does not name.
        outsider = Path(tmp) / "outsider.secret"
        outsider_pub = call(["keygen", outsider])["public_key"]
        fake = dict(ref.read(home / "trust.json"), authority=outsider_pub)
        fake.pop("owner_passkey", None)
        (Path(tmp) / "fake-trust.json").write_text(json.dumps(fake))
        forged = call(
            ["approve", outsider, Path(tmp) / "fake-trust.json"],
            dict(
                document="release-notes",
                expected_version=1,
                content="Release 1.4: forged.",
            ),
        )
        forged = dict(forged, owner_assertion=req_first["owner_assertion"])
        signed_trust = ref.read(home / "trust-signed.json")
        root = ref.read(home / "root-public.json")["public_key"]

    entries = {
        ot.ID_PREFIX
        + ot.approval_digest(req_first): ot.store_entry(req_first, receipt, checkpoint),
        ot.ID_PREFIX + ot.approval_digest(req_second): ot.store_entry(req_second),
        ot.ID_PREFIX + ot.approval_digest(forged): ot.store_entry(forged),
    }
    store = {"resolver": RESOLVER, "signed_trust": signed_trust, "entries": entries}
    altered = json.loads(json.dumps(store))
    first_id = ot.ID_PREFIX + ot.approval_digest(req_first)
    altered["entries"][first_id]["request"][
        "content"
    ] = "Release 1.4: rewritten after approval."

    key = ot.new_record_key()
    iat = int(time.time())
    missing = dict(ot.reference(req_first, RESOLVER), id=ot.ID_PREFIX + "0" * 64)
    cases = {
        "01-approval-executed.json": (
            "openproof-approvals.json",
            ot.reference(req_first, RESOLVER),
        ),
        "02-approval-altered-after-issue.json": (
            "openproof-approvals-altered.json",
            ot.reference(req_first, RESOLVER),
        ),
        "03-approved-not-executed.json": (
            "openproof-approvals.json",
            ot.reference(req_second, RESOLVER),
        ),
        "04-reference-unresolvable.json": ("openproof-approvals.json", missing),
        "05-approval-outside-trust.json": (
            "openproof-approvals.json",
            ot.reference(forged, RESOLVER),
        ),
    }
    out = a.out
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    write(out / "openproof-approvals.json", store)
    write(out / "openproof-approvals-altered.json", altered)
    expected = {
        "trace_signer_jwk": None,
        "openproof_root_public_key": root,
        "resolver": RESOLVER,
        "cases": {},
    }
    stores = {
        "openproof-approvals.json": store,
        "openproof-approvals-altered.json": altered,
    }
    for name, (store_name, reference) in cases.items():
        record = trace_record(key, reference, iat)
        write(out / name, record)
        expected["trace_signer_jwk"] = record["cnf"]["jwk"]
        expected["cases"][name] = dict(
            store=store_name, **ot.check(record, stores[store_name], root)
        )
    write(out / "expected.json", expected)
    for name, case in expected["cases"].items():
        print(f"{name}: {case['verdict']}")


if __name__ == "__main__":
    main()
