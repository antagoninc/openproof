"""Link OpenProof approvals to TRACE Trust Records.

A TRACE Trust Record (https://github.com/agentrust-io/trace-spec) says what ran,
where and under which policy. It can point at a human approval held elsewhere
through its `references` block with the registered relation `approval-outcome`
(TRACE v0.2 section 3.1.2). This module makes an OpenProof approval that
target, and checks one:

- `reference()` builds the `references` entry for an OpenProof approval. Its
  `digest` is the SHA-256 of the RFC 8785 canonical form of the approved
  request (the signed approval, the exact content and the owner's passkey
  assertion), as TRACE requires for every registered relation.
- `check()` follows the verifier steps of the crosswalk in README.md and
  reports one verdict. It needs only this file, `rfc8785` and `cryptography`:
  no OpenProof binary and no TRACE library.

TRACE section 3.1.2 rule 3 holds throughout: whatever the reference resolves
to, the Trust Record itself verifies or not on its own signature.
"""

import base64, hashlib, json
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REL = "approval-outcome"
ID_PREFIX = "openproof/approval/"


# ---------------------------------------------------------------- encodings


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64u(text):
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u(raw) != text:
        raise ValueError("noncanonical base64url")
    return raw


def jcs(value):
    """RFC 8785 canonical bytes. TRACE requires an RFC 8785 library."""
    return rfc8785.dumps(value)


def jcs_digest(value):
    return "sha256:" + hashlib.sha256(jcs(value)).hexdigest()


def opec(value):
    """OpenProof OPEC-1 canonical bytes, as crates/openproof-core and
    reference/python/openproof_ref.py define them: a one-byte type tag, 64-bit
    big-endian lengths, object keys sorted by their UTF-8 bytes."""

    def frame(n):
        return n.to_bytes(8, "big")

    def enc(v):
        if v is None:
            return b"\x00"
        if v is False:
            return b"\x01"
        if v is True:
            return b"\x02"
        if type(v) is int:
            if not 0 <= v < 2**64:
                raise ValueError("OPEC-1 integers are unsigned 64-bit")
            return b"\x03" + frame(v)
        if type(v) is str:
            raw = v.encode()
            return b"\x04" + frame(len(raw)) + raw
        if type(v) is list:
            return b"\x05" + frame(len(v)) + b"".join(enc(x) for x in v)
        if type(v) is dict:
            keys = sorted(v, key=lambda k: k.encode())
            return b"\x06" + frame(len(v)) + b"".join(enc(k) + enc(v[k]) for k in keys)
        raise ValueError("unsupported value")

    return b"OPEC\x01" + enc(value)


def openproof_preimage(domain, payload):
    return b"OpenProof/v1/" + domain.encode() + b"\0" + opec(payload)


def openproof_digest(domain, payload):
    return hashlib.sha256(openproof_preimage(domain, payload)).hexdigest()


def openproof_verify(signed, domain, key_hex):
    """An OpenProof Signed<T>: Ed25519 over the domain-separated OPEC-1 bytes."""
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(
            bytes.fromhex(signed["signature"]),
            openproof_preimage(domain, signed["payload"]),
        )
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


# ---------------------------------------------------------------- TRACE records


def trace_preimage(record):
    """TRACE v0.2 section 3.2.2: RFC 8785 over the record without `signature`."""
    return jcs({k: v for k, v in record.items() if k != "signature"})


def sign_trace_record(record, key):
    """Embedded EdDSA signature; the key goes in `cnf.jwk` before signing."""
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    record = dict(record, cnf={"jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}})
    record.pop("signature", None)
    record["signature"] = b64u(key.sign(trace_preimage(record)))
    return record


def verify_trace_record(record):
    """Signature check only (TRACE section 3.2.2). Freshness and appraisal are
    the relying party's TRACE verifier's job and are not repeated here."""
    try:
        jwk = record["cnf"]["jwk"]
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            return False
        Ed25519PublicKey.from_public_bytes(unb64u(jwk["x"])).verify(
            unb64u(record["signature"]), trace_preimage(record)
        )
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


# ---------------------------------------------------------------- the reference


def approval_digest(request):
    return openproof_digest("document-approval/1", request["approval"]["payload"])


def reference(request, resolver, retention=None):
    """The `references` entry a TRACE producer adds for an OpenProof approval."""
    entry = {
        "rel": REL,
        "id": ID_PREFIX + approval_digest(request),
        "resolver": resolver,
        "digest": jcs_digest(request),
    }
    if retention:
        entry["retention"] = retention
    return entry


def store_entry(request, receipt=None, checkpoint=None):
    """What a resolver keeps for one approval: the approved request, and the
    receiver receipt and witness checkpoint once it executed."""
    return {"request": request, "receipt": receipt, "checkpoint": checkpoint}


# ---------------------------------------------------------------- the check


def passkey_ok(request, passkey, digest_hex):
    """WebAuthn ES256 assertion over the approval digest (OpenProof passkey.rs)."""
    try:
        a = request["owner_assertion"]
        auth = unb64u(a["authenticator_data"])
        client = unb64u(a["client_data_json"])
        data = json.loads(client)
        if (
            data.get("type") != "webauthn.get"
            or data.get("challenge") != b64u(bytes.fromhex(digest_hex))
            or data.get("origin") != passkey["origin"]
            or data.get("crossOrigin", False) is not False
            or len(auth) < 37
            or auth[:32] != hashlib.sha256(passkey["rp_id"].encode()).digest()
            or auth[32] & 0x05 != 0x05
        ):
            return False
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(passkey["public_key"])
        )
        key.verify(
            unb64u(a["signature"]),
            auth + hashlib.sha256(client).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


def check(record, store, root_key):
    """Follow the crosswalk steps and return the findings and one verdict.

    `store` is what the resolver holds: {"signed_trust": ..., "entries": {id: entry}}.
    `root_key` is the OpenProof trust root, obtained separately from the store.
    """
    out = {
        "trace_record_verifies": verify_trace_record(record),
        "reference_resolves": False,
        "digest_matches": None,
        "approval_attributable": None,
        "executed_as_approved": None,
        "witnessed": None,
    }

    def done(verdict):
        out["verdict"] = verdict
        return out

    refs = [r for r in record.get("references", []) if r.get("rel") == REL]
    if len(refs) != 1:
        return done("no-approval-reference")
    ref = refs[0]
    entry = store.get("entries", {}).get(ref.get("id"))
    if entry is None:
        # Rule 3: the record still verifies; the approval is unconfirmed.
        return done("approval-unconfirmed")
    out["reference_resolves"] = True
    request = entry["request"]
    out["digest_matches"] = jcs_digest(request) == ref.get("digest")
    if not out["digest_matches"]:
        return done("approval-contradicted")
    # The trust names the authority, receiver, witness and owner passkey keys.
    signed_trust = store["signed_trust"]
    if not openproof_verify(signed_trust, "witness-trust/1", root_key):
        out["approval_attributable"] = False
        return done("trust-unverified")
    trust = signed_trust["payload"]
    digest_hex = approval_digest(request)
    approval = request["approval"]["payload"]
    attributable = (
        ref["id"] == ID_PREFIX + digest_hex
        and approval["authority"] not in trust["revoked_authorities"]
        and approval["authority"]
        in [trust["authority"], *trust["previous_authorities"]]
        and openproof_verify(
            request["approval"], "document-approval/1", approval["authority"]
        )
        and approval["content_sha256"]
        == hashlib.sha256(request["content"].encode()).hexdigest()
        and approval["receiver"] == trust["receiver"]
    )
    passkey = trust.get("owner_passkey")
    if attributable and passkey is not None:
        attributable = passkey_ok(request, passkey, digest_hex)
    out["approval_attributable"] = attributable
    if not attributable:
        return done("approval-not-attributable")
    receipt = entry.get("receipt")
    if receipt is None:
        out["executed_as_approved"] = False
        return done("approved-not-executed")
    r = receipt["payload"]
    out["executed_as_approved"] = (
        openproof_verify(receipt, "receiver-receipt/1", trust["receiver"])
        and r["kind"] == "update"
        and r["approval_sha256"] == digest_hex
        and r["content_sha256"] == approval["content_sha256"]
        and r["document"] == approval["document"]
        and r["document_version"] == approval["expected_version"] + 1
    )
    if not out["executed_as_approved"]:
        return done("execution-contradicted")
    cp = entry.get("checkpoint")
    out["witnessed"] = bool(
        cp
        and openproof_verify(cp, "witness-checkpoint/1", trust["witness"])
        and cp["payload"]["receiver"] == trust["receiver"]
        and cp["payload"]["count"] >= r["sequence"]
    )
    return done(
        "approval-confirmed-and-executed"
        if out["witnessed"]
        else "executed-unwitnessed"
    )


def new_record_key():
    return Ed25519PrivateKey.generate()
