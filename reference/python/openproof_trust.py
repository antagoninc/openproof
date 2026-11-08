#!/usr/bin/env python3
"""Independent offline trust verification. Caller supplies trusted anchor and evaluation time."""

import copy, json, sys
import openproof_ref as ref


def validate(t):
    ref.fields(
        t, ["version", "audience", "revision", "issued_at", "expires_at", "keys"]
    )
    ref.need(t["version"] == "openproof-trust/1", "unsupported trust version")
    ref.text(t["audience"])
    for n in ["revision", "issued_at", "expires_at"]:
        ref.integer(t[n])
    ref.need(
        0 < t["revision"] <= 2**63 - 1 and t["issued_at"] <= t["expires_at"],
        "revision/window",
    )
    ref.need(type(t["keys"]) is list and 1 <= len(t["keys"]) <= 1024, "key count")
    seen = set()
    for k in t["keys"]:
        ref.fields(
            k, ["public_key", "role", "not_before", "expires_at"], ["revoked_at"]
        )
        ref.public(k["public_key"])
        ref.need(k["role"] in ["authority", "actor", "executor"], "role")
        ref.integer(k["not_before"])
        ref.integer(k["expires_at"])
        ref.need(k["not_before"] <= k["expires_at"], "key window")
        if k.get("revoked_at") is not None:
            ref.integer(k["revoked_at"])
        pair = (k["public_key"], k["role"])
        ref.need(pair not in seen, "duplicate role/key")
        seen.add(pair)


def preimage(t):
    validate(t)
    # Rust serializes missing Option fields as explicit null before canonicalization.
    t = copy.deepcopy(t)
    for k in t["keys"]:
        k.setdefault("revoked_at", None)
    return b"OpenProof/v1/trust-bundle\0" + ref.canonical(t)


def snapshot(s, a, now):
    ref.fields(a, ["root_key", "audience", "minimum_revision"])
    ref.integer(a["minimum_revision"])
    ref.need(type(a["audience"]) is str, "audience string")
    ref.integer(now)
    ref.fields(s, ["payload", "signature"])
    raw = ref.hx(s["signature"], 64)
    ref.need(int.from_bytes(raw[32:], "little") < ref.L, "scalar")
    ref.nonweak(raw[:32])
    ref.need(
        (int.from_bytes(raw[:32], "little") & ((1 << 255) - 1)) < ref.P, "R encoding"
    )
    ref.public(a["root_key"]).verify(raw, preimage(s["payload"]))
    t = s["payload"]
    ref.need(t["audience"] == a["audience"], "audience")
    ref.need(t["revision"] >= a["minimum_revision"], "pinned revision")
    ref.need(t["issued_at"] <= now <= t["expires_at"], "snapshot freshness")


def verify(b, c, s, a, now, mode):
    ref.need(mode in ["current", "historical"], "mode")
    snapshot(s, a, now)
    ref.need(c["audience"] == a["audience"], "context audience")
    ref.integer(c["now"])
    ref.need(c["now"] <= now, "future evaluation")
    effective = copy.deepcopy(c)
    if mode == "current":
        effective["now"] = now
    report = ref.verify(b, effective)

    def allowed(key, role, event):
        k = next(
            (
                k
                for k in s["payload"]["keys"]
                if k["public_key"] == key and k["role"] == role
            ),
            None,
        )
        ref.need(k is not None, "key/role absent")
        ref.need(
            k.get("revoked_at") is None or now < k["revoked_at"],
            "revoked including history",
        )
        ref.need(k["not_before"] <= event <= k["expires_at"], "event key validity")
        if mode == "current":
            ref.need(k["not_before"] <= now <= k["expires_at"], "current key validity")

    auth = b["authorization"]["payload"]
    for event in [auth["not_before"], auth["expires_at"]]:
        allowed(c["authority_key"], "authority", event)
    allowed(c["actor_key"], "actor", b["action"]["payload"]["claimed_at"])
    allowed(
        c["executor_key"],
        "executor",
        (
            b["receipt"]["payload"]["observed_at"]
            if b.get("receipt")
            else effective["now"]
        ),
    )
    return report


if __name__ == "__main__":
    try:
        if len(sys.argv) != 7:
            raise ValueError(
                "usage: openproof_trust.py BUNDLE CONTEXT SNAPSHOT ANCHOR MODE TRUSTED_UNIX_TIME"
            )
        print(
            json.dumps(
                verify(
                    *(ref.read(p) for p in sys.argv[1:5]), int(sys.argv[6]), sys.argv[5]
                ),
                indent=2,
            )
        )
    except Exception as e:
        print("openproof-trust-ref: " + str(e), file=sys.stderr)
        sys.exit(1)
