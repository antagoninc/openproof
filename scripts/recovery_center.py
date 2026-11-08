#!/usr/bin/env python3
"""Read-only recovery inventory plus receipt-only recovery. Never approve or redispatch."""

import argparse, json, time, re
from pathlib import Path
from witness_workflow import call, ref, home_lock, require_admission


def rotation_status(home):
    h = Path(home)
    if not (h / "rotation-pending.json").exists():
        return {"status": "not_paused", "can_resume": False}
    result = {
        "status": "needs_operator",
        "can_resume": False,
        "message": "Admission is paused. Retain the original handover and state; do not delete the pause or reset trust.",
    }
    try:
        name = ref.read(h / "rotation-pending.json")["job"]
        if not isinstance(name, str) or not re.fullmatch("[0-9a-f]{32}", name):
            return result
        handover = ref.read(h / "rotations" / name / "handover.json")
        p = handover["old_root"]["payload"]
        now = int(time.time())
        if (h / "service-client.json").exists():
            return result
        applied = {
            role: call(["rotation-applied", path], handover)["applied"]
            for role, path in [
                ("receiver", h / "receiver/state"),
                ("witness", h / "witness/state"),
                ("verifier", h / "verifier"),
            ]
        }
        live = p["not_before"] <= now <= p["expires_at"]
        result.update(applied=applied, expires_at=p["expires_at"])
        if (live or all(applied.values())) and p["new_trust"]["expires_at"] >= now:
            result.update(
                status="resumable",
                can_resume=True,
                message="Resume only this retained planned handover. This is not compromised-key recovery.",
            )
        else:
            result.update(
                status="expired_partial_handover",
                message="The handover window ended before all roles completed. Keep admission paused and obtain operator review. Automatic rollback or a replacement plan is unsupported.",
            )
    except Exception:
        pass
    return result


def certificate_status(home):
    path = Path(home) / "service-client.json"
    if not path.exists():
        return {"status": "local_roles_no_tls", "certificates": []}
    from certificate_lifecycle import inspect_certificate

    results = []
    try:
        config = ref.read(path)
        for role in ["receiver", "witness"]:
            for field in ["cert", "ca"]:
                try:
                    result = inspect_certificate(config[role][field])
                except Exception:
                    result = {
                        "status": "unreadable",
                        "scope": "Certificate could not be inspected. Ask the operator; no TLS verification was bypassed.",
                    }
                results.append(
                    dict(
                        role=role,
                        kind="client" if field == "cert" else "server_ca",
                        **result,
                    )
                )
    except Exception:
        return {"status": "configuration_unreadable", "certificates": []}
    return {
        "status": (
            "attention" if any(x["status"] != "valid" for x in results) else "valid"
        ),
        "certificates": results,
        "scope": "Inspects locally configured client/CA certificates only; remote server leaf renewal is managed by its operator.",
    }


def inventory(owner):
    h = owner.home
    items = []
    with home_lock(h):
        rotation = rotation_status(h)
        for path in sorted((h / "approved").glob("*.json")):
            item = {
                "id": path.stem,
                "can_recover": False,
                "status": "unconfirmed",
                "message": "State could not be read. Preserve the original approval and inspect the operator logs.",
            }
            try:
                q = ref.read(path)
                receipt = call(["recover", h / "receiver/state"], q)
                item["document"] = q["approval"]["payload"]["document"]
                if receipt is not None:
                    item.update(
                        status="committed",
                        document_version=receipt["payload"]["document_version"],
                        can_recover=rotation["status"] == "not_paused",
                        message="A durable receipt exists. Recovery refreshes witness/evidence state without creating a new document update.",
                    )
                elif time.time() > q["approval"]["payload"]["expires_at"]:
                    item.update(
                        status="expired_uncommitted",
                        message="No durable receipt was found. Review a new proposal separately; recovery cannot execute it.",
                    )
                else:
                    item.update(
                        status="approved_uncommitted",
                        message="No durable receipt was found. Execution is a separate owner decision in Activity.",
                    )
            except Exception:
                pass
            items.append(item)
        heads = {}
        for role in ["receiver", "witness"]:
            try:
                heads[role] = call(["head", h / role / "state"])["count"]
            except Exception:
                heads[role] = None
        saved = []
        for path in sorted((h / "evidence").glob("*/checkpoint.json")):
            try:
                saved.append(ref.read(path)["payload"]["observed_at"])
            except Exception:
                pass
        latest = max(saved) if saved else None
        age = int(time.time()) - latest if latest is not None else None
        return {
            "items": items,
            "rotation": rotation,
            "heads": heads,
            "evidence": {
                "last_recorded_at": latest,
                "age_seconds": age,
                "status": (
                    "none"
                    if age is None
                    else (
                        "needs_refresh"
                        if age < 0 or age > 300
                        else "recent_record_only"
                    )
                ),
                "scope": "Saved checkpoint age is not a fresh verification or proof that no newer event exists.",
            },
            "tls": certificate_status(h),
            "scope": "Read-only observations of configured role state. No trust reset, automatic approval or execution.",
        }


def recover(owner, identity):
    return owner.broker.commit(identity, recover_only=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("home")
    p.add_argument("--recover")
    a = p.parse_args()
    from owner_app import Owner

    owner = Owner(a.home)
    print(
        json.dumps(
            recover(owner, a.recover) if a.recover else inventory(owner), indent=2
        )
    )


if __name__ == "__main__":
    main()
