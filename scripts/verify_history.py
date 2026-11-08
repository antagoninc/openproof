#!/usr/bin/env python3
"""Verify an extracted archive offline with independently supplied trust.
Runs a separately obtained Go verifier; nothing from the archive is executed."""

import argparse, datetime, hashlib, json, re, subprocess, sys, time
from pathlib import Path


def verify(directory, root, checkpoint, binary, out):
    directory = Path(directory).resolve()
    checkpoint = Path(checkpoint).resolve()
    binary = Path(binary).resolve()
    out = Path(out).resolve()
    if not re.fullmatch("[0-9a-f]{64}", root):
        raise ValueError("Root must be a separately trusted 32-byte public key")
    if binary.is_relative_to(directory):
        raise ValueError("Use a verifier obtained separately from the evidence archive")
    if checkpoint.is_relative_to(directory):
        raise ValueError(
            "Supply the checkpoint from your separate trusted channel, outside the archive"
        )
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    now = int(time.time())
    r = subprocess.run(
        [
            str(binary),
            "verify-archive",
            root,
            str(checkpoint),
            str(directory),
            str(now),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    result = {
        "status": "rejected",
        "checked_at": datetime.datetime.fromtimestamp(
            now, datetime.timezone.utc
        ).isoformat(),
        "trusted_genesis_root": root,
        "independent_operators_established": False,
        "physical_effects_proven": False,
    }
    if r.returncode == 0:
        checked = json.loads(r.stdout)
        if checked.get("status") not in [
            "portable_history_verified",
            "unknown_due_to_disclosed_gap",
        ]:
            raise ValueError("Unexpected verifier response")
        result.update(checked)
    result["verifier_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("archive")
    for name in ["root", "checkpoint", "go-binary", "out"]:
        p.add_argument("--" + name, required=True)
    a = p.parse_args()
    result = verify(a.archive, a.root, a.checkpoint, a.go_binary, a.out)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "portable_history_verified" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, TimeoutError) as e:
        print("Verification unavailable: " + str(e), file=sys.stderr)
        sys.exit(1)
