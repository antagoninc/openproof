#!/usr/bin/env python3
"""Seeded process-crash/restart exercise on disposable local state only."""

import argparse, json, random, subprocess, sys, time
from pathlib import Path
from witness_workflow import initialize, call
from owner_app import Owner
from paged_workflow import enable

ROOT = Path(__file__).resolve().parents[1]
CHILD = """import os,sys
sys.path.insert(0,sys.argv[1]);import witness_workflow,paged_workflow
real=witness_workflow.call
def interrupt(args,value=None):
 result=real(args,value)
 if args[0]==sys.argv[4]:os._exit(73)
 return result
witness_workflow.call=interrupt;paged_workflow.call=interrupt
witness_workflow.Broker(sys.argv[2]).commit(sys.argv[3])
"""


def run(out, cycles, seed):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    home = out / "private-home"
    initialize(home)
    enable(home)
    owner = Owner(home)
    rng = random.Random(seed)
    results = []
    for i in range(cycles):
        boundary = (
            ["receive", "witness", "verify-page"][i % 3]
            if i < 3
            else rng.choice(["receive", "witness", "verify-page"])
        )
        identity = owner.broker.propose("report", i, f"Synthetic crash fixture {i}")[
            "proposal_id"
        ]
        r = owner.review(identity)
        owner.approve(identity, r["review_token"])
        child = subprocess.run(
            [
                sys.executable,
                "-c",
                CHILD,
                str(ROOT / "scripts"),
                str(home),
                identity,
                boundary,
            ],
            capture_output=True,
            timeout=60,
        )
        if child.returncode != 73:
            raise AssertionError("Crash boundary did not execute")
        from recovery_center import recover

        result = recover(owner, identity)
        if (
            result.get("verification_status") != "local_consistency_verified"
            or result["document_version"] != i + 1
        ):
            raise AssertionError("Recovery failed or duplicate effect")
        for role in ["receiver", "witness"]:
            if call(["head", home / role / "state"])["count"] != i + 1:
                raise AssertionError("Unexpected durable sequence")
        results.append(
            {
                "cycle": i,
                "crash_after": boundary,
                "document_version": i + 1,
                "recovered": True,
            }
        )
        (out / "results.json").write_text(
            json.dumps(
                {
                    "seed": seed,
                    "completed_cycles": len(results),
                    "requested_cycles": cycles,
                    "results": results,
                    "scope": "Process exits after completed CLI calls; not torn filesystem writes, power loss or independent-host recovery.",
                },
                indent=2,
            )
            + "\n"
        )
    return results


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True)
    p.add_argument("--cycles", type=int, default=30)
    p.add_argument("--seed", type=int, default=20261108)
    a = p.parse_args()
    if not 1 <= a.cycles <= 1000:
        p.error("cycles must be 1..1000")
    print(json.dumps({"completed_cycles": len(run(a.out, a.cycles, a.seed))}))
