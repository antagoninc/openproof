#!/usr/bin/env python3
"""Synthetic witnessed workflow. Approval responses are simulated, never represented as human consent."""

import argparse, json
from pathlib import Path
from witness_workflow import Broker, initialize, call, save, timeline
from witness_client import Client

p = argparse.ArgumentParser()
p.add_argument("--out", required=True)
args = p.parse_args()
home = Path(args.out).resolve()
initialize(home)
b = Broker(home)
with Client(home) as client:
    proposal = client.tool(
        "document_propose",
        {
            "document": "project-status",
            "expected_version": 0,
            "content": "OpenProof synthetic receiver-witness demonstration. No model was called.",
        },
    )
    try:
        client.tool("document_commit", {"proposal_id": proposal["proposal_id"]})
    except RuntimeError:
        denied = True
    else:
        raise AssertionError("unapproved request executed")
    b.approve(
        proposal["proposal_id"],
        reader=lambda _: "APPROVE " + proposal["content_sha256"][:12],
    )
    result = client.tool("document_commit", {"proposal_id": proposal["proposal_id"]})
    repeat = client.tool("document_commit", {"proposal_id": proposal["proposal_id"]})
    assert result["document_version"] == repeat["document_version"] == 1
run = home / "evidence" / result["evidence_id"]
timeline(
    run / "package.json",
    home / "trust.json",
    run / "checkpoint.json",
    home / "timeline.html",
)
save(
    home / "demo-result.json",
    dict(
        approval_mode="simulated_test_response",
        external_model_calls=0,
        unapproved_denied=denied,
        idempotent_retry=True,
        assessment=result,
    ),
)
print(json.dumps(result, indent=2))
