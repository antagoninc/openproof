"""Interactive approval of captured bytes; no reusable approval token or deferred dispatch."""

import hashlib, json, sys, time


def approve(report, out, *, reader=None):
    if reader is None:
        if not sys.stdin.isatty():
            raise RuntimeError("Human approval requires an interactive terminal")
        reader = input
    digest = hashlib.sha256(report).hexdigest()
    # JSON escaping prevents terminal controls, bidi controls and invisible Unicode hiding text.
    print("\nREVIEW BEFORE AUTHORIZATION")
    print("Action: artifact.write | resource: urn:openproof:artifact")
    print("Destination: " + str(out / "state/jobs") + "/<nonce-derived-id>/output.bin")
    print(
        "Exact UTF-8 report as a JSON string (escapes are literal byte representations):"
    )
    print(json.dumps(report.decode("utf-8"), ensure_ascii=True))
    print(f"Bytes: {len(report)} | SHA-256: {digest}")
    if (
        reader(
            "Type APPROVE "
            + digest[:12]
            + " to authorize these exact bytes, or anything else to cancel: "
        )
        != "APPROVE " + digest[:12]
    ):
        raise RuntimeError("Approval declined; no authorization or execution created")
    return {
        "version": "openproof-human-approval/1",
        "report_sha256": digest,
        "bytes": len(report),
        "tool": "artifact.write",
        "resource": "urn:openproof:artifact",
        "destination_root": str(out / "state/jobs"),
        "approved_at": int(time.time()),
        "kind": "local-interactive-observation",
        "independent_identity_proven": False,
    }
