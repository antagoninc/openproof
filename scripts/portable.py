"""Original portable evidence envelope. Never extracts files or trusts an embedded anchor."""

import base64, hashlib, json, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference/python"))
import openproof_ref as ref
import openproof_trust as trust

VERSION = "openproof-portable/1"


def verify(package, anchor, now=None):
    ref.fields(package, ["version", "bundle", "context", "snapshot", "output_base64"])
    ref.need(package["version"] == VERSION, "unsupported portable version")
    output = base64.b64decode(package["output_base64"], validate=True)
    ref.need(len(output) <= ref.MAX, "output too large")
    result = trust.verify(
        package["bundle"],
        package["context"],
        package["snapshot"],
        anchor,
        int(time.time()) if now is None else now,
        "historical",
    )
    receipt = package["bundle"].get("receipt")
    ref.need(receipt is not None, "receipt required")
    ref.need(
        hashlib.sha256(output).hexdigest() == receipt["payload"]["output_sha256"],
        "artifact digest mismatch",
    )
    return dict(
        result,
        artifact_bytes_match_receipt=True,
        anchor_source="independently supplied file",
        verified_at=int(time.time()) if now is None else now,
    )


def export(run, destination):
    from render_evidence import inside

    run = Path(run).resolve()
    execution = ref.read(inside(run, run / "execution.json"))
    jobs = inside(run, run / "state/jobs")
    job = inside(jobs, Path(execution["artifact_directory"]))
    with inside(job, job / "output.bin").open("rb") as f:
        output = f.read(ref.MAX + 1)
    ref.need(len(output) <= ref.MAX, "output too large")
    value = {
        "version": VERSION,
        "bundle": ref.read(inside(job, job / "bundle.json")),
        "context": ref.read(inside(job, job / "context.json")),
        "snapshot": ref.read(inside(run, run / "trust.json")),
        "output_base64": base64.b64encode(output).decode(),
    }
    # Export can preserve expired evidence. Acceptance is always a separate verification.
    raw = json.dumps(value, indent=2).encode()
    ref.need(len(raw) <= ref.MAX, "portable envelope too large")
    with Path(destination).open("xb") as f:
        f.write(raw)
    return {
        "path": str(destination),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "verified": False,
        "contains_anchor": False,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify portable evidence offline with a separately trusted root."
    )
    parser.add_argument("package")
    parser.add_argument("--anchor", required=True)
    args = parser.parse_args()
    try:
        print(
            json.dumps(verify(ref.read(args.package), ref.read(args.anchor)), indent=2)
        )
    except Exception as error:
        print("Verification rejected: " + str(error), file=sys.stderr)
        sys.exit(1)
