#!/usr/bin/env python3
"""Real synthetic tamper experiments, with an interactive recorded-results explorer."""

import argparse, copy, hashlib, html, json, os, shutil, subprocess, time
from pathlib import Path
from witness_workflow import initialize, call, ref, save
from paged_workflow import enable
from owner_app import Owner
from portable_history import export_history
from history_viewer import document


def run(out, binary):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    home = out / "private-demo-home"
    initialize(home)
    enable(home)
    owner = Owner(home)
    results = []
    p = owner.broker.propose(
        "demo-report", 0, "Public synthetic report. No model was called."
    )["proposal_id"]
    try:
        owner.broker.commit(p)
    except (RuntimeError, FileNotFoundError):
        pass
    else:
        raise AssertionError("Unapproved action was accepted")
    results.append(
        dict(
            name="No approval",
            expected="rejected",
            observed="rejected",
            meaning="A proposal alone cannot authorize execution.",
        )
    )
    review = owner.review(p)
    owner.approve(
        p, review["review_token"]
    )  # Explicitly simulated, never human consent.
    q = owner.broker.request(p)
    for name, change in [
        ("Changed content", lambda x: x.update(content="Substituted content")),
        (
            "Substituted signer",
            lambda x: x["approval"]["payload"].update(
                authority=ref.read(home / "trust.json")["receiver"]
            ),
        ),
    ]:
        bad = copy.deepcopy(q)
        change(bad)
        try:
            call(
                [
                    "receive",
                    home / "receiver/state",
                    home / "receiver/key.secret",
                    home / "trust.json",
                ],
                bad,
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError(name + " was accepted")
        if call(["head", home / "receiver/state"])["count"] != 0:
            raise AssertionError("Rejected request changed state")
        results.append(
            dict(
                name=name,
                expected="rejected",
                observed="rejected",
                meaning="The signature and approval bind the exact content and authority.",
                before=q,
                after=bad,
            )
        )
    first = owner.broker.commit(p)
    again = owner.broker.commit(p)
    if (
        first["document_version"] != 1
        or again["document_version"] != 1
        or call(["head", home / "receiver/state"])["count"] != 1
    ):
        raise AssertionError("Retry created duplicate effect")
    results.append(
        dict(
            name="Replay the same approval",
            expected="original receipt; no second update",
            observed="original receipt; no second update",
            meaning="An identical approved retry recovers the original effect. Replay is idempotent, not necessarily an error.",
        )
    )
    archive = out / "public-evidence"
    export_history(home, archive)
    root = ref.read(home / "root-public.json")["public_key"]
    pin = out / "demo-checkpoint.json"
    shutil.copyfile(archive / "checkpoint-copy.json", pin)

    def check(folder):
        r = subprocess.run(
            [
                str(Path(binary).resolve()),
                "verify-archive",
                root,
                str(pin),
                str(folder),
                str(int(time.time())),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return r.returncode == 0

    if not check(archive):
        raise AssertionError("Unmodified baseline failed")
    results.append(
        dict(
            name="Intact evidence",
            expected="verified",
            observed="verified",
            meaning="Go reconstructs the signed chain against the demo root and checkpoint. Both anchors are locally generated; independence is not established.",
        )
    )
    for name, kind in [
        ("Remove evidence", "omit"),
        ("Alter archived content", "content"),
        ("Replay a receipt in history", "duplicate"),
    ]:
        folder = out / ("attack-" + kind)
        shutil.copytree(archive, folder)
        m = ref.read(folder / "manifest.json")
        if kind == "omit":
            m["entries"] = m["entries"][1:]
        else:
            entry = m["entries"][0]
            f = folder / entry["file"]
            value = ref.read(f)
            if kind == "content":
                value["page"]["requests"][0]["content"] = "Changed archive report"
            else:
                value["page"]["receipts"].append(
                    copy.deepcopy(value["page"]["receipts"][0])
                )
            f.write_text(json.dumps(value))
            entry["sha256"] = hashlib.sha256(f.read_bytes()).hexdigest()
        (folder / "manifest.json").write_text(json.dumps(m))
        if check(folder):
            raise AssertionError(name + " passed")
        results.append(
            dict(
                name=name,
                expected="rejected",
                observed="rejected",
                meaning="Changing the unsigned file manifest cannot repair the signed chain. Rejection alone does not diagnose malicious intent.",
            )
        )
    report = dict(
        version="openproof-assurance-lab/1",
        approval_mode="simulated_test_response",
        external_model_calls=0,
        independent_operators=False,
        cases=results,
    )
    save(out / "results.json", report)
    cards = []
    for r in results:
        extra = ""
        for key in ["before", "after"]:
            if key in r:
                extra += (
                    "<h3>"
                    + key.title()
                    + "</h3><pre>"
                    + html.escape(json.dumps(r[key], indent=2))
                    + "</pre>"
                )
        cards.append(
            "<details><summary>"
            + html.escape(r["name"])
            + " · "
            + html.escape(r["observed"])
            + "</summary><p>"
            + html.escape(r["meaning"])
            + "</p>"
            + extra
            + "</details>"
        )
    (out / "lab.html").write_text(
        document(
            "See what changes. See what breaks.",
            "<p>Expand an experiment to explore its recorded result. These outcomes came from real Rust receiver and Go verifier calls during this run; this page does not rerun cryptography.</p><article><h2>Synthetic approval, real checks</h2><p>All content and keys were generated locally for this demonstration. Approval was simulated. No model, independent operator or human auditor participated. This does not prove physical effects or model truth.</p></article>"
            + "".join(cards),
        )
    )
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True)
    p.add_argument("--go-binary", required=True)
    a = p.parse_args()
    r = run(a.out, a.go_binary)
    print(
        json.dumps(
            {
                "cases_passed": len(r["cases"]),
                "explorer": str(Path(a.out).resolve() / "lab.html"),
            }
        )
    )


if __name__ == "__main__":
    main()
