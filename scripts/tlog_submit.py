#!/usr/bin/env python3
"""Push the witness's checkpoint to independent C2SP witnesses and keep their cosignatures.

    python3 scripts/tlog_submit.py HOME

This program is outside the trusted code. It only carries bytes: the OpenProof
witness signs the checkpoint and the consistency proof (`tlog-request`), each
public witness checks them and cosigns (c2sp.org/tlog-witness), and the binary
checks every cosignature (`tlog-verify`) before anything is saved. A lying
submitter can withhold cosignatures; it cannot make one up.

Configuration, HOME/tlog/witnesses.json:

    {"origin": "openproof.example.org/log/1", "quorum": 1,
     "witnesses": [{"name": "w.example", "url": "https://w.example/witness",
                    "vkey": "w.example+1234abcd+BA..."}]}

`url` is the witness's submission prefix; `vkey` its Ed25519 cosigner key
(c2sp.org/tlog-cosignature). The origin is fixed by the first submission.

Writes HOME/tlog/sizes.json (the size each witness last cosigned) and
HOME/tlog/checkpoint.note: the newest checkpoint with the quorum of valid
cosignatures. A checkpoint short of the quorum goes to pending.note instead.
"""

import json, sys, tempfile, urllib.error, urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from witness_workflow import call

TIMEOUT = 20


def post(url, body):
    request = urllib.request.Request(
        url.rstrip("/") + "/add-checkpoint", data=body.encode(), method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def note_of(request):
    # The request is "old N", the proof lines, a blank line, then the signed note.
    return request.split("\n\n", 1)[1]


def cosigned_by(trust, origin, vkeys, note):
    """The cosigners in `vkeys` whose cosignature on `note` the binary accepts."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(vkeys, f)
    try:
        return call(["tlog-verify", trust, origin, f.name], note)["cosigned_by"]
    finally:
        Path(f.name).unlink()


def submit(home):
    home = Path(home)
    folder = home / "tlog"
    config = json.loads((folder / "witnesses.json").read_text())
    origin, witnesses = config["origin"], config["witnesses"]
    quorum = int(config.get("quorum", 1))
    if quorum < 1:
        raise ValueError("quorum must be at least 1")
    sizes_path = folder / "sizes.json"
    sizes = json.loads(sizes_path.read_text()) if sizes_path.exists() else {}
    state, key, trust = (
        home / "witness/state",
        home / "witness/key.secret",
        home / "trust.json",
    )
    notes, report = {}, []
    for w in witnesses:
        old, status, text = sizes.get(w["name"], 0), 0, ""
        try:
            for _ in range(2):
                req = call(["tlog-request", state, key, trust, origin, str(old)])[
                    "request"
                ]
                status, text = post(w["url"], req)
                if status == 409 and text.strip().isdigit():
                    # The witness holds a different size: retry once from its size.
                    old = int(text.strip())
                    continue
                break
        except (OSError, RuntimeError) as e:
            # Unreachable, or a witness ahead of this log: never cosign that.
            status, text = 0, str(e)
        if status != 200:
            report.append({"witness": w["name"], "status": status, "error": text[:200]})
            continue
        note = note_of(req)
        # Keep only the lines this witness's own key verifies on this note.
        lines = [l + "\n" for l in text.splitlines() if l.startswith("\u2014 ")]
        good = [l for l in lines if cosigned_by(trust, origin, [w["vkey"]], note + l)]
        if not good:
            report.append(
                {
                    "witness": w["name"],
                    "status": status,
                    "error": "no valid cosignature",
                }
            )
            continue
        notes.setdefault(note, []).extend(good)
        sizes[w["name"]] = int(note.split("\n", 2)[1])
        report.append({"witness": w["name"], "status": 200})
    sizes_path.write_text(json.dumps(sizes, indent=2) + "\n")
    result = {"cosigned_by": [], "witnesses": report, "quorum_met": False}
    if not notes:
        return result
    note = max(notes, key=lambda n: int(n.split("\n", 2)[1]))
    merged = note + "".join(dict.fromkeys(notes[note]))
    result["cosigned_by"] = cosigned_by(
        trust, origin, [w["vkey"] for w in witnesses], merged
    )
    result["size"] = int(note.split("\n", 2)[1])
    result["quorum_met"] = len(result["cosigned_by"]) >= quorum
    # Replace the kept checkpoint only with one that meets the quorum.
    if result["quorum_met"]:
        (folder / "checkpoint.note").write_text(merged)
    else:
        (folder / "pending.note").write_text(merged)
    return result


if __name__ == "__main__":
    print(json.dumps(submit(sys.argv[1]), indent=2))
