#!/usr/bin/env python3
"""Interop check: an OpenProof log cosigned by litewitness, an independent C2SP witness.

Needs `litewitness` and `witnessctl` (filippo.io/torchwood) on PATH, OpenSSH's
ssh-agent, ssh-add and ssh-keygen, the debug openproof-witness binary and the
Go verifier at OPENPROOF_GO_VERIFY. Run by .github/workflows/tlog-interop.yml.
"""

import base64, hashlib, json, os, socket, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from witness_workflow import Broker, call, initialize, ref
from paged_workflow import enable
from portable_history import export_history
from tlog_submit import submit

ORIGIN = "openproof.test/interop/1"
NAME = "litewitness.interop.test/1"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def cosigner_vkey(name, public):
    kid = hashlib.sha256(name.encode() + b"\n\x04" + public).digest()[:4]
    return "%s+%s+%s" % (name, kid.hex(), base64.b64encode(b"\x04" + public).decode())


def ssh_ed25519_public(pub_line):
    blob = base64.b64decode(pub_line.split()[1])
    # string "ssh-ed25519", then string key (each with a 4-byte length).
    n = int.from_bytes(blob[:4], "big")
    assert blob[4 : 4 + n] == b"ssh-ed25519"
    m = int.from_bytes(blob[4 + n : 8 + n], "big")
    return blob[8 + n : 8 + n + m]


def main():
    work = Path(tempfile.mkdtemp(dir=ROOT / "outputs"))
    sock, key, db = work / "agent.sock", work / "witness.key", work / "litewitness.db"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True
    )
    agent = subprocess.Popen(
        ["ssh-agent", "-D", "-a", str(sock)], stdout=subprocess.DEVNULL
    )
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.05)
    env = dict(os.environ, SSH_AUTH_SOCK=str(sock))
    subprocess.run(["ssh-add", str(key)], env=env, check=True, capture_output=True)
    fingerprint = subprocess.run(
        ["ssh-keygen", "-lf", str(key) + ".pub", "-E", "sha256"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()[1]
    public = ssh_ed25519_public(Path(str(key) + ".pub").read_text())
    witness_vkey = cosigner_vkey(NAME, public)

    home = work / "home"
    initialize(home)
    enable(home)
    log_vkey = call(["tlog-vkey", ORIGIN, ref.read(home / "trust.json")["witness"]])[
        "vkey"
    ]
    subprocess.run(
        ["witnessctl", "add-log", "-db", str(db), "-origin", ORIGIN], check=True
    )
    subprocess.run(
        ["witnessctl", "add-key", "-db", str(db), "-origin", ORIGIN, "-key", log_vkey],
        check=True,
    )
    port = free_port()
    witness = subprocess.Popen(
        [
            "litewitness",
            "-db",
            str(db),
            "-name",
            NAME,
            "-key",
            fingerprint,
            "-ssh-agent",
            str(sock),
            "-listen",
            "127.0.0.1:%d" % port,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(200):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        (home / "tlog").mkdir()
        (home / "tlog/witnesses.json").write_text(
            json.dumps(
                {
                    "origin": ORIGIN,
                    "quorum": 1,
                    "witnesses": [
                        {
                            "name": NAME,
                            "url": "http://127.0.0.1:%d" % port,
                            "vkey": witness_vkey,
                        }
                    ],
                }
            )
        )
        broker, version, results = Broker(home), 0, []
        for text in ("first", "second", "third"):
            identity = broker.propose("report", version, text)["proposal_id"]
            broker.approve(identity, reader=lambda prompt: prompt[5:-2])
            assert (
                broker.commit(identity)["verification_status"]
                == "local_consistency_verified"
            )
            version += 1
            r = submit(home)
            results.append(r)
            assert r.get("quorum_met") and r["size"] == version, r
        archive = work / "archive"
        export_history(home, archive)
        cosigners = work / "cosigners.json"
        cosigners.write_text(json.dumps([witness_vkey]))
        go = subprocess.run(
            [
                os.environ["OPENPROOF_GO_VERIFY"],
                "verify-archive",
                ref.read(home / "root-public.json")["public_key"],
                str(archive / "checkpoint-copy.json"),
                str(archive),
                str(int(time.time())),
                str(home / "tlog/checkpoint.note"),
                ORIGIN,
                str(cosigners),
                "1",
            ],
            capture_output=True,
            text=True,
        )
        assert go.returncode == 0, go.stderr
        print(
            json.dumps(
                {"submissions": results, "go_verifier": json.loads(go.stdout)}, indent=2
            )
        )
    finally:
        witness.kill()
        agent.kill()
        err = witness.stderr.read().decode(errors="replace")
        if err:
            print("litewitness log:\n" + err[-4000:], file=sys.stderr)


if __name__ == "__main__":
    main()
