"""The witness history as a transparency log, cosigned by independent C2SP witnesses."""

import json, os, subprocess, sys, tempfile, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from witness_workflow import Broker, call, initialize, ref
from paged_workflow import enable
from portable_history import export_history
from tlog_submit import submit, post
from c2sp_test_witness import Witness

ORIGIN = "openproof.test/log/1"
GO = os.environ.get(
    "OPENPROOF_GO_VERIFY", str(ROOT / "outputs/v0.9/openproof-go-verify")
)


class TlogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "outputs")
        self.h = Path(self.temp.name) / "home"
        initialize(self.h)
        enable(self.h)
        self.b = Broker(self.h)
        self.version = 0
        public = ref.read(self.h / "trust.json")["witness"]
        self.log_vkey = call(["tlog-vkey", ORIGIN, public])["vkey"]
        self.witnesses, self.servers = [], []
        for name in ("witness-a.test/1", "witness-b.test/1"):
            w = Witness(name)
            w.add_log(ORIGIN, self.log_vkey)
            server, url = w.serve()
            self.witnesses.append((w, url))
            self.servers.append(server)
        self.configure(quorum=2)

    def tearDown(self):
        for s in self.servers:
            s.shutdown()
        self.temp.cleanup()

    def configure(self, quorum, origin=ORIGIN):
        folder = self.h / "tlog"
        folder.mkdir(exist_ok=True)
        (folder / "witnesses.json").write_text(
            json.dumps(
                {
                    "origin": origin,
                    "quorum": quorum,
                    "witnesses": [
                        {"name": w.name, "url": url, "vkey": w.vkey}
                        for w, url in self.witnesses
                    ],
                }
            )
        )

    def change(self, text):
        identity = self.b.propose("report", self.version, text)["proposal_id"]
        self.b.approve(identity, reader=lambda prompt: prompt[5:-2])
        self.assertEqual(
            self.b.commit(identity)["verification_status"], "local_consistency_verified"
        )
        self.version += 1

    def verify_archive(self, quorum, note=None):
        archive = Path(self.temp.name) / ("archive-%d" % time.time_ns())
        export_history(self.h, archive)
        cosigners = Path(self.temp.name) / "cosigners.json"
        cosigners.write_text(json.dumps([w.vkey for w, _ in self.witnesses]))
        note_file = Path(self.temp.name) / "checkpoint.note"
        note_file.write_text(note or (self.h / "tlog/checkpoint.note").read_text())
        root = ref.read(self.h / "root-public.json")["public_key"]
        return subprocess.run(
            [
                GO,
                "verify-archive",
                root,
                str(archive / "checkpoint-copy.json"),
                str(archive),
                str(int(time.time())),
                str(note_file),
                ORIGIN,
                str(cosigners),
                str(quorum),
            ],
            capture_output=True,
            text=True,
        )

    def test_cosigned_twice_and_verified_offline_by_the_go_verifier(self):
        self.change("first")
        self.change("second")
        r = submit(self.h)
        self.assertTrue(r["quorum_met"], r)
        self.assertEqual(r["size"], 2)
        self.change("third")
        r = submit(self.h)  # now with an RFC 6962 consistency proof from size 2
        self.assertEqual((r["size"], len(r["cosigned_by"])), (3, 2), r)
        self.assertEqual(
            json.loads((self.h / "tlog/sizes.json").read_text()),
            {"witness-a.test/1": 3, "witness-b.test/1": 3},
        )
        ok = self.verify_archive(quorum=2)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        result = json.loads(ok.stdout)
        self.assertEqual(result["count"], 3)
        self.assertEqual(
            sorted(c["name"] for c in result["cosigned_by"]),
            ["witness-a.test/1", "witness-b.test/1"],
        )
        # The verifier refuses a quorum it cannot meet.
        self.assertNotEqual(self.verify_archive(quorum=3).returncode, 0)

    def test_the_go_verifier_binds_the_cosigned_tree_to_the_whole_history(self):
        self.change("first")
        submit(self.h)
        stale = (self.h / "tlog/checkpoint.note").read_text()
        self.change("second")
        # A note cosigned for size 1 does not cover a history of 2 receipts.
        self.assertNotEqual(self.verify_archive(quorum=1, note=stale).returncode, 0)
        submit(self.h)
        self.assertEqual(self.verify_archive(quorum=1).returncode, 0)

    def test_a_bad_proof_is_refused_and_nothing_advances(self):
        self.change("first")
        submit(self.h)
        self.change("second")
        self.change("third")
        request = call(
            [
                "tlog-request",
                self.h / "witness/state",
                self.h / "witness/key.secret",
                self.h / "trust.json",
                ORIGIN,
                "1",
            ]
        )["request"]
        lines = request.split("\n")
        lines[1] = lines[1][:-4] + ("AAA=" if not lines[1].endswith("AAA=") else "BBB=")
        status, _ = post(self.witnesses[0][1], "\n".join(lines))
        self.assertEqual(status, 422)
        self.assertEqual(self.witnesses[0][0].logs[ORIGIN][1], 1)

    def test_a_lost_size_is_recovered_from_the_witness(self):
        self.change("first")
        submit(self.h)
        self.change("second")
        (self.h / "tlog/sizes.json").unlink()  # the submitter forgot what was cosigned
        r = submit(self.h)
        self.assertEqual((r["size"], len(r["cosigned_by"])), (2, 2), r)

    def test_the_origin_never_changes(self):
        self.change("first")
        submit(self.h)
        with self.assertRaisesRegex(RuntimeError, "origin never changes"):
            call(
                [
                    "tlog-request",
                    self.h / "witness/state",
                    self.h / "witness/key.secret",
                    self.h / "trust.json",
                    "openproof.test/log/2",
                    "0",
                ]
            )

    def test_a_witness_that_does_not_know_the_log_cosigns_nothing(self):
        self.change("first")
        stranger = Witness("stranger.test/1")
        server, url = stranger.serve()
        self.servers.append(server)
        self.witnesses = [(stranger, url)]
        self.configure(quorum=1)
        r = submit(self.h)
        self.assertEqual(r["witnesses"][0]["status"], 404)
        self.assertEqual(r["cosigned_by"], [])


if __name__ == "__main__":
    unittest.main()
