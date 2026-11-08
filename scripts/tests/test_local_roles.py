"""End-to-end test of separate role accounts (scripts/local_roles.py).

This test creates real operating-system accounts, so it runs only as root on
Linux and only when OPENPROOF_ROLE_ACCOUNT_TEST=1. The role services are the
Rust binary; nothing is downloaded.
"""

import json, os, platform, pwd, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

ENABLED = (
    os.environ.get("OPENPROOF_ROLE_ACCOUNT_TEST") == "1"
    and platform.system() == "Linux"
    and os.geteuid() == 0
)
OWNER = "optest-owner"
BASE = Path("/var/lib/openproof-roletest")
PORT = 47201
# Run as the owner account: attempts that separate accounts must refuse.
PROBE = r"""
import json, socket, sqlite3, ssl, sys, http.client
base, home = sys.argv[1], sys.argv[2]
out = {}
for role in ["receiver", "witness"]:
    try:
        open(f"{base}/{role}/key.secret", "rb").read()
        out[role + "_key"] = "read"
    except PermissionError:
        out[role + "_key"] = "denied"
    try:
        db = sqlite3.connect(f"{base}/{role}/state/state.db")
        db.execute("UPDATE docs SET content='forged'")
        db.commit()
        out[role + "_state"] = "written"
    except Exception:
        out[role + "_state"] = "denied"
# The owner may call the receiver service, but an unapproved request is refused.
c = ssl.create_default_context(cafile=f"{home}/service-tls/ca.pem")
c.load_cert_chain(f"{home}/service-tls/client.pem", f"{home}/service-tls/client.key")
conn = http.client.HTTPSConnection("127.0.0.1", int(sys.argv[3]), context=c, timeout=5)
conn.request("POST", "/v1/receive", json.dumps({"request": {"forged": True}}),
             {"Content-Type": "application/json"})
out["forged_receive"] = conn.getresponse().status
print(json.dumps(out))
"""


@unittest.skipUnless(ENABLED, "needs root on Linux and OPENPROOF_ROLE_ACCOUNT_TEST=1")
class LocalRolesTests(unittest.TestCase):
    def setUp(self):
        from witness_workflow import initialize
        from paged_workflow import enable

        if not _exists(OWNER):
            subprocess.run(
                ["useradd", "--system", "--user-group", "--no-create-home", OWNER],
                check=True,
            )
        self.owner = pwd.getpwnam(OWNER)
        self.temp = tempfile.TemporaryDirectory(dir="/var/tmp")
        os.chmod(self.temp.name, 0o755)
        self.h = Path(self.temp.name) / "home"
        initialize(self.h)
        enable(self.h)
        self.commit("report", 0, "first")
        _chown(self.h, self.owner)

    def tearDown(self):
        if (BASE / "install.json").exists():
            self.local_roles("uninstall")
        self.temp.cleanup()

    def owner_app(self):
        from owner_client import OwnerClient

        return OwnerClient(self.h)

    def commit(self, document, version, content):
        o = self.owner_app()
        try:
            identity = o.propose(document, version, content)["proposal_id"]
            o.approve(identity, o.review(identity)["review_token"])
            return o.commit(identity)
        finally:
            o.close()

    def local_roles(self, command, user=None):
        python = sys.executable
        args = [
            python,
            str(ROOT / "scripts/local_roles.py"),
            command,
            "--home",
            str(self.h),
        ]
        args += ["--base", str(BASE), "--manager", "manual", "--port", str(PORT)]
        args += ["--receiver-account", "optest-rcv", "--witness-account", "optest-wit"]
        r = subprocess.run(args, capture_output=True, text=True, user=user)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return json.loads(r.stdout[r.stdout.index("{") :])

    def test_install_separates_roles_and_uninstall_restores(self):
        from witness_workflow import call, renew

        record = self.local_roles("install")
        self.assertEqual(record["history"]["receiver"]["count"], 1)
        # The owner home keeps no role keys.
        self.assertEqual(list((self.h / "receiver").iterdir()), [])
        self.assertEqual(list((self.h / "witness").iterdir()), [])
        # The normal workflow runs through the role services.
        o = self.owner_app()
        self.assertEqual(o.current_version("report"), 1)
        self.assertEqual(o.current_version("absent"), 0)
        o.close()
        result = self.commit("report", 1, "second")
        self.assertEqual(result["document_version"], 2)
        self.assertEqual(call(["head", self.h / "witness/state"])["count"], 2)
        # A new trust epoch reaches both role services.
        epoch = json.loads((self.h / "trust.json").read_text())["epoch"]
        self.assertEqual(renew(self.h)["installed_epoch"], epoch + 1)
        self.assertEqual(self.commit("report", 2, "third")["document_version"], 3)
        # The owner account cannot read role keys or change role state, and an
        # unapproved request through the service changes nothing.
        probe = Path(self.temp.name) / "probe.py"
        probe.write_text(PROBE)
        r = subprocess.run(
            ["/usr/bin/python3", "-I", str(probe), str(BASE), str(self.h), str(PORT)],
            capture_output=True,
            text=True,
            user=OWNER,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        seen = json.loads(r.stdout)
        self.assertIn(seen.pop("forged_receive"), (400, 409))
        self.assertEqual(
            seen,
            {
                "receiver_key": "denied",
                "receiver_state": "denied",
                "witness_key": "denied",
                "witness_state": "denied",
            },
        )
        self.assertEqual(call(["head", self.h / "receiver/state"])["count"], 3)
        # Uninstall returns the keys and the full history to the owner home.
        self.local_roles("uninstall")
        self.assertFalse((self.h / "service-client.json").exists())
        self.assertEqual(call(["head", self.h / "receiver/state"])["count"], 3)
        self.assertEqual(self.commit("report", 3, "local again")["document_version"], 4)
        self.assertEqual(call(["head", self.h / "witness/state"])["count"], 4)


def _exists(name):
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def _chown(path, account):
    for p in [path, *path.rglob("*")]:
        os.lchown(p, account.pw_uid, account.pw_gid)


if __name__ == "__main__":
    unittest.main()
