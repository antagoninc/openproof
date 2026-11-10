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
SOCKET = BASE / "sockets/receiver/service.sock"
# Run as the owner account: attempts that separate accounts must refuse.
PROBE = r"""
import json, socket, sqlite3, sys
base, home, path = sys.argv[1], sys.argv[2], sys.argv[3]
def post(value):
    raw = json.dumps(value).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(path)
        s.sendall(b"POST /v1/receive HTTP/1.1\r\nContent-Type: application/json\r\n"
                  + b"Content-Length: %d\r\n\r\n" % len(raw) + raw)
        response = b""
        while chunk := s.recv(65536):
            response += chunk
    return int(response.split(b" ")[1]) if response else None
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
# Any other account gets no answer at all.
try:
    out["forged_receive"] = post({"request": {"forged": True}})
except ConnectionError:
    out["forged_receive"] = "closed"
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

    def local_roles(
        self, command, user=None, script=ROOT / "scripts/local_roles.py", ok=True
    ):
        # The system Python, isolated: the script needs only the standard library.
        args = [
            "/usr/bin/python3",
            "-I",
            str(script),
            command,
            "--home",
            str(self.h),
        ]
        args += ["--base", str(BASE), "--manager", "manual"]
        args += ["--receiver-account", "optest-rcv", "--witness-account", "optest-wit"]
        r = subprocess.run(args, capture_output=True, text=True, user=user)
        if not ok:
            self.assertNotEqual(r.returncode, 0, r.stdout)
            return r.stderr
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return json.loads(r.stdout[r.stdout.index("{") :])

    def test_install_follows_no_link_in_the_owner_home(self):
        """Root must not read a file that the owner home only links to."""
        secret = Path(self.temp.name) / "root-only.secret"
        secret.write_text("not the owner's")
        secret.chmod(0o600)
        elsewhere = Path(self.temp.name) / "elsewhere"
        for planted in ["receiver/key.secret", "trust.json", "witness/state"]:
            target = self.h / planted
            # Move the real entry aside and leave a link in its place.
            target.rename(elsewhere)
            target.symlink_to(elsewhere if planted.endswith("state") else secret)
            os.lchown(target, self.owner.pw_uid, self.owner.pw_gid)
            error = self.local_roles("install", ok=False)
            self.assertIn("is a link, not a regular file", error)
            self.assertFalse((BASE / "install.json").exists())
            self.assertFalse((BASE / "staging").exists())
            self.assertFalse(_exists("optest-rcv"))
            target.unlink()
            elsewhere.rename(target)
        # The lock file the failed installs created belongs to the owner.
        self.assertEqual((self.h / ".broker.lock").stat().st_uid, self.owner.pw_uid)

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

        def run_probe(user):
            r = subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    str(probe),
                    str(BASE),
                    str(self.h),
                    str(SOCKET),
                ],
                capture_output=True,
                text=True,
                user=user,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            return json.loads(r.stdout)

        seen = run_probe(OWNER)
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
        self.assertIn(run_probe("nobody")["forged_receive"], (None, "closed"))
        self.assertEqual(call(["head", self.h / "receiver/state"])["count"], 3)
        # Status runs from the root-owned copy that install made.
        copy = BASE / "libexec/local_roles.py"
        self.assertEqual((copy.stat().st_uid, copy.stat().st_mode & 0o777), (0, 0o644))
        status = self.local_roles("status", user=OWNER, script=copy)
        self.assertTrue(status["separated"], status)
        # The administrator gets the same answer.
        self.assertEqual(self.local_roles("status", script=copy), status)
        # This home has no owner passkey: the receiver says so itself.
        self.assertFalse(status["passkey_required_by_receiver"], status)
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
