"""End-to-end test of separate role accounts (scripts/local_roles.py).

This test creates real operating-system accounts, so it runs only as root on
Linux and only when OPENPROOF_ROLE_ACCOUNT_TEST=1. The role services are the
Rust binary; nothing is downloaded.
"""

import hashlib, json, os, platform, pwd, shutil, subprocess, sys, tempfile, unittest
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
        s.sendall(len(raw).to_bytes(4, "big") + raw)
        response = b""
        while chunk := s.recv(65536):
            response += chunk
    return json.loads(response[4:])["code"] if response else None
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
    out["forged_receive"] = post({"op": "receive", "body": {"request": {"forged": True}}})
except ConnectionError:
    out["forged_receive"] = "closed"
print(json.dumps(out))
"""


# Run as the owner account, or any other: every way to change a protected file.
FILE_PROBE = r"""
import json, os, sys
folder, name, source = sys.argv[1], sys.argv[2], sys.argv[3]
file = os.path.join(folder, name)
out = {"read": open(file).read()}
def attempt(label, action):
    try:
        action()
        out[label] = "done"
    except OSError as e:
        out[label] = type(e).__name__
attempt("write", lambda: open(file, "w").write("forged"))
attempt("append", lambda: open(file, "a").write("forged"))
attempt("delete", lambda: os.unlink(file))
attempt("rename", lambda: os.rename(file, file + ".old"))
attempt("create", lambda: open(os.path.join(folder, "forged"), "x").close())
attempt("replace", lambda: os.replace(source, file))
attempt("link", lambda: os.symlink("/etc/hostname", os.path.join(folder, "other")))
attempt("mode", lambda: os.chmod(file, 0o666))
attempt("folder_mode", lambda: os.chmod(folder, 0o777))
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
        self,
        command,
        user=None,
        script=ROOT / "scripts/local_roles.py",
        ok=True,
        extra=(),
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
        args += list(extra)
        r = subprocess.run(args, capture_output=True, text=True, user=user)
        if not ok:
            self.assertNotEqual(r.returncode, 0, r.stdout)
            return r.stderr
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return json.loads(r.stdout[r.stdout.index("{") :])

    def status(self, user=None, base=BASE, ok=True):
        """The status check, from the root-owned copy that install made."""
        copy = BASE / "libexec/roles_status.py"
        r = subprocess.run(
            ["/usr/bin/python3", "-I", copy, "--home", self.h, "--base", base],
            capture_output=True,
            text=True,
            user=user,
        )
        if not ok:
            self.assertNotEqual(r.returncode, 0, r.stdout)
            return r.stderr
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return json.loads(r.stdout)

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

    def test_protected_files_cannot_be_changed_by_the_owner(self):
        folder = BASE / "published"
        record = self.local_roles("install", extra=["--publish"])
        self.assertEqual(record["publish"], str(folder))
        # The document approved before the install is a file already.
        file = folder / "report"
        self.assertEqual(file.read_text(), "first")
        rcv = pwd.getpwnam("optest-rcv").pw_uid
        self.assertEqual(
            (file.stat().st_uid, file.stat().st_mode & 0o7777), (rcv, 0o644)
        )
        self.assertEqual(
            (folder.stat().st_uid, folder.stat().st_mode & 0o7777), (rcv, 0o755)
        )
        # An approved change through the owner app changes the file.
        self.assertEqual(self.commit("report", 1, "second")["document_version"], 2)
        self.assertEqual(file.read_text(), "second")
        self.commit("Notes", 0, "capital letter")
        probe = Path(self.temp.name) / "file_probe.py"
        probe.write_text(FILE_PROBE)
        # A folder that every account can move files out of, on the same volume.
        drop = BASE / "drop"
        drop.mkdir()
        os.chmod(drop, 0o777)
        for user in [OWNER, "nobody"]:
            source = drop / user
            source.write_text("forged")
            os.chown(source, pwd.getpwnam(user).pw_uid, -1)
            r = subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    str(probe),
                    str(folder),
                    "report",
                    str(source),
                ],
                capture_output=True,
                text=True,
                user=user,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            seen = json.loads(r.stdout)
            self.assertEqual(seen.pop("read"), "second")
            self.assertEqual(set(seen.values()), {"PermissionError"}, (user, seen))
            self.assertEqual(len(seen), 9)
            self.assertEqual(source.read_text(), "forged")
        shutil.rmtree(drop)
        self.assertEqual(file.read_text(), "second")
        self.assertEqual(sorted(os.listdir(folder)), ["report"])
        expected = dict(
            folder=str(folder),
            owner_cannot_change=True,
            receiver_writes_here=True,
            not_published=["Notes"],
        )
        status = self.status(OWNER)
        self.assertEqual(status["protected_files"], expected)
        self.assertTrue(status["separated"])
        self.assertEqual(self.status(), status)
        # A folder that another account can write (here: every account can
        # add files to it) is reported, by the script and by the receiver
        # service, and is repaired when it is safe again.
        os.chmod(folder, 0o1777)
        file.write_text("forged")
        unsafe = self.status(OWNER)["protected_files"]
        self.assertEqual(
            unsafe, dict(expected, owner_cannot_change=False, not_published=None)
        )
        os.chmod(folder, 0o755)
        status = self.status(OWNER)
        self.assertEqual(status["protected_files"], expected)
        self.assertEqual(file.read_text(), "second")
        # So is a folder that does not belong to the receiver's account.
        os.chown(folder, 0, 0)
        unsafe = self.status(OWNER)["protected_files"]
        self.assertEqual(
            unsafe, dict(expected, owner_cannot_change=False, not_published=None)
        )
        os.chown(folder, rcv, -1)
        # A file that belongs to the owner in the folder is reported too.
        planted = folder / "planted"
        planted.write_text("x")
        os.chown(planted, self.owner.pw_uid, self.owner.pw_gid)
        status = self.status()
        self.assertFalse(status["protected_files"]["owner_cannot_change"])
        planted.unlink()
        self.assertIn(
            "option of install",
            self.local_roles("status", ok=False, extra=["--publish"]),
        )
        # An install record of the earlier version: uninstall, then install.
        path = BASE / "install.json"
        old = json.loads(path.read_text())
        path.write_text(json.dumps(dict(old, version="openproof-local-roles/2")))
        self.assertIn("earlier version", self.local_roles("status", ok=False))
        self.local_roles("uninstall")
        self.assertFalse(folder.exists())
        self.assertEqual(self.commit("report", 2, "local")["document_version"], 3)
        # Without the option there is no folder and no report of one.
        record = self.local_roles("install")
        self.assertIsNone(record["publish"])
        self.assertFalse(folder.exists())
        status = self.status()
        self.assertNotIn("protected_files", status)
        self.assertTrue(status["separated"])

    def test_failed_install_with_protected_files_leaves_nothing(self):
        import local_roles

        def stop(path, seconds=20):
            raise RuntimeError("stopped for the test")

        users = {"receiver": "optest-rcv", "witness": "optest-wit"}
        # A lock file in the owner home that is a hard link to a file of
        # root: install must not give that file to the owner.
        roots = Path(self.temp.name) / "roots-file"
        roots.write_text("root's")
        (self.h / ".broker.lock").unlink(missing_ok=True)
        os.link(roots, self.h / ".broker.lock")
        saved = local_roles.wait_for_socket
        local_roles.wait_for_socket = stop
        try:
            with self.assertRaisesRegex(RuntimeError, "stopped for the test"):
                local_roles.install(self.h, BASE, users, "manual", True)
        finally:
            local_roles.wait_for_socket = saved
        # Only root-only backups stay in the role location.
        left = [p.name for p in BASE.iterdir() if "-backup-" not in p.name]
        self.assertEqual(left, [])
        self.assertFalse(_exists("optest-rcv") or _exists("optest-wit"))
        self.assertEqual((roots.stat().st_uid, roots.read_text()), (0, "root's"))
        (self.h / ".broker.lock").unlink()
        # The owner home works as before, and a later install succeeds.
        self.assertEqual(self.commit("report", 1, "after")["document_version"], 2)
        _chown(self.h, self.owner)
        self.local_roles("install", extra=["--publish"])
        self.assertEqual((BASE / "published/report").read_text(), "after")

    def test_service_definitions_are_compared_in_full(self):
        """The launchd and systemd definitions, with files in a test folder."""
        import plistlib
        import roles_status as rs

        folder = Path("/var/lib/openproof-roletest-definitions")
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir()
        saved = rs.LAUNCHD, rs.SYSTEMD
        rs.LAUNCHD = rs.SYSTEMD = folder
        record = dict(
            base="/var/lib/openproof-roletest",
            users={"receiver": "optest-rcv", "witness": "optest-wit"},
            sockets={"receiver": "/r.sock", "witness": "/w.sock"},
            publish="/var/lib/openproof-roletest/published",
        )
        check = lambda manager: rs.service_as_installed(
            dict(record, manager=manager), "receiver", 1234
        )
        # Role accounts: two accounts without a shell, not root, not the owner.
        accounts = lambda receiver, witness, owner_uid=12345: rs.role_accounts(
            dict(users={"receiver": receiver, "witness": witness}), owner_uid
        )
        daemon, nobody = pwd.getpwnam("daemon").pw_uid, pwd.getpwnam("nobody").pw_uid
        self.assertEqual(accounts("daemon", "nobody"), [daemon, nobody])
        self.assertNotIn(self.owner.pw_shell, rs.NO_LOGIN)
        for refused in [
            ("daemon", "daemon"),
            ("root", "nobody"),
            ("daemon", "nobody", nobody),
            ("daemon", OWNER),
        ]:
            self.assertIsNone(accounts(*refused), refused)
        # A second account name with the user ID of a role account.
        listed = pwd.getpwall
        alias = pwd.struct_passwd(("alias", "x", daemon, 1, "", "/", "/bin/sh"))
        pwd.getpwall = lambda: listed() + [alias]
        try:
            self.assertIsNone(accounts("daemon", "nobody"))
        finally:
            pwd.getpwall = listed
        self.assertEqual(accounts("daemon", "nobody"), [daemon, nobody])
        try:
            path, wanted = rs.definition(
                dict(record, manager="launchd"), "receiver", 1234
            )
            self.assertFalse(check("launchd"))  # No file.
            write = lambda value: path.write_bytes(plistlib.dumps(value))
            write(wanted)
            self.assertTrue(check("launchd"))
            self.assertIn("--publish", wanted["ProgramArguments"])
            self.assertEqual(
                wanted["ProgramArguments"][-7:-3],
                ["--client-uid", "1234", "--client-uid", "0"],
            )
            arguments = wanted["ProgramArguments"]
            for changed in [
                dict(wanted, Program="/tmp/other"),
                dict(wanted, EnvironmentVariables={"DYLD_INSERT_LIBRARIES": "/tmp/x"}),
                dict(wanted, UserName="root"),
                dict(wanted, ProgramArguments=arguments + ["--client-uid", "99"]),
                dict(wanted, ProgramArguments=["/tmp/other"] + arguments[1:]),
                {k: v for k, v in wanted.items() if k != "Umask"},
            ]:
                write(changed)
                self.assertFalse(check("launchd"), changed)
            write(wanted)
            os.chown(path, self.owner.pw_uid, -1)
            self.assertFalse(check("launchd"))
            os.chown(path, 0, -1)
            os.chmod(path, 0o666)
            self.assertFalse(check("launchd"))
            path.unlink()
            real = folder / "real.plist"
            real.write_bytes(plistlib.dumps(wanted))
            path.symlink_to(real)
            self.assertFalse(check("launchd"))
            path.unlink()
            path, text = rs.definition(
                dict(record, manager="systemd"), "receiver", 1234
            )
            path.write_text(text)
            self.assertTrue(check("systemd"))
            for changed in [
                text + "User=root\n",
                text.replace("[Service]\n", "[Service]\nExecStartPre=/tmp/x\n"),
                text.replace("NoNewPrivileges=yes\n", ""),
                text.replace("--client-uid 0", "--client-uid 0 --client-uid 99"),
            ]:
                self.assertNotEqual(changed, text)
                path.write_text(changed)
                self.assertFalse(check("systemd"), changed)
            path.write_text(text)
            drop_in = folder / (path.name + ".d")
            drop_in.mkdir()
            self.assertFalse(check("systemd"))
            drop_in.rmdir()
            self.assertTrue(check("systemd"))
        finally:
            rs.LAUNCHD, rs.SYSTEMD = saved
            shutil.rmtree(folder)

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
        # The status check runs from the root-owned copy that install made.
        status = self.status(OWNER)
        self.assertTrue(status["separated"], status)
        self.assertTrue(status["code_protected"])
        self.assertTrue(status["role_keys_out_of_owner_reach"])
        binary = (ROOT / "target/debug/openproof-role").read_bytes()
        self.assertEqual(status["code_sha256"], hashlib.sha256(binary).hexdigest())
        for role in status["roles"].values():
            self.assertTrue(
                role["socket_folder_protected"] and role["service_as_installed"]
            )
        # Root gets the same answer. The services do not answer a third
        # account, so that account cannot confirm the separation.
        self.assertEqual(self.status(), status)
        other = self.status("nobody")
        self.assertFalse(other["separated"])
        self.assertIn("not reachable", other["roles"]["receiver"]["service"])
        # This home has no owner passkey: the receiver says so itself.
        self.assertFalse(status["passkey_required_by_receiver"], status)
        # The check does not rely on the installer: each of these states,
        # which a defective install could leave, makes a value false.
        code = BASE / "libexec"
        rcv, wit = pwd.getpwnam("optest-rcv"), pwd.getpwnam("optest-wit")

        def changed(apply, undo):
            apply()
            try:
                return self.status(OWNER)
            finally:
                undo()

        def separated(apply, undo, value):
            report = changed(apply, undo)
            self.assertFalse(report["separated"], value)
            return report

        # Role code, or the install record, that is not root's alone: a
        # folder that every account can add to, a file of the owner, a link,
        # a role location that belongs to the owner.
        r = separated(lambda: os.chmod(code, 0o1777), lambda: os.chmod(code, 0o755), 1)
        self.assertFalse(r["code_protected"])
        binary = code / "openproof-role"
        aside = Path(self.temp.name) / "openproof-role"
        r = separated(
            lambda: (binary.rename(aside), binary.symlink_to(aside)),
            lambda: (binary.unlink(), aside.rename(binary)),
            1,
        )
        self.assertFalse(r["code_protected"])
        # The record must be the record of the role location that was asked
        # for: a copy in another place is refused.
        other = Path("/var/lib/openproof-roletest-copy")
        other.mkdir()
        try:
            shutil.copy(BASE / "install.json", other)
            error = self.status(OWNER, base=other, ok=False)
            self.assertIn("is not the record of " + str(other), error)
        finally:
            shutil.rmtree(other)
        # Role accounts that are not two separate accounts without a shell.
        r = separated(
            lambda: subprocess.run(
                ["usermod", "-s", "/bin/sh", "optest-rcv"], check=True
            ),
            lambda: subprocess.run(
                ["usermod", "-s", "/usr/sbin/nologin", "optest-rcv"], check=True
            ),
            1,
        )
        self.assertFalse(r["accounts_separate"])
        self.assertIn("not reachable", r["roles"]["receiver"]["service"])
        # A process of the owner that listens on the receiver's socket path,
        # after the folder was open for a moment and root then gave the
        # socket to the role account. All metadata is as an install leaves
        # it; the system reports who listens, so its answers are not used.
        aside = SOCKET.with_name("real.sock")
        listen = (
            "import socket, sys, time\n"
            "s = socket.socket(socket.AF_UNIX)\n"
            "s.bind(sys.argv[1])\ns.listen(8)\nprint('ready', flush=True)\n"
            "time.sleep(60)\n"
        )
        impostors = []

        def impostor():
            SOCKET.rename(aside)
            os.chmod(SOCKET.parent, 0o777)
            p = subprocess.Popen(
                ["/usr/bin/python3", "-I", "-c", listen, SOCKET],
                user=OWNER,
                stdout=subprocess.PIPE,
            )
            impostors.append(p)
            self.assertEqual(p.stdout.readline(), b"ready\n")
            os.chmod(SOCKET.parent, 0o755)
            os.chown(SOCKET, rcv.pw_uid, rcv.pw_gid)
            os.chmod(SOCKET, 0o666)

        def real_again():
            for p in impostors:
                p.kill()
                p.wait()
                p.stdout.close()
            SOCKET.unlink()
            aside.rename(SOCKET)

        r = separated(impostor, real_again, 1)
        self.assertIn(
            "not answered by the role account", r["roles"]["receiver"]["service"]
        )
        self.assertTrue(r["roles"]["receiver"]["socket_folder_protected"])
        self.assertFalse(r["passkey_required_by_receiver"])
        # A status check, a folder above the sockets, or an owner home that
        # is not as an install leaves it.
        copy = code / "roles_status.py"
        r = separated(
            lambda: os.chown(copy, self.owner.pw_uid, -1),
            lambda: os.chown(copy, 0, -1),
            1,
        )
        self.assertFalse(r["code_protected"])
        above = SOCKET.parent.parent
        r = separated(
            lambda: os.chown(above, self.owner.pw_uid, -1),
            lambda: os.chown(above, 0, -1),
            4,
        )
        self.assertFalse(r["roles"]["receiver"]["socket_folder_protected"])
        self.assertTrue(r["code_protected"])
        separated(
            lambda: os.chown(self.h, 0, -1),
            lambda: os.chown(self.h, self.owner.pw_uid, -1),
            1,
        )
        r = separated(
            lambda: os.chown(binary, self.owner.pw_uid, -1),
            lambda: os.chown(binary, 0, -1),
            2,
        )
        self.assertFalse(r["code_protected"])
        # An install record that is not root's is not believed at all.
        record = BASE / "install.json"
        for path in [record, BASE]:
            os.chown(path, self.owner.pw_uid, -1)
            try:
                error = self.status(OWNER, ok=False)
            finally:
                os.chown(path, 0, -1)
            self.assertIn("install.json is not a file of root", error)
        relative = self.status(OWNER, base=str(BASE)[1:], ok=False)
        self.assertIn("full path", relative)
        # A socket folder that another account can write, or that does not
        # belong to the role account: another process could answer there.
        folder = SOCKET.parent
        for apply, undo in [
            (lambda: os.chmod(folder, 0o1777), lambda: os.chmod(folder, 0o755)),
            (lambda: os.chown(folder, 0, -1), lambda: os.chown(folder, rcv.pw_uid, -1)),
        ]:
            r = separated(apply, undo, 4)
            self.assertFalse(r["roles"]["receiver"]["socket_folder_protected"])
            self.assertTrue(r["roles"]["witness"]["socket_folder_protected"])
        # A service that does not run the installed command, or not under
        # its own account, or whose record the owner can change.
        pids = {role: BASE / (role + ".pid") for role in ["receiver", "witness"]}
        saved = pids["receiver"].read_text()
        raw = Path("/proc", saved, "cmdline").read_bytes().split(b"\0")[:-1]
        installed = [a.decode() for a in raw]
        fake = Path(self.temp.name) / "fake"
        fake.mkdir()
        (fake / "serve").write_text("import time\ntime.sleep(60)\n")
        started = []

        def run_instead(args, user, **more):
            started.append(subprocess.Popen(args, user=user, **more))
            pids["receiver"].write_text(str(started[-1].pid))

        for apply in [
            lambda: pids["receiver"].write_text(pids["witness"].read_text()),
            lambda: pids["receiver"].write_text(str(os.getpid())),
            # Another command under the receiver's account.
            lambda: run_instead(["/bin/sleep", "60"], rcv.pw_uid),
            # The installed command line, under another account.
            lambda: run_instead(installed, 0, executable=sys.executable, cwd=fake),
            lambda: os.chown(pids["receiver"], self.owner.pw_uid, -1),
        ]:
            r = separated(
                apply,
                lambda: (
                    pids["receiver"].write_text(saved),
                    os.chown(pids["receiver"], 0, -1),
                ),
                5,
            )
            self.assertFalse(r["roles"]["receiver"]["service_as_installed"])
            self.assertTrue(r["roles"]["witness"]["service_as_installed"])
        for process in started:
            process.kill()
            process.wait()
        # A role folder that other accounts can enter.
        role_dir = BASE / "receiver"
        r = separated(
            lambda: os.chmod(role_dir, 0o755), lambda: os.chmod(role_dir, 0o700), 6
        )
        self.assertFalse(r["roles"]["receiver"]["folder_private"])
        # A closed role folder that does not belong to the role account.
        r = separated(
            lambda: os.chown(role_dir, 0, -1),
            lambda: os.chown(role_dir, rcv.pw_uid, -1),
            6,
        )
        self.assertFalse(r["roles"]["receiver"]["folder_private"])
        # A role file where the owner can read it. G1 does not depend on
        # this, so `separated` stays true.
        leak = BASE / "leak"
        left = self.h / "receiver/key.secret"
        for path in [leak, left]:
            r = changed(
                lambda: (path.write_text("x"), os.chmod(path, 0o644)),
                path.unlink,
            )
            self.assertFalse(r["role_keys_out_of_owner_reach"], path)
            self.assertTrue(r["separated"])
        self.assertEqual(self.status(OWNER), status)
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
