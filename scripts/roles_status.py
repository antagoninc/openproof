#!/usr/bin/env python3
"""Check that the receiver and the witness run under their own accounts.

    /usr/bin/python3 -I BASE/libexec/roles_status.py --home HOME

This is the check of the condition for G1 (docs/TCB.md). It uses the Python
standard library only. `scripts/local_roles.py install` puts a root-owned copy
of this file in BASE/libexec. Run that copy, as your own account or, with
sudo, as the administrator.

This script does not rely on the installer. It believes only what root owns:
the install record, the role code and the service definitions must be files
of root that no other account can write, under folders of root. What it
cannot see is in docs/TCB.md ("Why the installer is not trusted").
"""

import argparse, hashlib, json, os, platform, plistlib, pwd, socket, stat
import struct, sys, time
from pathlib import Path

ROLES = ("receiver", "witness")
VERSION = "openproof-local-roles/4"
MAC = platform.system() == "Darwin"
BASE = Path("/private/var/db/openproof" if MAC else "/var/lib/openproof")
# Where the service managers read their definitions.
LAUNCHD = Path("/Library/LaunchDaemons")
SYSTEMD = Path("/etc/systemd/system")
NO_LOGIN = ("/usr/bin/false", "/bin/false", "/usr/sbin/nologin", "/sbin/nologin")


def root_only(path, kind=stat.S_ISREG):
    """True when `path` is a regular file (or what `kind` tests) and not a
    link, and it and every folder above it belong to root and no other
    account can write them. Access control lists are not read."""
    try:
        path = Path(path)
        if not kind(os.lstat(path).st_mode):
            return False
        for p in [path, *path.parents]:
            s = os.lstat(p)
            if s.st_uid != 0 or s.st_mode & 0o022:
                return False
            if p != path and not stat.S_ISDIR(s.st_mode):
                return False
        return True
    except OSError:
        return False


def account_folder(folder, uid, tree=False):
    """True when the folder belongs to the account `uid`, no other account
    can write it or (with `tree`) an entry in it, and the folders above it
    are root's."""
    try:
        folder = Path(folder)
        if not stat.S_ISDIR(os.lstat(folder).st_mode):
            return False
        for p in [folder, *(folder.rglob("*") if tree else [])]:
            try:
                s = os.lstat(p)
            except FileNotFoundError:
                continue  # A file that was replaced during the check.
            if s.st_uid != uid or s.st_mode & 0o022:
                return False
        return root_only(folder.parent, stat.S_ISDIR)
    except OSError:
        return False


def label(role):
    return "com.antagon.openproof." + role


def socket_path(base, role):
    """Each role's socket is in a folder that only its account can change."""
    return base / "sockets" / role / "service.sock"


def service_command(code, role_dir, role, socket_file, owner, publish=None):
    return [
        str(code / "openproof-role"),
        "serve",
        "--role",
        role,
        "--state",
        str(role_dir / "state"),
        "--key",
        str(role_dir / "key.secret"),
        "--trust",
        str(role_dir / "trust.json"),
        "--signed-trust",
        str(role_dir / "trust-signed.json"),
        "--socket",
        str(socket_file),
        # The owner's account, and root for install, status checks and recovery.
        "--client-uid",
        str(owner),
        "--client-uid",
        "0",
        "--accept-trust-updates",
        *(["--publish", str(publish)] if publish else []),
    ]


def definition(record, role, owner_uid):
    """The file that starts a role's service, and all that an install puts in
    it. `install` writes exactly this, and the status check compares all of
    it. In manual mode (tests only) there is no such file: the value is the
    command and the account of the process."""
    base, account = Path(record["base"]), record["users"][role]
    role_dir = base / role
    command = service_command(
        base / "libexec",
        role_dir,
        role,
        record["sockets"][role],
        owner_uid,
        record.get("publish") if role == "receiver" else None,
    )
    if record["manager"] == "launchd":
        return LAUNCHD / (label(role) + ".plist"), dict(
            Label=label(role),
            ProgramArguments=command,
            UserName=account,
            GroupName=account,
            WorkingDirectory=str(role_dir),
            RunAtLoad=True,
            KeepAlive=True,
            Umask=0o077,
            EnvironmentVariables={"PATH": "/usr/bin:/bin"},
            StandardOutPath=str(role_dir / "service.log"),
            StandardErrorPath=str(role_dir / "service.log"),
        )
    if record["manager"] == "systemd":
        return SYSTEMD / ("openproof-" + role + ".service"), (
            "[Unit]\nDescription=OpenProof " + role + "\n\n[Service]\n"
            f"User={account}\nGroup={account}\n"
            f"WorkingDirectory={role_dir}\nUMask=0077\nNoNewPrivileges=yes\n"
            "ExecStart=" + " ".join(command) + "\nRestart=always\n\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )
    return base / (role + ".pid"), (command, account)


def service_as_installed(record, role, owner_uid):
    """True when the definition of a role's service is a file of root and
    holds exactly what an install puts in it, and nothing more. The loaded
    job is not read: only root can load another one."""
    path, expected = definition(record, role, owner_uid)
    if not root_only(path):
        return False
    try:
        if record["manager"] == "launchd":
            with open(path, "rb") as f:
                return plistlib.load(f) == expected
        if record["manager"] == "systemd":
            # A drop-in folder can change a unit without a change to its file.
            folders = [
                SYSTEMD,
                Path("/run/systemd/system"),
                SYSTEMD.parent / "system.control",
            ]
            extra = any((d / (path.name + ".d")).exists() for d in folders)
            return not extra and path.read_text() == expected
        process = Path("/proc") / str(int(path.read_text()))
        raw = (process / "cmdline").read_bytes().split(b"\0")[:-1]
        user = pwd.getpwuid(process.stat().st_uid).pw_name
        return ([a.decode() for a in raw], user) == expected
    except (OSError, ValueError, KeyError):
        return False


def record_path(base):
    return base / "install.json"


def peer_uid(s):
    """The account of the process that listens at the other end of a
    connected Unix socket, as the system reports it."""
    if MAC:  # LOCAL_PEERCRED: struct xucred starts with a version and a user ID.
        version, uid = struct.unpack_from("=II", s.getsockopt(0, 1, 76))
        if version != 0:
            raise RuntimeError("peer credentials have an unknown form")
        return uid
    return struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[
        1
    ]


def ask(sock, op, uid=None):
    """One request to a role service on its Unix socket: a 4-byte length and
    a JSON message each way. With `uid`, nothing is sent and no answer is
    used unless the process that listens there runs under that account."""
    raw = json.dumps({"op": op, "body": {}}).encode()
    end = time.monotonic() + 20
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(20)
        s.connect(str(sock))
        if uid is not None and peer_uid(s) != uid:
            raise RuntimeError(f"{sock} is not answered by the role account")
        s.sendall(len(raw).to_bytes(4, "big") + raw)
        response = b""
        while chunk := s.recv(65536):
            response += chunk
            if len(response) > 1_200_000 or time.monotonic() > end:
                raise RuntimeError("role service answer too large or too slow")
    if len(response) < 4 or int.from_bytes(response[:4], "big") != len(response) - 4:
        raise RuntimeError(f"role service {sock}: no complete answer")
    answer = json.loads(response[4:])
    if answer.get("code") != 200:
        raise RuntimeError(f"role service {sock}: {str(answer)[:200]}")
    return answer["body"]


def load_record(base, home, versions=(VERSION,)):
    path = record_path(base)
    if not path.exists():
        raise RuntimeError("Local roles are not installed.")
    record = json.loads(path.read_text())
    if record.get("version") not in versions:
        raise RuntimeError(
            "Local roles were installed by an earlier version. Run uninstall, then install."
        )
    if Path(record["home"]) != home.resolve():
        raise RuntimeError(
            f"Local roles are installed for another home: {record.get('home')}"
        )
    return record


def role_accounts(record, owner_uid):
    """The user IDs of the role accounts. `None` unless they are two accounts
    without a login shell that are not root and not the owner, and no other
    account name has one of their user IDs. If an account has a password
    cannot be read here."""
    entries = [pwd.getpwnam(record["users"][role]) for role in ROLES]
    uids = [e.pw_uid for e in entries]
    names = {e.pw_name for e in pwd.getpwall() if e.pw_uid in uids}
    separate = len({0, owner_uid, *uids}) == 4 and len(names) == 2
    return uids if separate and all(e.pw_shell in NO_LOGIN for e in entries) else None


def keys_out_of_reach(record, owner):
    """Whether role keys or state are where the owner account can read them:
    in the role location (every entry there but the public ones must be
    closed to other accounts) or in the owner home's role folders. G1 does
    not depend on this value; a role key signs receipts and checkpoints."""
    base, public = Path(record["base"]), ("libexec", "sockets", "published")
    for name in os.listdir(base):
        if name in public or name == "install.json" or name.endswith(".pid"):
            continue
        s = os.lstat(base / name)
        if s.st_uid == owner.pw_uid or s.st_mode & 0o077:
            return False
    try:
        return not any(os.listdir(Path(record["home"]) / role) for role in ROLES)
    except FileNotFoundError:
        return True


def status(home, base):
    """The report. `separated` is the condition for G1 that this script can
    check: the install record and the role code are root's; each role
    service is defined as an install defines it, under its own account; the
    socket that answers was made by that account, in that account's folder;
    and each role folder is closed to other accounts."""
    if not base.is_absolute() or not root_only(record_path(base)):
        raise RuntimeError(
            f"{record_path(base)} is not a file of root under folders of root "
            "(give the role location as a full path)."
        )
    record = load_record(base, home)
    if record.get("base") != str(base):
        raise RuntimeError(f"The install record is not the record of {base}.")
    owner = pwd.getpwnam(record["owner"])
    code = base / "libexec"
    report = dict(installed_for=record["home"], manager=record["manager"], roles={})
    try:
        uids = role_accounts(record, owner.pw_uid)
    except KeyError:
        uids = None
    report["accounts_separate"] = uids is not None
    for role, uid in zip(ROLES, uids or (None, None)):
        account, sock = record["users"][role], record["sockets"][role]
        entry = dict(account=account, socket=sock)
        try:
            # Without a role account to compare with, nothing is asked.
            entry["history_count"] = ask(sock, "head", -1 if uid is None else uid)[
                "count"
            ]
            entry["service"] = "running"
        except Exception as e:
            entry["service"] = "not reachable: " + str(e)[:200]
        try:
            s = os.lstat(base / role)
            entry["folder_owner"] = pwd.getpwuid(s.st_uid).pw_name
            # A folder only its account can enter keeps the state from the owner.
            entry["folder_private"] = (
                stat.S_ISDIR(s.st_mode)
                and not s.st_mode & 0o077
                and s.st_uid == uid
                and root_only(base, stat.S_ISDIR)
            )
        except (KeyError, OSError):
            entry["folder_owner"], entry["folder_private"] = "unknown", False
        # The socket itself is open to every account; the service admits by
        # the peer's account. Its folder decides who can put a socket there,
        # and `ask` checks the account of the process that listens.
        entry["socket_folder_protected"] = account_folder(Path(sock).parent, uid)
        entry["service_as_installed"] = service_as_installed(record, role, owner.pw_uid)
        report["roles"][role] = entry
    files = [code / "openproof-role", code / "roles_status.py"]
    report["code_protected"] = all(root_only(f) for f in files)
    if report["code_protected"]:
        # Compare this with the SHA-256 of a role binary from a build that you trust.
        binary = (code / "openproof-role").read_bytes()
        report["code_sha256"] = hashlib.sha256(binary).hexdigest()
    try:
        home_is_owners = os.stat(record["home"]).st_uid == owner.pw_uid
    except OSError:
        home_is_owners = False
    # Without separate role accounts, no service counts as running (above).
    report["separated"] = (
        report["code_protected"]
        and home_is_owners
        and all(
            r["service"] == "running"
            and r["folder_private"]
            and r["socket_folder_protected"]
            and r["service_as_installed"]
            for r in report["roles"].values()
        )
    )
    try:
        report["role_keys_out_of_owner_reach"] = keys_out_of_reach(record, owner)
    except OSError:
        report["role_keys_out_of_owner_reach"] = False
    # The receiver service reports the trust it admits under. With an owner
    # passkey in it, every new change needs an assertion from that passkey.
    try:
        answer = ask(record["sockets"]["receiver"], "status", uids[0] if uids else -1)
    except Exception:
        answer = {}
    passkey = answer.get("owner_passkey")
    report["passkey_required_by_receiver"] = passkey is not None
    if passkey is not None:
        report["receiver_passkey_origin"] = passkey["origin"]
    if record.get("publish"):
        # Protected files (docs/PROTECTED-FILES.md). `not_published` names the
        # documents whose files do not have the current content; `null` means
        # that the service did not accept the folder.
        published = answer.get("published") or {}
        report["protected_files"] = dict(
            folder=record["publish"],
            owner_cannot_change=account_folder(
                record["publish"], uids[0] if uids else -1, tree=True
            ),
            receiver_writes_here=published.get("folder") == record["publish"],
            not_published=published.get("not_published"),
        )
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home", required=True, type=Path)
    p.add_argument("--base", type=Path, default=BASE)
    a = p.parse_args()
    try:
        print(json.dumps(status(a.home, a.base), indent=2))
    except Exception as e:
        print("openproof roles status: " + str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
