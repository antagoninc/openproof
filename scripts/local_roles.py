#!/usr/bin/env python3
"""Run the receiver and the witness under their own operating-system accounts.

Without this, one account runs the owner app, the receiver and the witness. A
process that runs as the owner can then change the receiver's state directly
or sign a false history with the witness key. After `install`:

- the receiver and the witness each run as a separate service account;
- their keys and state are readable only by that account;
- the owner app reaches them only through the role service on a Unix socket
  that admits the owner's account (and root) by its kernel-checked user ID, so
  every change still passes the receiver's approval checks;
- the services run one root-owned copy of the role binary (`openproof-role`),
  which the owner cannot change and which holds only the receiver and witness
  code; no interpreter or downloaded package is involved.

The owner keeps the approval gate, the authority key and the root key. An
owner passkey is still needed to make approvals that the owner account alone
cannot produce. The witness is still on the same computer, so G2 still needs
an independent witness operator.

Commands (the Python standard library only; use the system Python):
  sudo /usr/bin/python3 -I scripts/local_roles.py install --home HOME
  /usr/bin/python3 -I BASE/libexec/local_roles.py status --home HOME
  sudo /usr/bin/python3 -I scripts/local_roles.py uninstall --home HOME

Run `install` only from a checkout you have just pulled and checked: it copies
the role code and this script from the checkout into a root-owned location.
Run `status` from that copy: the owner account cannot change it.
"""

import argparse, contextlib, errno, fcntl, json, os, platform, plistlib
import pwd, shutil, signal, socket, sqlite3, stat, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROLES = ("receiver", "witness")
VERSION = "openproof-local-roles/2"
# Records this script can still uninstall: version 1 used loopback mTLS.
UNINSTALLABLE = {"openproof-local-roles/1", VERSION}
# The only code the role services run: one root-owned copy of this binary.
BINARY = "target/debug/openproof-role"
MAC = platform.system() == "Darwin"


def defaults():
    if MAC:
        return dict(
            base=Path("/private/var/db/openproof"),
            users={"receiver": "_openproofrcv", "witness": "_openproofwit"},
            manager="launchd",
        )
    return dict(
        base=Path("/var/lib/openproof"),
        users={"receiver": "openproof-receiver", "witness": "openproof-witness"},
        manager=(
            "systemd"
            if shutil.which("systemctl") and Path("/run/systemd/system").exists()
            else "manual"
        ),
    )


def run(*args, check=True, **kw):
    r = subprocess.run([str(a) for a in args], capture_output=True, text=True, **kw)
    if check and r.returncode:
        raise RuntimeError(f"{args[0]} failed: {(r.stderr or r.stdout).strip()[:500]}")
    return r


def say(text):
    print(text, flush=True)


# ---------------------------------------------------------------- accounts


def account_exists(name):
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def create_account(name, description):
    if account_exists(name):
        raise RuntimeError(f"Account {name} already exists. Run uninstall first.")
    if MAC:
        used = set()
        for kind, field in [("/Users", "UniqueID"), ("/Groups", "PrimaryGroupID")]:
            for line in run("dscl", ".", "-list", kind, field).stdout.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1].lstrip("-").isdigit():
                    used.add(int(parts[1]))
        free = next((i for i in range(450, 500) if i not in used), None)
        if free is None:
            raise RuntimeError("No free service account ID in 450-499")
        group = "/Groups/" + name
        user = "/Users/" + name
        for args in [
            (group,),
            (group, "PrimaryGroupID", free),
            (group, "RealName", description),
            (group, "Password", "*"),
            (user,),
            (user, "UniqueID", free),
            (user, "PrimaryGroupID", free),
            (user, "UserShell", "/usr/bin/false"),
            (user, "NFSHomeDirectory", "/var/empty"),
            (user, "RealName", description),
            (user, "Password", "*"),
            (user, "IsHidden", "1"),
        ]:
            run("dscl", ".", "-create", *args)
    else:
        run(
            "useradd",
            "--system",
            "--user-group",
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/sbin/nologin",
            "--comment",
            description,
            name,
        )
    for _ in range(50):  # The directory service can take a moment.
        try:
            return pwd.getpwnam(name)
        except KeyError:
            time.sleep(0.1)
    raise RuntimeError(f"Account {name} was created but cannot be read back.")


def delete_account(name):
    if not account_exists(name):
        return
    if MAC:
        run("dscl", ".", "-delete", "/Users/" + name)
        run("dscl", ".", "-delete", "/Groups/" + name, check=False)
    else:
        run("userdel", name)


# ---------------------------------------------------------------- checks


def owner_groups(uid):
    entry = pwd.getpwuid(uid)
    return set(os.getgrouplist(entry.pw_name, entry.pw_gid))


def writable_by(path, uid, gids):
    """True when the account can change this file or directory entry."""
    s = os.lstat(path)
    if stat.S_ISLNK(s.st_mode):
        return False  # The link target is checked separately.
    if s.st_uid == uid:
        return True  # An owner can always change the mode back.
    if s.st_gid in gids and s.st_mode & stat.S_IWGRP:
        return True
    return bool(s.st_mode & stat.S_IWOTH) and not (
        stat.S_ISDIR(s.st_mode) and s.st_mode & stat.S_ISVTX
    )


def refuse_writable(paths, uid, why):
    gids = owner_groups(uid)
    seen = set()
    for top in paths:
        top = Path(os.path.realpath(top))
        chain = [top, *top.parents]
        tree = list(top.rglob("*")) if top.is_dir() else []
        for p in chain + tree:
            real = Path(os.path.realpath(p))
            for q in {p, real}:
                if q in seen:
                    continue
                seen.add(q)
                if writable_by(q, uid, gids):
                    raise RuntimeError(
                        f"{q} can be changed by the owner account. {why} "
                        "Choose a location owned by root and not writable by the owner."
                    )


# ---------------------------------------------------------------- files


# Root never follows a link in the owner's home: every file there is opened
# relative to a directory opened with O_NOFOLLOW, and must be a regular file.
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def no_link(open_call, name):
    try:
        return open_call()
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            raise RuntimeError(
                f"{name} in the owner home is a link, not a regular file or folder"
            ) from None
        raise


def open_dir(name, dir_fd=None):
    return no_link(lambda: os.open(name, DIRECTORY, dir_fd=dir_fd), name)


def read_regular(name, dir_fd):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = no_link(lambda: os.open(name, flags, dir_fd=dir_fd), name)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError(f"{name} in the owner home is not a regular file")
        chunks = []
        while chunk := os.read(fd, 1 << 20):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_private(name, data, uid, gid, dir_fd, mode=0o600):
    """Create a new file relative to `dir_fd`; never through a link."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(name, flags, mode, dir_fd=dir_fd)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
        f.flush()
        os.fsync(f.fileno())
        os.fchown(f.fileno(), uid, gid)


def snapshot_home(home, dest):
    """Copy the owner's role folders and trust files into `dest`, a new
    root-only folder. Only regular files are read, and no link is followed."""
    dest.mkdir(mode=0o700)
    home_fd = open_dir(home)
    try:
        for name in ["trust.json", "trust-signed.json"]:
            (dest / name).write_bytes(read_regular(name, home_fd))
        for role in ROLES:
            role_fd = open_dir(role, home_fd)
            state_fd = None
            try:
                state_fd = open_dir("state", role_fd)
                (dest / role / "state").mkdir(parents=True, mode=0o700)
                for name in sorted(os.listdir(state_fd)):
                    if not name.endswith("-shm"):
                        data = read_regular(name, state_fd)
                        (dest / role / "state" / name).write_bytes(data)
                (dest / role / "key.secret").write_bytes(
                    read_regular("key.secret", role_fd)
                )
            finally:
                if state_fd is not None:
                    os.close(state_fd)
                os.close(role_fd)
    finally:
        os.close(home_fd)
    # Fold any write-ahead log into the copied databases.
    for db in dest.glob("*/state/*.db"):
        c = open_db(db)
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        c.close()
    for p in dest.rglob("*"):
        os.chmod(p, 0o700 if p.is_dir() else 0o600)


def open_db(path):
    """Open a database that only root, or a stopped role service, can change.
    Never read-only: the states use a write-ahead log, and a read-only open
    of such a database can fail when its -wal file is absent (seen as "unable
    to open database file" with the macOS system Python). An error names the
    file."""
    try:
        db = sqlite3.connect(str(path))
        db.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
        return db
    except sqlite3.Error as e:
        raise RuntimeError(f"{path}: {e}") from None


def copy_state(source, target):
    """Copy a role state directory with a consistent SQLite snapshot."""
    target.mkdir(mode=0o700)
    for item in sorted(source.iterdir()):
        if item.name.endswith(("-wal", "-shm")):
            continue
        if item.suffix == ".db":
            src = open_db(item)
            dst = sqlite3.connect(str(target / item.name))
            with dst:
                src.backup(dst)
            src.close()
            dst.close()
        elif item.is_file():
            shutil.copy2(item, target / item.name)
        else:
            raise RuntimeError(f"Unexpected entry in role state: {item}")


def chown_tree(path, uid, gid):
    for p in [path, *path.rglob("*")]:
        os.lchown(p, uid, gid)
        if not p.is_symlink():
            os.chmod(p, 0o700 if p.is_dir() else 0o600)


def install_code(base):
    code = base / "libexec"
    if code.exists():
        shutil.rmtree(code)
    src = ROOT / BINARY
    if not src.is_file():
        raise RuntimeError(
            "Missing " + BINARY + ". Build first with: cargo build --workspace --locked"
        )
    code.mkdir(mode=0o755)
    shutil.copy2(src, code / "openproof-role")
    # A root-owned copy of this script, so `status` can run from code the
    # owner account cannot change (docs/LOCAL-ROLES.md).
    shutil.copy2(Path(__file__).resolve(), code / "local_roles.py")
    for p, mode in [
        (code, 0o755),
        (code / "openproof-role", 0o755),
        (code / "local_roles.py", 0o644),
    ]:
        os.chown(p, 0, 0)
        os.chmod(p, mode)
    return code


# ---------------------------------------------------------------- services


def label(role):
    return "com.antagon.openproof." + role


def socket_path(base, role):
    """Each role's socket is in a folder that only its account can change."""
    return base / "sockets" / role / "service.sock"


def service_command(code, role_dir, role, socket_file, owner):
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
    ]


def start_service(manager, base, role, account, command, role_dir):
    if manager == "launchd":
        plist = Path("/Library/LaunchDaemons") / (label(role) + ".plist")
        data = dict(
            Label=label(role),
            ProgramArguments=command,
            UserName=account.pw_name,
            GroupName=account.pw_name,
            WorkingDirectory=str(role_dir),
            RunAtLoad=True,
            KeepAlive=True,
            Umask=0o077,
            EnvironmentVariables={"PATH": "/usr/bin:/bin"},
            StandardOutPath=str(role_dir / "service.log"),
            StandardErrorPath=str(role_dir / "service.log"),
        )
        with open(plist, "wb") as f:
            plistlib.dump(data, f)
        os.chown(plist, 0, 0)
        os.chmod(plist, 0o644)
        run("launchctl", "bootstrap", "system", plist)
    elif manager == "systemd":
        unit = Path("/etc/systemd/system") / ("openproof-" + role + ".service")
        unit.write_text(
            "[Unit]\nDescription=OpenProof " + role + "\n\n[Service]\n"
            f"User={account.pw_name}\nGroup={account.pw_name}\n"
            f"WorkingDirectory={role_dir}\nUMask=0077\nNoNewPrivileges=yes\n"
            "ExecStart=" + " ".join(command) + "\nRestart=always\n\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "--now", unit.name)
    else:
        log = open(role_dir / "service.log", "ab")
        process = subprocess.Popen(
            command,
            cwd=role_dir,
            user=account.pw_uid,
            group=account.pw_gid,
            extra_groups=[],
            umask=0o077,
            env={"PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
        (base / (role + ".pid")).write_text(str(process.pid))


def stop_service(manager, base, role):
    if manager == "launchd":
        run("launchctl", "bootout", "system/" + label(role), check=False)
        (Path("/Library/LaunchDaemons") / (label(role) + ".plist")).unlink(
            missing_ok=True
        )
    elif manager == "systemd":
        unit = "openproof-" + role + ".service"
        run("systemctl", "disable", "--now", unit, check=False)
        (Path("/etc/systemd/system") / unit).unlink(missing_ok=True)
        run("systemctl", "daemon-reload", check=False)
    else:
        pid_file = base / (role + ".pid")
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text()), signal.SIGTERM)
            except ProcessLookupError:
                pass
            pid_file.unlink()
    time.sleep(0.5)


def wait_for_socket(path, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect(str(path))
            return
        except OSError:
            time.sleep(0.3)
    raise RuntimeError(f"Role service at {path} did not start. Read its service.log.")


# ---------------------------------------------------------------- commands


def record_path(base):
    return base / "install.json"


# This script uses the Python standard library only, and never runs code
# from the checkout or the owner home: it runs as root, and `status` is the
# check that G1's condition holds (docs/TCB.md).


@contextlib.contextmanager
def home_lock(home, owner):
    """The owner home's broker lock, as the owner app and broker take it. A
    lock file this creates belongs to the owner, whatever happens next."""
    fd = os.open(
        Path(home) / ".broker.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        if os.fstat(fd).st_uid == 0:
            os.fchown(fd, owner.pw_uid, owner.pw_gid)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def state_head(state):
    """History length and pinned root of a role state, read directly."""
    db = open_db(Path(state) / "state.db")
    try:
        count = db.execute("SELECT COALESCE(MAX(seq),0) FROM events").fetchone()[0]
        anchored = db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='role_anchor'"
        ).fetchone()
        row = (
            db.execute("SELECT root FROM role_anchor WHERE id=1").fetchone()
            if anchored
            else None
        )
    finally:
        db.close()
    return dict(count=count, root=row[0] if row else None)


def ask(sock, op):
    """One request to a role service on its Unix socket."""
    raw = b"{}"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(20)
        s.connect(str(sock))
        s.sendall(
            b"POST /v1/%s HTTP/1.1\r\nContent-Type: application/json\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n" % (op.encode(), len(raw))
            + raw
        )
        response = b""
        while chunk := s.recv(65536):
            response += chunk
            if len(response) > 1_200_000:
                raise RuntimeError("role service answer too large")
    head, _, body = response.partition(b"\r\n\r\n")
    if not head.startswith(b"HTTP/1.1 200 "):
        raise RuntimeError(f"role service {sock}: {head[:40]!r} {body[:200]!r}")
    return json.loads(body)


def heads(states):
    return {role: state_head(states / role / "state") for role in ROLES}


def service_heads(sockets):
    return {
        role: dict(
            count=ask(sockets[role], "head")["count"],
            root=ask(sockets[role], "status")["root"],
        )
        for role in ROLES
    }


def _move_roles(
    home,
    base,
    code,
    users,
    manager,
    owner,
    owner_entry,
    accounts,
    roles_dir,
    staging,
    before,
    backup,
):
    say("3/7 Create the service accounts")
    for role in ROLES:
        accounts[role] = create_account(users[role], "OpenProof " + role)
    say("4/7 Copy the role keys and state")
    for role in ROLES:
        d = roles_dir[role]
        d.mkdir(mode=0o700)
        copy_state(staging / role / "state", d / "state")
        shutil.copy2(staging / role / "key.secret", d / "key.secret")
        shutil.copy2(staging / "trust.json", d / "trust.json")
        shutil.copy2(staging / "trust-signed.json", d / "trust-signed.json")
    for role in ROLES:
        chown_tree(roles_dir[role], accounts[role].pw_uid, accounts[role].pw_gid)
    sockets = base / "sockets"
    sockets.mkdir(mode=0o755)
    os.chown(sockets, 0, 0)
    for role in ROLES:
        folder = socket_path(base, role).parent
        folder.mkdir(mode=0o755)
        os.chown(folder, accounts[role].pw_uid, accounts[role].pw_gid)
        os.chmod(folder, 0o755)
    say("5/7 Start the role services")
    for role in ROLES:
        command = service_command(
            code, roles_dir[role], role, socket_path(base, role), owner
        )
        start_service(manager, base, role, accounts[role], command, roles_dir[role])
    for role in ROLES:
        wait_for_socket(socket_path(base, role))
    say("6/7 Connect the owner home and compare the history")
    config = dict(
        version="openproof-service-client/2",
        **{role: dict(socket=str(socket_path(base, role))) for role in ROLES},
    )
    home_fd = open_dir(home)
    try:
        write_private(
            "service-client.json",
            json.dumps(config, indent=2),
            owner,
            owner_entry.pw_gid,
            home_fd,
        )
    finally:
        os.close(home_fd)
    after = service_heads({role: socket_path(base, role) for role in ROLES})
    if after != before:
        raise RuntimeError(f"History differs after the move: {before} vs {after}")
    say("7/7 Move the owner's copies of the role keys out of the owner's reach")
    backup.mkdir(mode=0o700)
    home_fd = open_dir(home)
    try:
        for role in ROLES:
            # A rename moves the entry itself, never through a link.
            os.rename(role, backup / role, src_dir_fd=home_fd)
            os.mkdir(role, 0o700, dir_fd=home_fd)
            os.chown(
                role, owner, owner_entry.pw_gid, dir_fd=home_fd, follow_symlinks=False
            )
    finally:
        os.close(home_fd)
    for p in backup.rglob("*"):
        os.lchown(p, 0, 0)
    return after


def return_roles(source, home, owner):
    """Put the role folders prepared in `source` (root-only) into the owner
    home, in place of its empty role folders. Nothing in the owner home is
    followed or written through. All folders are checked before one moves."""
    roles = [role for role in ROLES if (source / role).exists()]
    for role in roles:
        chown_tree(source / role, owner.pw_uid, owner.pw_gid)
    home_fd = open_dir(home)
    try:
        present = []
        for role in roles:
            try:
                fd = open_dir(role, home_fd)
            except FileNotFoundError:
                continue
            try:
                if os.listdir(fd):
                    raise RuntimeError(
                        f"{home / role} is not empty. Move its contents aside first."
                    )
            finally:
                os.close(fd)
            present.append(role)
        for role in roles:
            if role in present:
                os.rmdir(role, dir_fd=home_fd)
            os.rename(source / role, role, dst_dir_fd=home_fd)
    finally:
        os.close(home_fd)


def same_volume(home, base):
    """Role folders move between the home and `base` by rename, which never
    follows a link. That needs both on one volume."""
    if os.stat(home).st_dev != os.stat(base).st_dev:
        raise RuntimeError(
            f"{home} and {base} are on different volumes. Use a home on the "
            "same volume as the role location."
        )


def install(home, base, users, manager):
    if os.geteuid() != 0:
        raise RuntimeError("Run install with sudo.")
    home = home.resolve()
    owner = home.stat().st_uid
    if owner == 0:
        raise RuntimeError(
            "The home belongs to root. Use a home owned by your own account."
        )
    if (home / "service-client.json").exists():
        raise RuntimeError("This home already uses role services.")
    if record_path(base).exists():
        raise RuntimeError(
            f"Local roles are already installed ({record_path(base)}). Run uninstall first."
        )
    for role in ROLES:
        for need in ["state", "key.secret"]:
            if not (home / role / need).exists():
                raise RuntimeError(f"{home / role / need} is missing.")
    owner_entry = pwd.getpwuid(owner)
    with home_lock(home, owner_entry):
        for left in ["sockets", *ROLES]:
            if (base / left).exists():
                raise RuntimeError(
                    f"{base / left} already exists. Run uninstall first or move it aside."
                )
        base.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chown(base, 0, 0)
        os.chmod(base, 0o755)
        refuse_writable(
            [base], owner, "Role keys and code would be in the owner's reach."
        )
        same_volume(home, base)
        # Root works only on a copy of the owner's files made without links.
        staging = base / "staging"
        shutil.rmtree(staging, ignore_errors=True)  # From an interrupted install.
        try:
            snapshot_home(home, staging)
            before = heads(staging)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        if before["receiver"]["count"] != before["witness"]["count"]:
            shutil.rmtree(staging)
            raise RuntimeError(
                "Some receipts are not witnessed yet. Execute or recover the pending "
                "actions in the owner app first."
            )
        say("1/7 Check that the owner cannot change the role location")
        say("2/7 Install a root-owned copy of the openproof-witness binary")
        code = install_code(base)
        refuse_writable(
            [code], owner, "The role services would run code the owner can change."
        )
        accounts = {}
        roles_dir = {role: base / role for role in ROLES}
        backup = base / ("owner-backup-" + time.strftime("%Y%m%dT%H%M%S"))
        try:
            after = _move_roles(
                home,
                base,
                code,
                users,
                manager,
                owner,
                owner_entry,
                accounts,
                roles_dir,
                staging,
                before,
                backup,
            )
        except BaseException:
            say("Install failed. Undo the partial install and restore the owner home.")
            for role in ROLES:
                log = roles_dir[role] / "service.log"
                if log.exists():
                    tail = log.read_text(errors="replace").splitlines()[-5:]
                    say(f"{role} service log: " + " | ".join(tail))
            return_roles(backup, home, owner_entry)
            for role in ROLES:
                stop_service(manager, base, role)
                if role in accounts:  # Only accounts this install created.
                    delete_account(users[role])
                shutil.rmtree(roles_dir[role], ignore_errors=True)
            home_fd = open_dir(home)
            try:
                os.unlink("service-client.json", dir_fd=home_fd)
            except FileNotFoundError:
                pass
            finally:
                os.close(home_fd)
            shutil.rmtree(base / "sockets", ignore_errors=True)
            shutil.rmtree(code, ignore_errors=True)
            shutil.rmtree(staging, ignore_errors=True)
            raise
        shutil.rmtree(staging)
        record = dict(
            version=VERSION,
            home=str(home),
            owner=owner_entry.pw_name,
            platform="macos" if MAC else "linux",
            manager=manager,
            users=users,
            sockets={role: str(socket_path(base, role)) for role in ROLES},
            base=str(base),
            backup=str(backup),
            installed_at=int(time.time()),
            history=after,
        )
        path = record_path(base)
        path.write_text(json.dumps(record, indent=2))
        os.chmod(path, 0o644)
    say("Done. The receiver and the witness now run under their own accounts.")
    say(f"Backup of the owner's old role folders (root only): {backup}")
    return record


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


def status(home, base):
    """Whether the roles are separated and the receiver requires the passkey.
    Run it as the owner or as the administrator; it reads only the install
    record, the role folders' metadata and the services' own answers."""
    record = load_record(base, home)
    owner = pwd.getpwnam(record["owner"])
    report = dict(installed_for=record["home"], roles={})
    for role in ROLES:
        d = Path(record["base"]) / role
        entry = dict(account=record["users"][role], socket=record["sockets"][role])
        try:
            entry["history_count"] = ask(record["sockets"][role], "head")["count"]
            entry["service"] = "running"
        except Exception as e:
            entry["service"] = "not reachable: " + str(e)[:200]
        try:
            s = os.lstat(d)
            entry["folder_owner"] = pwd.getpwuid(s.st_uid).pw_name
            # A folder only its account can enter keeps the key from the owner.
            entry["folder_private"] = stat.S_ISDIR(s.st_mode) and not (
                s.st_mode & 0o077
            )
        except (KeyError, OSError):
            entry["folder_owner"], entry["folder_private"] = "unknown", False
        report["roles"][role] = entry
    report["separated"] = owner.pw_uid != 0 and all(
        r["service"] == "running"
        and r["folder_private"]
        and r["folder_owner"] == r["account"] != owner.pw_name
        for r in report["roles"].values()
    )
    # The receiver service reports the trust it admits under. With an owner
    # passkey in it, every new change needs an assertion from that passkey.
    try:
        passkey = ask(record["sockets"]["receiver"], "status").get("owner_passkey")
    except Exception:
        passkey = None
    report["passkey_required_by_receiver"] = passkey is not None
    if passkey is not None:
        report["receiver_passkey_origin"] = passkey["origin"]
    return report


def uninstall(home, base):
    if os.geteuid() != 0:
        raise RuntimeError("Run uninstall with sudo.")
    home = home.resolve()
    record = load_record(base, home, UNINSTALLABLE)
    owner = pwd.getpwnam(record["owner"])
    same_volume(home, base)
    with home_lock(home, owner):
        # Read the role states directly, not through the services: uninstall
        # must work even when a service does not answer.
        say("1/4 Stop the role services")
        for role in ROLES:
            stop_service(record["manager"], base, role)
        before = heads(base)
        say("2/4 Return the role keys and state to the owner home")
        # Prepare the returned folders where the owner cannot reach, check
        # them, then move them into place. The role folders stay as they are
        # until that has worked, so a failed uninstall can be run again.
        for old in base.glob("restore-*"):  # From an interrupted uninstall.
            shutil.rmtree(old)
        restore = base / ("restore-" + time.strftime("%Y%m%dT%H%M%S"))
        restore.mkdir(mode=0o700)
        try:
            for role in ROLES:
                (restore / role).mkdir(mode=0o700)
                copy_state(base / role / "state", restore / role / "state")
                shutil.copy2(base / role / "key.secret", restore / role / "key.secret")
            after = heads(restore)
            if after != before:
                raise RuntimeError(
                    f"History differs after the return: {before} vs {after}"
                )
            return_roles(restore, home, owner)
        except BaseException:
            shutil.rmtree(restore, ignore_errors=True)
            raise
        restore.rmdir()
        home_fd = open_dir(home)
        try:
            os.unlink("service-client.json", dir_fd=home_fd)
        finally:
            os.close(home_fd)
        # Version 1 installs kept TLS client credentials here.
        shutil.rmtree(home / "service-tls", ignore_errors=True)
        say("3/4 Keep the role folders in a root-only backup")
        backup = base / ("roles-backup-" + time.strftime("%Y%m%dT%H%M%S"))
        backup.mkdir(mode=0o700)
        for role in ROLES:
            shutil.move(str(base / role), str(backup / role))
        for p in backup.rglob("*"):
            os.lchown(p, 0, 0)
        say("4/4 Remove the service accounts and the role code")
        for role in ROLES:
            delete_account(record["users"][role])
        shutil.rmtree(base / "libexec", ignore_errors=True)
        shutil.rmtree(base / "runtime", ignore_errors=True)
        shutil.rmtree(base / "sockets", ignore_errors=True)
        record_path(base).unlink()
    say("Done. The owner home runs the receiver and the witness locally again.")
    return dict(history=after, backup=str(backup))


def main():
    d = defaults()
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("command", choices=["install", "status", "uninstall"])
    p.add_argument("--home", required=True, type=Path)
    p.add_argument(
        "--base",
        type=Path,
        default=d["base"],
        help="Root-owned folder for role code, keys and state",
    )
    p.add_argument(
        "--manager", choices=["launchd", "systemd", "manual"], default=d["manager"]
    )
    p.add_argument("--receiver-account", default=d["users"]["receiver"])
    p.add_argument("--witness-account", default=d["users"]["witness"])
    a = p.parse_args()
    users = {"receiver": a.receiver_account, "witness": a.witness_account}
    try:
        if a.command == "install":
            result = install(a.home, a.base, users, a.manager)
        elif a.command == "status":
            result = status(a.home, a.base)
        else:
            result = uninstall(a.home, a.base)
    except Exception as e:
        print("openproof local roles: " + str(e), file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
