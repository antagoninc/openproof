#!/usr/bin/env python3
"""Run the receiver and the witness under their own operating-system accounts.

Without this, one account runs the owner app, the receiver and the witness. A
process that runs as the owner can then change the receiver's state directly
or sign a false history with the witness key. After `install`:

- the receiver and the witness each run as a separate service account;
- their keys and state are readable only by that account;
- the owner app reaches them only through the bounded mTLS role service, so
  every change still passes the receiver's approval checks;
- the services run one root-owned copy of the Rust binary, which the owner
  cannot change; no interpreter or downloaded package is involved.

The owner keeps the approval gate, the authority key and the root key. An
owner passkey is still needed to make approvals that the owner account alone
cannot produce. The witness is still on the same computer, so G2 still needs
an independent witness operator.

Commands:
  sudo python scripts/local_roles.py install --home HOME
  python scripts/local_roles.py status --home HOME
  sudo python scripts/local_roles.py uninstall --home HOME

Run `install` only from a checkout you have just pulled and checked: it copies
the role code from this checkout into a root-owned location.
"""

import argparse, datetime, hashlib, ipaddress, json, os, platform, plistlib
import pwd, shutil, signal, socket, sqlite3, stat, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
ROLES = ("receiver", "witness")
VERSION = "openproof-local-roles/1"
# Files the role service needs, relative to the repository root.
# The only code the role services run: one root-owned copy of this binary.
BINARY = "target/debug/openproof-witness"
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


# ---------------------------------------------------------------- TLS


def make_tls(roles_dir, owner_dir, days=825):
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "OpenProof local roles CA")]
    )
    usage = dict(
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        encipher_only=False,
        decipher_only=False,
    )

    def builder(public, subject):
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
        )

    ca = (
        builder(ca_key.public_key(), ca_name)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, key_cert_sign=True, crl_sign=True, **usage
            ),
            True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM)
    secret = lambda k: k.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    def leaf(name, server):
        key = ec.generate_private_key(ec.SECP256R1())
        b = (
            builder(
                key.public_key(),
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]),
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=False, crl_sign=False, **usage
                ),
                True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        (
                            ExtendedKeyUsageOID.SERVER_AUTH
                            if server
                            else ExtendedKeyUsageOID.CLIENT_AUTH
                        )
                    ]
                ),
                False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
            )
        )
        if server:
            b = b.add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                False,
            )
        return b.sign(ca_key, hashes.SHA256()), key

    files = {}
    client, client_key = leaf("OpenProof owner app", False)
    files[owner_dir / "ca.pem"] = pem(ca)
    files[owner_dir / "client.pem"] = pem(client)
    files[owner_dir / "client.key"] = secret(client_key)
    for role in ROLES:
        cert, key = leaf("OpenProof " + role, True)
        files[roles_dir[role] / "tls/ca.pem"] = pem(ca)
        files[roles_dir[role] / "tls/server.pem"] = pem(cert)
        files[roles_dir[role] / "tls/server.key"] = secret(key)
    fingerprint = hashlib.sha256(
        client.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    return files, fingerprint, (now + datetime.timedelta(days=days)).isoformat()


# ---------------------------------------------------------------- files


def write_private(path, data, uid, gid, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
        f.flush()
        os.fsync(f.fileno())
    os.chown(path, uid, gid)


def copy_state(source, target):
    """Copy a role state directory with a consistent SQLite snapshot."""
    target.mkdir(mode=0o700)
    for item in sorted(source.iterdir()):
        if item.name.endswith(("-wal", "-shm")):
            continue
        if item.suffix == ".db":
            src = sqlite3.connect(f"file:{item}?mode=ro", uri=True)
            dst = sqlite3.connect(target / item.name)
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


def port_free(port):
    """No process accepts connections on the port. Connections in TIME_WAIT
    do not count: the services bind with SO_REUSEADDR."""
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return False
    except OSError:
        return True


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
    shutil.copy2(src, code / "openproof-witness")
    for p in [code, code / "openproof-witness"]:
        os.chown(p, 0, 0)
        os.chmod(p, 0o755)
    return code


# ---------------------------------------------------------------- services


def label(role):
    return "com.antagon.openproof." + role


def service_command(code, role_dir, role, port, fingerprint):
    return [
        str(code / "openproof-witness"),
        "serve-role",
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
        "--cert",
        str(role_dir / "tls/server.pem"),
        "--tls-key",
        str(role_dir / "tls/server.key"),
        "--ca",
        str(role_dir / "tls/ca.pem"),
        "--client-fingerprint",
        fingerprint,
        "--bind",
        "127.0.0.1",
        "--port",
        str(port),
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


def wait_for_port(port, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.3)
    raise RuntimeError(
        f"Role service on port {port} did not start. Read its service.log."
    )


# ---------------------------------------------------------------- commands


def record_path(base):
    return base / "install.json"


def heads(home):
    from witness_workflow import call

    return {
        role: dict(
            count=call(["head", home / role / "state"])["count"],
            root=call(["role-status", home / role / "state"])["root"],
        )
        for role in ROLES
    }


def _move_roles(
    home,
    base,
    code,
    users,
    manager,
    ports,
    owner,
    owner_entry,
    accounts,
    roles_dir,
    tls_owner,
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
        copy_state(home / role / "state", d / "state")
        shutil.copy2(home / role / "key.secret", d / "key.secret")
        shutil.copy2(home / "trust.json", d / "trust.json")
        shutil.copy2(home / "trust-signed.json", d / "trust-signed.json")
    files, fingerprint, expires = make_tls(roles_dir, tls_owner)
    for path, data in files.items():
        role = next((r for r in ROLES if roles_dir[r] in path.parents), None)
        uid, gid = (
            (owner, owner_entry.pw_gid)
            if role is None
            else (accounts[role].pw_uid, accounts[role].pw_gid)
        )
        write_private(path, data, uid, gid)
    os.chown(tls_owner, owner, owner_entry.pw_gid)
    os.chmod(tls_owner, 0o700)
    for role in ROLES:
        chown_tree(roles_dir[role], accounts[role].pw_uid, accounts[role].pw_gid)
    say("5/7 Start the role services")
    for role in ROLES:
        command = service_command(code, roles_dir[role], role, ports[role], fingerprint)
        start_service(manager, base, role, accounts[role], command, roles_dir[role])
    for role in ROLES:
        wait_for_port(ports[role])
    say("6/7 Connect the owner home and compare the history")
    config = dict(
        version="openproof-service-client/1",
        **{
            role: dict(
                url=f"https://127.0.0.1:{ports[role]}",
                ca=str(tls_owner / "ca.pem"),
                cert=str(tls_owner / "client.pem"),
                key=str(tls_owner / "client.key"),
            )
            for role in ROLES
        },
    )
    write_private(
        home / "service-client.json",
        json.dumps(config, indent=2),
        owner,
        owner_entry.pw_gid,
    )
    after = heads(home)
    if after != before:
        raise RuntimeError(f"History differs after the move: {before} vs {after}")
    say("7/7 Move the owner's copies of the role keys out of the owner's reach")
    backup.mkdir(mode=0o700)
    for role in ROLES:
        shutil.move(str(home / role), str(backup / role))
        (home / role).mkdir(mode=0o700)
        os.chown(home / role, owner, owner_entry.pw_gid)
    for p in backup.rglob("*"):
        os.lchown(p, 0, 0)
    return after, expires


def install(home, base, users, manager, base_port):
    from witness_workflow import home_lock

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
    ports = {"receiver": base_port, "witness": base_port + 1}
    with home_lock(home):
        before = heads(home)
        if before["receiver"]["count"] != before["witness"]["count"]:
            raise RuntimeError(
                "Some receipts are not witnessed yet. Execute or recover the pending "
                "actions in the owner app first."
            )
        for role in ROLES:
            if not port_free(ports[role]):
                raise RuntimeError(
                    f"Port {ports[role]} is in use. Choose another with --port."
                )
        base.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chown(base, 0, 0)
        os.chmod(base, 0o755)
        refuse_writable(
            [base], owner, "Role keys and code would be in the owner's reach."
        )
        say("1/7 Check that the owner cannot change the role location")
        say("2/7 Install a root-owned copy of the openproof-witness binary")
        code = install_code(base)
        refuse_writable(
            [code], owner, "The role services would run code the owner can change."
        )
        accounts = {}
        roles_dir = {role: base / role for role in ROLES}
        tls_owner = home / "service-tls"
        if tls_owner.exists():
            raise RuntimeError(f"{tls_owner} already exists. Move it aside first.")
        backup = base / ("owner-backup-" + time.strftime("%Y%m%dT%H%M%S"))
        try:
            after, expires = _move_roles(
                home,
                base,
                code,
                users,
                manager,
                ports,
                owner,
                owner_entry,
                accounts,
                roles_dir,
                tls_owner,
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
            for role in ROLES:
                if (backup / role).exists():
                    if (home / role).exists():
                        (home / role).rmdir()
                    shutil.move(str(backup / role), str(home / role))
                    chown_tree(home / role, owner, owner_entry.pw_gid)
            for role in ROLES:
                stop_service(manager, base, role)
                if role in accounts:  # Only accounts this install created.
                    delete_account(users[role])
                shutil.rmtree(roles_dir[role], ignore_errors=True)
            (home / "service-client.json").unlink(missing_ok=True)
            shutil.rmtree(tls_owner, ignore_errors=True)
            shutil.rmtree(code, ignore_errors=True)
            raise
        record = dict(
            version=VERSION,
            home=str(home),
            owner=owner_entry.pw_name,
            platform="macos" if MAC else "linux",
            manager=manager,
            users=users,
            ports=ports,
            base=str(base),
            backup=str(backup),
            tls_expires=expires,
            installed_at=int(time.time()),
            history=after,
        )
        path = record_path(base)
        path.write_text(json.dumps(record, indent=2))
        os.chmod(path, 0o644)
    lock = home / ".broker.lock"
    if lock.exists() and lock.stat().st_uid == 0:
        os.chown(lock, owner, owner_entry.pw_gid)
    say("Done. The receiver and the witness now run under their own accounts.")
    say(f"Backup of the owner's old role folders (root only): {backup}")
    return record


def load_record(base, home):
    path = record_path(base)
    if not path.exists():
        raise RuntimeError("Local roles are not installed.")
    record = json.loads(path.read_text())
    if record.get("version") != VERSION or Path(record["home"]) != home.resolve():
        raise RuntimeError(
            f"Local roles are installed for another home: {record.get('home')}"
        )
    return record


def status(home, base):
    record = load_record(base, home)
    report = dict(
        installed_for=record["home"], tls_expires=record["tls_expires"], roles={}
    )
    from witness_workflow import call

    for role in ROLES:
        d = Path(record["base"]) / role
        entry = dict(account=record["users"][role], port=record["ports"][role])
        try:
            entry["history_count"] = call(["head", home / role / "state"])["count"]
            entry["service"] = "running"
        except Exception as e:
            entry["service"] = "not reachable: " + str(e)[:200]
        try:
            open(d / "key.secret", "rb").close()
            entry["key_readable_by_this_account"] = True
        except PermissionError:
            entry["key_readable_by_this_account"] = False
        try:
            entry["folder_owner"] = pwd.getpwuid(d.stat().st_uid).pw_name
        except (KeyError, PermissionError):
            entry["folder_owner"] = "unknown"
        report["roles"][role] = entry
    report["separated"] = os.geteuid() != 0 and all(
        r["service"] == "running"
        and not r["key_readable_by_this_account"]
        and r["folder_owner"] == r["account"]
        for r in report["roles"].values()
    )
    return report


def uninstall(home, base):
    from witness_workflow import home_lock

    if os.geteuid() != 0:
        raise RuntimeError("Run uninstall with sudo.")
    home = home.resolve()
    record = load_record(base, home)
    owner = pwd.getpwnam(record["owner"])
    with home_lock(home):
        # Read the role states directly, not through the services: uninstall
        # must work even when a service does not answer.
        say("1/4 Stop the role services")
        for role in ROLES:
            stop_service(record["manager"], base, role)
        before = heads(base)
        say("2/4 Return the role keys and state to the owner home")
        for role in ROLES:
            d = base / role
            target = home / role
            if any(target.iterdir()):
                raise RuntimeError(
                    f"{target} is not empty. Move its contents aside first."
                )
            copy_state(d / "state", target / "state")
            shutil.copy2(d / "key.secret", target / "key.secret")
            chown_tree(target, owner.pw_uid, owner.pw_gid)
        (home / "service-client.json").unlink()
        shutil.rmtree(home / "service-tls")
        after = heads(home)
        if after != before:
            raise RuntimeError(f"History differs after the return: {before} vs {after}")
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
    p.add_argument(
        "--port",
        type=int,
        default=47101,
        help="Receiver port; the witness uses the next port",
    )
    a = p.parse_args()
    users = {"receiver": a.receiver_account, "witness": a.witness_account}
    try:
        if a.command == "install":
            result = install(a.home, a.base, users, a.manager, a.port)
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
