#!/usr/bin/env python3
"""Replace the owner passkey. Only the administrator can do this.

    sudo /usr/bin/python3 -I BASE/libexec/roles_passkey.py

The owner makes the new passkey in the owner app first ("Replace passkey" on
the passkey set-up page). The page shows a code for the new passkey. This
tool asks for that code and continues only when it is the code of the
prepared passkey. So a replacement that a program in the owner's account
prepared with its own key, or for another address, is refused
(docs/PASSKEY.md).

The receiver service and the witness service take the replacement only from
user ID 0. The receiver writes a receipt of kind `passkey` into its history.
The tool also brings a witness that is behind the receiver into step; that
needs no code, because the receiver already has the passkey.

Run this copy, which `install` made as root, and no other: the owner's
account can show any command. The owner home is read from the install record,
which is a file of root.

This tool is in the trusted code (docs/TCB.md). It uses the Python standard
library and the status check beside it.
"""

import argparse, hashlib, json, os, pwd, stat, sys
from pathlib import Path

# `-I` leaves the folder of this file out of the search path. The status check
# beside it is a file of root, as this file is.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from roles_status import BASE, ROLES, ask, load_record, record_path, role_accounts
from roles_status import root_only, status

PREPARED = "passkey-replacement.json"
PASSKEYS = ("owner_passkey", "retired_owner_passkeys")


def code(passkey):
    """The code of a passkey: the first 20 hexadecimal characters of the
    SHA-256 of its public key (the 65-byte point, in hexadecimal), its
    relying party and its origin, one on each line, in groups of four. The
    set-up page computes the same from the passkey that it made and from its
    own address."""
    text = "\n".join(passkey[k] for k in ("public_key", "rp_id", "origin"))
    digest = hashlib.sha256(text.encode()).hexdigest()[:20].upper()
    return "-".join(digest[i : i + 4] for i in range(0, 20, 4))


def plain(text):
    return "".join(c for c in text.upper() if c.isalnum())


def prepared(home):
    """The replacement that the owner app prepared, or None. It is a file of
    the owner's account and is not trusted: no link is followed, nothing but
    a regular file is read, and what it holds is checked by the code and by
    the role services."""
    try:
        fd = os.open(home / PREPARED, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        raw = f.read(1_048_577)
    try:
        signed = json.loads(raw[:1_048_576])["signed"]
        trust = signed["payload"]
        return signed, trust["owner_passkey"], trust["retired_owner_passkeys"][-1]
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):
        return None


def replace(base, read=input):
    if os.geteuid() != 0:
        raise RuntimeError("Run this as the administrator, with sudo.")
    if not base.is_absolute() or not root_only(record_path(base)):
        raise RuntimeError(f"No install record of root in {base}.")
    home = Path(json.loads(record_path(base).read_text())["home"])
    if not status(home, base)["separated"]:
        raise RuntimeError(
            "The role accounts are not as an install leaves them. "
            "Run roles_status.py and correct that first."
        )
    record = load_record(base, home)
    uids = role_accounts(record, pwd.getpwnam(record["owner"]).pw_uid)

    def to(role, op, body=None):
        """Ask a role service, and only the process of its own account."""
        return ask(record["sockets"][role], op, uids[ROLES.index(role)], body)

    def passkeys(role):
        signed = to(role, "signed-trust")
        return signed, [signed["payload"].get(k) for k in PASSKEYS]

    def witness_in_step():
        """The witness takes the receiver's passkeys and the receipt of the
        last replacement. The receiver has them through this tool already."""
        signed, required = passkeys("receiver")
        if passkeys("witness")[1] != required:
            to("witness", "replace-passkey", {"signed": signed})
        if required[1]:
            sequence = required[0]["from_sequence"] - 1
            receipt = to("receiver", "receipt", {"sequence": sequence})
            try:
                to("witness", "witness", {"receipt": receipt})
            except RuntimeError:
                # The witness is some receipts behind. The owner's next executed
                # change brings them to it in order.
                pass
        return required[0]

    try:
        required = witness_in_step()
    except RuntimeError as e:
        raise RuntimeError(
            "The witness is not in step with the receiver, and this tool could "
            f"not correct that ({e}). If the trust has ended, renew it in the "
            "owner app, then run this tool again."
        ) from None
    if required is None:
        raise RuntimeError("The receiver requires no owner passkey.")
    found = prepared(home)
    if found is None or found[1] == required:
        return dict(
            replaced=False,
            receiver_requires=code(required),
            note="No replacement is waiting. The witness is in step with the receiver.",
        )
    signed, new, old = found
    if old != required:
        raise RuntimeError(
            "The prepared replacement is not for the passkey that the receiver "
            "requires now. Make the new passkey again in the owner app."
        )
    print("Passkey that the receiver requires now: " + code(required))
    typed = read("Type the code that the set-up page shows for the new passkey: ")
    if plain(typed) != plain(code(new)):
        raise RuntimeError(
            "That is not the code of the prepared passkey. Nothing was changed. "
            "If the page shows another code, a program in the owner's account "
            "can have changed the prepared replacement."
        )
    try:
        to("receiver", "replace-passkey", {"signed": signed})
    except RuntimeError:
        # The receiver can have taken it already: the answer was lost, or the
        # service stopped before it stored its trust files. Only a receiver
        # whose state has these passkeys accepts this trust as a plain install.
        try:
            to("receiver", "install-trust", {"signed": signed})
        except RuntimeError:
            raise RuntimeError(
                "The receiver refused the prepared replacement. Nothing was "
                "changed. A prepared replacement is good for one day, and only "
                "while no change is executed and no trust is renewed after it "
                "was prepared. Make the new passkey again in the owner app."
            ) from None
    try:
        witness_in_step()
    except RuntimeError as e:
        raise RuntimeError(
            "The receiver has the new passkey. The witness does not have it "
            f"yet ({e}). Run this tool again."
        ) from None
    return dict(
        replaced=True,
        receipt_sequence=new["from_sequence"] - 1,
        new_passkey=code(new),
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", type=Path, default=BASE)
    a = p.parse_args()
    try:
        print(json.dumps(replace(a.base), indent=2))
    except Exception as e:
        print("openproof passkey replacement: " + str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
