# Separate role accounts

By default, one account runs the owner app, the receiver and the witness. A
process that runs as that account can change the receiver's state directly. It
can also sign a false history with the witness key. A passkey does not stop
this, because the passkey protects approvals, not the receiver's files.

`scripts/local_roles.py` moves the receiver and the witness to their own
operating-system accounts on the same computer.

## What changes

| Before | After `install` |
|---|---|
| Receiver and witness keys are files in the owner home. | Each key is readable only by its service account. The owner home keeps no role keys. |
| Receiver and witness state are SQLite files the owner can write. | Each state is owned by its service account, mode 700. |
| The owner app runs the role commands itself. | The owner app reaches each role only through its role service (`openproof-role serve`) on a Unix socket. The service answers only the owner's account and root, by the user ID the kernel reports for the connection, and runs a fixed set of operations. Every change still passes the receiver's approval and passkey checks. |
| Role code runs from the checkout. | The services run one root-owned copy of the `openproof-role` binary. It holds only the receiver and witness code (`openproof-receiver`, `openproof-core`), not the owner app, the broker or the gate. No interpreter or downloaded package is involved. `install` refuses to continue if the owner account can change the role location. |

The owner keeps the approval gate, the authority key and the root key. Trust
epochs (passkey set-up, `renew`) still work: the role services install a
root-signed epoch, the role state refuses rollback and refuses to remove or
replace a pinned owner passkey, and the service refuses a change of role keys.

## What this does not do

- It does not make the witness independent. The witness still runs on the
  owner's computer, and the root key is still in the owner home. G2 still
  needs a witness operated by another party.
- It does not protect against an administrator who enters the administrator
  password. Root can read every account's files.
- Without a passkey, the authority key is still a file the owner account can
  read. Set up a passkey first ([PASSKEY.md](PASSKEY.md)).

## Install (macOS)

1. Stop the owner app.
2. Execute or recover all approved actions. `install` refuses to start while
   some receipts are not witnessed.
3. Pull and build a checkout you have checked:
   `cargo build --workspace --locked`.
4. Run, from the checkout. The script needs only the Python standard library,
   so use the system Python, isolated (`-I`), not a virtual environment that
   your account can change:

   ```
   sudo /usr/bin/python3 -I scripts/local_roles.py install --home outputs/passkey-trial
   ```

   If your login is a standard account, run it through the administrator
   account with `su ADMIN -c 'sudo …'` and full paths.

   The install:
   - copies the `openproof-role` binary and the script itself to
     `/private/var/db/openproof/libexec/` as root;
   - creates the hidden accounts `_openproofrcv` and `_openproofwit`;
   - copies the role keys and state, and starts two launchd daemons
     (`com.antagon.openproof.receiver`, `.witness`) whose sockets are
     `/private/var/db/openproof/sockets/ROLE/service.sock`, in a folder only
     that role's account can change;
   - compares the history before and after, then moves the owner's copies of
     the role folders into a root-only backup.

   If any step fails, the install undoes its changes and the owner home stays
   as it was.
5. Start the owner app as usual. To move an existing install to a new binary, run `uninstall`, then `install` again.

`uninstall` also removes an install made before 10 Nov 2026, which used
loopback TLS. `install` then sets up the Unix sockets.

## Check

Run it from the root-owned copy that install made, as your own account or as
the administrator:

```
/usr/bin/python3 -I /private/var/db/openproof/libexec/local_roles.py status --home outputs/passkey-trial
```

`status` asks the role services directly on their sockets. It never runs the
owner app's binary or other code from the checkout. Code that runs in your
account can still change what your own terminal shows, for example through
your shell's start-up files. For a check that does not depend on your account,
log in as the administrator and run the same command there.

`"separated": true` means both services answer, and each role folder belongs to
its service account and only that account can enter it, so your account cannot
read either role key.

`"passkey_required_by_receiver": true` means the receiver service itself
reports an owner passkey in the trust it admits under: it then refuses every
new change without an assertion from that passkey. The service reads this from
the trust it enforces, so it reports what the receiver requires, whatever the
owner app shows. G1 holds when both values are true ([TCB.md](TCB.md)).

## Uninstall

```
sudo /usr/bin/python3 -I scripts/local_roles.py uninstall --home outputs/passkey-trial
```

This stops the daemons, returns the keys and the full history to the owner
home, compares the history, keeps the role folders in a root-only backup, and
removes the accounts and the role code.

## Tests

`scripts/tests/test_local_roles.py` runs the full install, workflow, trust
renewal, separation probe, a refused connection from a third account, `status`
and uninstall with real accounts. It runs only as root on Linux with
`OPENPROOF_ROLE_ACCOUNT_TEST=1`. `scripts/tests/test_role_service.py` checks the
role service itself on every run: the peer check, each role's operations,
tampering, replay and opt-in trust updates. The macOS account and launchd steps
were checked on a Mac on 8 Nov 2026, with the earlier TLS transport; confirm
them with `status` after every install.
