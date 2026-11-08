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
| The owner app runs the role commands itself. | The owner app reaches each role only through the bounded mTLS role service on `127.0.0.1`. Every change still passes the receiver's approval and passkey checks. |
| Role code runs from the checkout. | Role code and its Python runtime are root-owned copies. `install` refuses to continue if the owner account can change them. |

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
4. Run, from the checkout:

   ```
   sudo outputs/local-venv/bin/python scripts/local_roles.py install --home outputs/passkey-trial
   ```

   The install:
   - downloads a pinned Python runtime (python-build-standalone 3.12.13) and
     checks its SHA-256. Apple's `/usr/bin/python3` uses LibreSSL without
     TLS 1.3, so it is not used;
   - installs the role code and the `cryptography` package under
     `/private/var/db/openproof/` as root;
   - creates the hidden accounts `_openproofrcv` and `_openproofwit`;
   - copies the role keys and state, makes TLS certificates, and starts two
     launchd daemons (`com.antagon.openproof.receiver`, `.witness`) on ports
     47101 and 47102;
   - compares the history before and after, then moves the owner's copies of
     the role folders into a root-only backup.

   If any step fails, the install undoes its changes and the owner home stays
   as it was.
5. Start the owner app as usual.

## Check

Run as your own account, not with sudo:

```
outputs/local-venv/bin/python scripts/local_roles.py status --home outputs/passkey-trial
```

`"separated": true` means both services answer, their folders belong to the
service accounts, and your account cannot read either role key.

## Uninstall

```
sudo outputs/local-venv/bin/python scripts/local_roles.py uninstall --home outputs/passkey-trial
```

This stops the daemons, returns the keys and the full history to the owner
home, compares the history, keeps the role folders in a root-only backup, and
removes the accounts and the role code.

## Tests

`scripts/tests/test_local_roles.py` runs the full install, workflow, trust
renewal, separation probe and uninstall with real accounts. It runs only as
root on Linux with `OPENPROOF_ROLE_ACCOUNT_TEST=1` and a root-owned Python in
`OPENPROOF_ROLE_PYTHON`. The macOS account and launchd steps are not covered
by automated tests; check them with `status` after install.
