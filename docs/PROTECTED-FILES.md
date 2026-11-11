# Protected files

An approved document is a row in the receiver's state. No other program reads
it there. With protected files, the receiver service also writes each approved
document as a normal file:

- every local account can read the file;
- only the receiver's account can change it.

So a program that runs as the owner, for example an AI agent, can read the
file but cannot change it. The receiver service is the only program that
writes the file, and it writes the content of the document in its state. That
content changes only as G1 says, under G1's condition ([TCB.md](TCB.md)).

This needs [separate role accounts](LOCAL-ROLES.md). It adds no guarantee to
G1, G2 or G3. It is off unless the administrator turns it on.

## Turn it on

Protected files are an option of the role accounts install:

```
sudo /usr/bin/python3 -I scripts/local_roles.py install --home HOME --publish
```

To add the option to an existing install, run `uninstall`, then `install`
with `--publish` ([LOCAL-ROLES.md](LOCAL-ROLES.md)). The history is kept.

The install makes the folder `BASE/published` (macOS:
`/private/var/db/openproof/published`; Linux: `/var/lib/openproof/published`).
The folder belongs to the receiver's account, with mode 755. The receiver
service starts with `--publish BASE/published`.

## What the receiver service does

- Each document is the file `BASE/published/DOCUMENT`, with mode 644. After a
  successful write, the file has the content of the current version of the
  document, and its SHA-256 equals `content_sha256` in the receipt of that
  version.
- The state stays the source. The service writes the file after the change is
  committed. It writes a new file and renames it into place, so a reader gets
  all of the old content or all of the new content.
- The service writes the files when it starts, after each change request that
  it handles (admitted or refused), and when it is asked for its status. It writes a file only when
  the file is absent or differs.
- When a write fails (for example on a full disk), the file keeps the earlier
  approved version, or is absent if there was none. The change is still
  stored and receipted. `status` names the document (below), and the service
  tries again at each of the events above.
- A document whose name has a capital letter is stored and receipted as
  before, but is not written as a file. Some file systems ignore case, and
  `Notes` and `notes` would then be one file. Use lower-case names for
  documents that you want as files.
- The service does not start when the folder is not a directory, when it does
  not belong to the account that owns the receiver's state, or when its mode
  lets a group or other accounts write it. The service does not check the
  folders above it; `status` does.

## Check

```
/usr/bin/python3 -I BASE/libexec/local_roles.py status --home HOME
```

With protected files on, the answer has this part:

```
"protected_files": {
  "folder": "/private/var/db/openproof/published",
  "owner_cannot_change": true,
  "receiver_writes_here": true,
  "not_published": []
}
```

- `owner_cannot_change`: by owner, group and mode, the owner's account cannot
  change the folder, a file in it, or a folder on the path to it; the folder
  belongs to the receiver's account; and its mode lets no group or other
  account write it. Access control lists are not read.
- `receiver_writes_here`: the receiver service reports this folder as its
  own.
- `not_published`: the documents whose files do not have the current
  content. A name with a capital letter stays in this list. Another name in
  it is a failed write: that file has an earlier version or is absent.
  `null` means that the service did not accept the folder.

The files are protected when `"separated"` and the first two values are true
and `not_published` is a list. A file is current when its document is not in
that list. If a change is written while `status` runs, `owner_cannot_change`
can be false once; run `status` again. As for the other values, the check
that does not depend on the owner's account is `status` run by the
administrator.

## Use a protected file

A program must read the file by a path that the agent cannot change:

- the path in `BASE/published` itself; or
- a link that root owns, in a folder that the owner's account cannot change,
  for example:

  ```
  sudo ln -s /private/var/db/openproof/published/agent-rules /Library/SomeTool/rules.md
  ```

A link or a copy in the owner's home folder is not protected: the owner's
account can replace it. A program that the agent controls can also ignore the
file. Protected files are for programs that read a fixed, administrator-set
path. Whether a given program follows a link at such a path is that program's
behaviour; test it.

## Limits

- Every local account can read the files. Do not put secrets in a document
  that becomes a protected file.
- An administrator, or root, can change the files and the folder, as for the
  receiver's state.
- A new version can be late. A process in the owner's account can fill the
  disk, and the file then keeps the earlier approved version; `status` names
  that document. Such a process can also stop a request before it reaches
  the receiver. That change then has no receipt, and `status` cannot show it.
  In both cases the file's content is still an approved version.
- After a power loss, a file can have the earlier approved version, or be
  unreadable to other accounts, until the receiver service starts again and
  writes it.
- A program that read the file before a change has the old content until it
  reads the file again.
- A document is at most 8,192 bytes.
- `uninstall` removes the folder and its files. The documents stay in the
  history. A link to a removed file then points to nothing.
- Documents are never removed, so a protected file is never removed while the
  option is on.
- The service writes all files before it accepts requests. With very many
  documents, the start can take longer than the 20 seconds that `install`
  waits.

## Tests

`crates/openproof-receiver/src/publish.rs` tests the writes, the repairs, the
names that do not become files and the folder checks.
`scripts/tests/test_role_service.py` tests the service: start-up refusals, a
file after a change, a replay, a status request and a restart, a new version,
a capital-letter name, a file that cannot be written, and a folder that
becomes unsafe. `scripts/tests/test_local_roles.py` (root on Linux) installs
with `--publish` and checks that the owner's account and a third account can
read a protected file and cannot write, append, delete, rename, replace or
re-mode it, or add a file or a link to the folder; it also checks `status`
for unsafe folders, and that a failed install leaves nothing.

On a Mac (launchd, 10 Nov 2026), these were checked by hand: `uninstall` of a
version 2 install, `install --publish`, the `status` answer above, the files
of the documents that existed before the install, a read by the owner's
account, a refused write by the owner's account, a new version of a file
after a passkey approval, the file of a new document, and a root-owned link
from the fixed rules path of another program to a protected file, which that
program then read and could not change. Confirm an install with `status`.
