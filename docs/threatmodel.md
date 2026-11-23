# Threat model

This file is for version 0.9.0 and the trusted code that [TCB.md](TCB.md)
lists. It replaces the threat models of versions 0.1 to 0.5. Those described
code that is no longer on the main path; they are in the git history of this
file.

This is a design model. It is not an audit and it is not a proof. No human
security review has been done
([handoff/REVIEW-BRIEF.md](handoff/REVIEW-BRIEF.md)). This file adds no
guarantee. The guarantees are G1, G2 and G3 in the [README](../README.md),
each with its condition. This file says who can attack what, what stops them,
and what does not stop them.

## What is protected

| Asset | Guarantee | Condition |
|---|---|---|
| The receiver's documents, and the protected files made from them | G1: a document changes only for the exact content, version and receiver that the owner approved, once, before the approval expires | An owner passkey is set up, and the receiver runs under its own account |
| The history of receipts | G2: every executed change is in the witness's signed, ordered history; omission, reordering or a fork is detected against a trusted checkpoint | The witness is run by a party other than the receiver. **This version has no supported way to meet it:** the role services run on the owner's computer only |
| A third party's result for an exported history | G3: anyone can verify an exported history offline with the separate Go verifier, given the trusted root and a current checkpoint | The verifier and root are obtained independently of the archive |

Not protected:

- **Secrecy of document content.** OpenProof does not encrypt content. The
  receiver stores each request with its content, an export holds those
  requests, and every local account can read a protected file.
- **Availability.** Code in the owner's account can block, delay or drop
  every request. OpenProof then does nothing; it does not do the wrong thing.
- **The truth of what a document says, or an effect outside the receiver.** A
  receipt is the receiver's signed statement about its own stored document.

## The parts

| Part | Runs as | Holds | Trusted for |
|---|---|---|---|
| Agent and its tools (`openproof-witness mcp`) | The owner's account | Nothing secret | Nothing. It can propose, and it can ask to execute approved work. It cannot approve |
| Owner app server, broker, approval gate | The owner's account | Authority key, root key, proposals | Nothing under G1's condition, except the origin and page tables ([TCB.md](TCB.md)) |
| Review page and passkey set-up page | The owner's browser, on the review origin | Its own copy of the proposal that it shows | What the owner sees, and what the passkey signs |
| Authenticator (for example Touch ID) | The platform | The passkey's private key | A signature only after a user-verified gesture |
| Receiver service (`openproof-role serve`) | The receiver's account | Receiver key, documents, used nonces, the pinned trust | G1; the receipts for G2 |
| Witness service (`openproof-role serve`) | The witness's account | Witness key, the ordered history | G2 |
| Status check (`roles_status.py`) | The owner or the administrator, from a root-owned copy | Nothing | The report that G1's condition holds |
| Go verifier | The party that verifies | The trusted root, a checkpoint, the current time | G3 |
| Cosigning witnesses (optional) | Other operators | Their own keys | That one history exists for each tree size ([WITNESS-NETWORK.md](WITNESS-NETWORK.md)) |
| Administrator, root | — | Everything | Fully trusted. See "Out of scope" |

## Attackers

**A. Code in the owner's account.** This is the main case: an AI agent, or
code that an agent was made to run. It can read and change every file of the
owner, the authority key and the root key included. It can run the owner's
programs, send any bytes to the role services, open local ports, and change
what the owner's terminal shows. Under G1's condition it cannot read or change
a role's key or state, it cannot change the root-owned role code, and it
cannot make the authenticator sign.

**B. Another local account** that is not the owner and not root. It can read
protected files. It can try to connect to local ports and to the role
sockets.

**C. A web page** that the owner's browser has open. It can send requests to
local ports. It cannot read the answers of another origin.

**D. Whoever makes or carries an exported archive.** They can change, cut,
reorder or add anything in it, and they can put their own verifier or root
beside it.

**E. The operator of the witness,** when that is also the operator of the
receiver. They hold both keys and can sign a different history.

**F. The network.** No OpenProof service listens outside the computer. Only
the optional witness submitter talks to other hosts.

## Boundaries and controls

### 1. The owner's account to the receiver service

Attacker A sends requests on the receiver's Unix socket.

| Control | Where |
|---|---|
| The service answers only the accounts it was started for (the owner and root), by the user ID that the kernel reports for the connection | `openproof-role`: `peer_uid` |
| One length-prefixed message for each connection, at most 1 MiB; JSON without duplicate keys or floats; a fixed set of operations for each role | `http.rs`: `read_message`, `strict_json`; `openproof-role`: `dispatch` |
| A change is admitted only with a signature of an active authority over the exact document, expected version, content hash, receiver, nonce and time window | `validate_request`, `apply_inner` |
| The content must have the approved hash and be at most 8,192 bytes | `validate_request` |
| With a passkey in the trust, every new admission needs a user-verified assertion from that passkey over the approval's digest, from the registered origin | `passkey.rs`: `admit_owner_assertion`, `verify_assertion` |
| A nonce is used once. A retry of the same approval returns the first receipt and changes nothing. The same nonce with another approval is refused | `apply_inner` (`consumed`) |
| The document must be at the expected version | `apply_inner` |
| The change, the receipt and the used nonce are one database transaction | `apply_inner` |
| The trust that the service admits under is installed only with the root's signature. A later trust cannot have a lower epoch, cannot remove or replace the passkey, and cannot change the role keys. The signing clock does not go back | `roles.rs`: `role_install`; `pin`; `pin_owner_passkey`; `clock.rs` |

What attacker A can still do here: read the root key in the owner home and
install a trust with another authority key. The receiver still requires the
passkey assertion, so no change is admitted. A can also stop all work.

Without a passkey, A reads the authority key and signs approvals. Without
separate role accounts, A changes the receiver's state directly. G1's
condition names both.

### 2. The owner app's server to the review page

The owner must see what the passkey signs. The authenticator shows no
content, and the server is not trusted.

| Control | Where |
|---|---|
| The review page keeps its own copy of the proposal that it shows. Before a passkey prompt it checks the signed approval against that copy: document, version, the content hash that it computes itself, and a window of at most 10 minutes that is valid now | `app/approval.js`, `app/review.js` |
| The page computes the approval digest itself and uses it as the passkey challenge. The server never chooses the challenge | `app/approval.js` |
| The review origin serves only the review page, the set-up page, their modules and their requests. The workspace runs on a second origin. An assertion obtained on the workspace origin carries that origin, and the gate and the receiver refuse it | `owner_app.rs`, `TCB:` regions; `verify_assertion` (origin) |
| Pages load scripts and styles only from their own origin, start no workers, cannot be put in a frame and have no form target; `Cross-Origin-Opener-Policy: same-origin` | `owner_app.rs`: `CSP` |
| Text from an agent or a document is shown as text, never as HTML or script | `app/common.js`, `app/review.js` |

Limits: the page's line diff compares against the current text that the
server reports, which the page cannot check, and the page says so. Code that
controls the browser itself, or the owner's whole account at the moment of
approval, can change what the screen shows.

### 3. Other accounts and web pages to the owner app

| Control | Where |
|---|---|
| The owner app listens only on 127.0.0.1 | `owner_app.rs` |
| A write needs the owner's session, the right `Host`, a same-origin request and an anti-forgery header | `owner_app.rs` |
| The role sockets are in folders that only the role account can change, and the services refuse a peer that is not the owner or root | `roles_status.py`: `socket_folder_protected`; `peer_uid` |

Limits: browsers do not scope cookies by port, so the session cookie also
goes to other local web servers on `localhost`. That exposes the session, not
approvals, which need the passkey. Another local program can serve its own
page at the review origin's address while the owner app is not running, and
ask for an assertion there. Confirm only a passkey prompt that you started
from the owner app ([PASSKEY.md](PASSKEY.md)).

### 4. The receiver to the witness

| Control | Where |
|---|---|
| The witness adds a receipt only with the receiver's signature, at the next sequence number, with the hash of the event before it. The same sequence number with another receipt is refused | `witness` in `openproof-receiver/src/lib.rs` |
| The witness signs a checkpoint over the count and the head of its history | `witness`, `current_checkpoint` |
| The history is also an RFC 6962 tree with C2SP checkpoints, which other witnesses can cosign | `tlog.rs`; [WITNESS-NETWORK.md](WITNESS-NETWORK.md) |

Limit: this is attacker E. When one operator holds the receiver and the
witness, these checks show mistakes, not dishonesty. Separate role accounts
keep the witness key from the owner's account. They do not make the witness
independent: one administrator controls both accounts. OpenProof's log is not
on a public witness list today.

### 5. An exported archive to the Go verifier

Attacker D gives a third party an archive.

| Control | Where |
|---|---|
| The verifier takes the trusted root, a checkpoint and the current time as its own arguments, not from the archive | `reference/go-witness/main.go`, `archive.go` |
| It checks the witness's signature on the checkpoint and the receiver's signature on each receipt; the sequence number of each receipt and the hash of the receipt before it; for each change, the approval's signature by an authority of the trust, its window, its content hash, its single use, the document version, and the owner assertion when the trust has a passkey; and that the checkpoint's count and head are those of the history | `main.go`: `verify`; `passkey.go` |
| Across the trusts in an archive, a later trust cannot drop or replace the passkey | `archive.go`; `passkey.go`: `samePasskey` |
| With a cosigned checkpoint, it computes the tree root from every receipt and requires a quorum of cosigners whose keys the verifier supplies. One key never counts twice | `tlog.go` |
| It is written in Go without calling the Rust code, and the two are compared on the same cases | `scripts/witness_conformance.py` |

Limits: the Go verifier and the Rust code have the same author, so it is a
second implementation, not an outside review. A verifier or a root that comes
from the archive proves nothing. A caller who also loses or rolls back their
trusted root and checkpoint has no protection.

### 6. The installer to the system

The installer of the role accounts runs one time as root.

| Control | Where |
|---|---|
| The status check does not rely on what the installer did. It believes only what root owns, and it checks the end state: the code, the accounts, the folders, the service definitions, the sockets and the account of the process on each socket | `scripts/roles_status.py`; [TCB.md](TCB.md) |
| The receiver service itself reports the passkey in the trust that it enforces | `openproof-role`: `status` |
| Three installer regions stay trusted: the creation of the service accounts without a password and without a shell, and the copies of the role code and the role state | `scripts/local_roles.py`, `TCB:` regions |

Limits are listed in [TCB.md](TCB.md): the status check does not read access
control lists or the job that the service manager has loaded, and code in the
owner's account can change what the owner's own terminal shows. For a check
that does not depend on that account, the administrator runs the status check
with `sudo`.

### 7. The receiver to protected files

| Control | Where |
|---|---|
| Only the receiver service writes the files, in a folder of its own account, after the change is committed. It writes a new file and renames it into place | `publish.rs` |
| The service does not start when the folder is not a directory that only its account can write | `publish.rs` |
| The status check reports the folder and each document whose file does not have the approved content | `roles_status.py`; `openproof-role`: `status` |

Limits are in [PROTECTED-FILES.md](PROTECTED-FILES.md): a new version can be
late, every local account can read the files, and a program must read a file
by a path that the agent cannot change.

### 8. The submitter to other witnesses

The submitter carries tree heads and proofs to the witnesses that the owner
lists. No receipt, approval or document leaves the computer. Each cosignature
is checked before it is kept, and again by the Go verifier. The submitter is
not trusted.

## Out of scope

- **The administrator and root.** Root can read and change every account's
  files. An owner's account with administrator rights is the same as root:
  use a standard account as the owner.
- **Physical access, the operating system, the browser, the authenticator
  and the hardware.**
- **The owner confirms a prompt for content that they did not mean to
  approve.** The review page shows the full text first; reading it is the
  owner's part.
- **A passkey that the platform syncs.** It is as safe as the platform
  account that syncs it. The sign counter is not used, so a copied
  authenticator is not detected.
- **The moment of passkey set-up.** An attacker in the owner's account at
  that moment can install a key that they hold. Set up the passkey on a
  computer that you trust at that time.
- **A lost passkey.** It cannot be replaced yet. The home then approves no
  new change.
- **Dependencies and build tools.** The Rust and Go dependencies are locked.
  Validation checks the Rust dependencies against the RustSec advisory
  database and against a list of accepted licenses. That finds known
  problems only. No
  release is signed, and no build has been reproduced on a separate machine.
- **Code outside the trusted list.** A defect there can break a feature or
  stop OpenProof. [TCB.md](TCB.md) gives the reason, for each area, why it
  cannot break a guarantee. That reasoning has had no human review.
- **Experimental code** behind the Cargo feature `experimental`, and the
  original version 1 crates.

## How this is tested

Every test uses synthetic data, on one computer or in CI. A passing test
shows that one case behaves as written. It does not show that no defect exists.

- Rust unit tests of the trusted crates, with negative cases.
- `scripts/tests/test_role_service.py`: the peer check, the message form,
  each role's operations, tampering, replay, trust updates, protected files.
- `scripts/tests/test_local_roles.py` (as root, on Linux): install, the
  workflow through the services, a separation probe from the owner's account
  and from a third account, and install states that a defective installer
  could leave.
- `scripts/tests/test_review_page.py`: the review page's approval check, with
  its digest matched to the Rust one and every single difference refused.
- `scripts/passkey_smoke.mjs`: the full passkey workflow in a real browser
  with a virtual authenticator, with the server's answers changed in flight.
- `scripts/witness_conformance.py`: the same cases through the Rust and the
  Go implementations, passkey cases included.
- `reference/go-witness`: the Go verifier's own tests, with the ways that a
  cosigned checkpoint must be refused.
- `fuzz/fuzz_targets`: five fuzz targets (`evidence`, `policy`, `trust`,
  `witness`, `witness_state`), run in bounded campaigns.

Checked by hand on a Mac only: the launchd install, Touch ID, and the
protected files ([LOCAL-ROLES.md](LOCAL-ROLES.md),
[PROTECTED-FILES.md](PROTECTED-FILES.md)).

## Open

1. An independent witness, so that G2's condition can be met.
2. A human security review of the trusted code.
3. Replacement of a lost passkey.
4. A signed release, and a build reproduced by another party.

Change this file in the same change that moves a boundary or adds trusted
code.
