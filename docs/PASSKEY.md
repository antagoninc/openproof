# Passkey owner approvals

## What it guarantees

Without a passkey, an approval is an Ed25519 signature made with
`authority/key.secret`. Any process that runs as the owner can read that file
and sign approvals.

With a passkey, every approval also needs a WebAuthn assertion. The assertion
needs a fresh gesture on the platform authenticator (Touch ID, face or device
PIN), with user verification. The passkey's private key stays in the
authenticator. Host processes cannot read it.

The receiver refuses to execute a request without a valid assertion. The Rust
and Go verifiers check the assertion again when they verify history.

The assertion signs the approval digest. That digest covers the document, the
expected version, the content hash, the single-use nonce, the receiver and the
time window. An assertion for one approval does not fit any other approval.

## How to set it up

1. Start the owner app. It is served at `http://localhost:PORT`. It still
   listens only on 127.0.0.1. WebAuthn does not accept IP addresses, so open
   the `localhost` link, not `127.0.0.1`.
2. Optional: choose a fixed port with `--port`. It is the review origin's port,
   which the passkey is bound to. Once a passkey is set up, the app always
   reuses the registered port; a different `--port` is refused. The workspace
   runs on a second port, and no workspace page can produce an assertion that
   the gate or the receiver accepts.
3. Select **Set up passkey**. It opens the set-up page, a separate page that
   runs no workspace code. Select **Set up passkey** there and confirm on your
   device.
4. The app checks the registration (its own challenge, `webauthn.create`, the
   exact origin, the `localhost` relying party, user presence and user
   verification, and an ES256 P-256 key).
5. The app issues a new trust epoch that contains `owner_passkey`. It is
   signed with the root key and installed in the receiver, witness and
   verifier states with the usual trust commands (`sign-trust`,
   `install-signed`, `verifier-install`). The credential id is kept in
   `passkey.json` in the owner home.

From then on:

1. Review the change on the review page, on the passkey's origin. That origin
   serves only the review and set-up pages, never the workspace's code. The
   page shows the exact content first, and the SHA-256 that it computes
   itself.
2. Approve. The Rust approval gate signs the approval of the stored
   proposal, but only if the proposal still has the review binding that the
   page showed. The gate keeps the signed approval as pending. A pending
   approval cannot be executed.
3. The page checks the approval before any passkey prompt
   (`app/approval.js`): the document, the version and the content hash must be
   those it shows, the approval must be valid now for at most 10 minutes, and
   the digest it computes must equal the gate's. Then it
   uses its own digest as the passkey challenge and shows it. The server never
   chooses the challenge, so the passkey cannot sign content that the page did
   not show. A mismatch stops with "The approval does not match the change
   shown here", and nothing is approved.
4. Confirm with the passkey. The gate verifies the assertion against the
   pending approval's digest. Then it stores the request with the assertion
   as approved. Only then is the action approved.
5. Execute as before. The receiver verifies the assertion again.

A pending approval is used once. It expires with the approval window (5
minutes). A failed assertion changes nothing; review again or retry before
expiry. The gate also pins the passkey: once it has seen a trust with a
passkey, it refuses a trust without that passkey. It also compares the trust
with the passkey that the local receiver state pinned.

The terminal approval command (`witness_workflow.py approve`) uses the gate
command `gate-approve-terminal`, which refuses when the trust has a passkey.
Approve in the owner app.

## Replace a lost passkey

A passkey can be lost, or you can want another one. The receiver refuses a
trust that changes the passkey, also with the root's signature: the root key
is a file in your home, and a program in your account could use it. So the
replacement needs the administrator of the computer. It needs
[separate role accounts](LOCAL-ROLES.md). Without them, the owner app offers
no replacement.

1. In the workspace, select **Replace passkey**. It opens the set-up page.
   Select **Make the new passkey** and confirm on your device.
2. The page shows a **code** of 20 characters. The page computes the code
   itself, from the passkey that it made and from its own address. Keep the
   page open.
3. The administrator runs the root-owned tool. On macOS:

   ```
   sudo /usr/bin/python3 -I /private/var/db/openproof/libexec/roles_passkey.py
   ```

   On Linux the tool is `/var/lib/openproof/libexec/roles_passkey.py`. The
   administrator runs this tool and no other program: a file in your home, or
   text on another screen, can name any command. The tool reads which home it
   serves from the install record, which is a file of root.

   The tool asks for the code. The administrator types the code **from your
   page**. The tool continues only when this is the code of the passkey that
   was prepared in your home. If the tool refuses the code, stop: a program
   in your account can have changed the prepared replacement.
4. Select **The administrator has confirmed**. Your next approval uses the
   new passkey.

What happens:

- The receiver service and the witness service take the replacement only
  from user ID 0. A request from your account is refused.
- The receiver writes a receipt of kind `passkey` into its history, with the
  SHA-256 of the new passkey record. The witness adds it like every receipt.
  So each replacement shows in the history and in every export.
- The new trust keeps the earlier passkey in `retired_owner_passkeys`. The
  verifiers check each approval against the passkey that was in force at its
  receipt: the old one before the `passkey` receipt, the new one after it.
- A request that the old passkey approved and that was not executed before
  the replacement is refused afterwards. Review it again.

When something stops in the middle:

- A prepared replacement is good for one day, and only while no change is
  executed and no trust is renewed after it was prepared. If the tool says
  that the receiver refused it, make the new passkey again.
- The receiver decides which passkey is in force. Your side follows the
  receiver: when you select the button, when the owner app starts, and when
  the trust is renewed. This also works when the prepared file is lost or
  its trust has ended.
- If the tool stops after the receiver and before the witness, the owner app
  says that the administrator must run the tool again. That run brings the
  witness into step and asks for no code.

Limits:

- The administrator can replace the passkey at any time. This was already
  the administrator's power: root can change every account's files.
- The tool cannot see who typed the code. Give the code only to the
  administrator, and only when you started the replacement yourself.
- Code that controls your browser when you make the new passkey can show a
  wrong code, as for the first set-up.
- A home can replace its passkey 8 times: a trust holds at most 8 retired
  passkeys.
- The replacement was tested on Linux. It was not yet run on a Mac.

## Trust and request fields

`owner_passkey` in the trust:

| Field | Meaning |
|---|---|
| `public_key` | Lowercase hex of the uncompressed P-256 point (65 bytes, starts with `04`). |
| `rp_id` | `localhost`, or a lowercase DNS name. |
| `origin` | Exactly `http://localhost:PORT`, or `https://HOST[:PORT]` inside `rp_id`. |
| `from_sequence` | The first receipt sequence that needs an assertion. |

`owner_assertion` in a request holds `authenticator_data`, `client_data_json`
and `signature`. All three are base64url without padding. The signature is the
DER ECDSA signature as the browser returns it. Limits: authenticator data at
most 1024 bytes, client data at most 2048 bytes, signature at most 80 bytes.

`retired_owner_passkeys` in the trust: the passkeys that were replaced,
oldest first, each with the same four fields. At most 8. The list is absent
unless a passkey was replaced; an empty list is refused. Each passkey starts
at a later sequence than the one before it.

A receipt of kind `passkey` has an empty `document` and `reason`,
`document_version` 0, an all-zero `approval_sha256`, and in `content_sha256`
the SHA-256 of the canonical bytes of the passkey that starts at the next
sequence.

These fields are optional. A trust or request without them has the same
bytes, digest and signature as before. A verifier from before 23 Nov 2026
refuses a history that holds a `passkey` receipt.

## The exact rule

A request needs an assertion exactly when a passkey of the trust was in force
at its receipt sequence: the passkey with the latest `from_sequence` at or
before it, among `owner_passkey` and `retired_owner_passkeys`. The assertion
must be from that passkey. Without a passkey in force, the request must not
carry one. The receiver is stricter: with a passkey in the trust, every new
admission needs an assertion from the current one.

Every passkey after the first starts right after a receiver receipt of kind
`passkey` that carries its hash. A `passkey` receipt that the trust does not
explain is refused, and so is a later passkey without its receipt.

An assertion is valid when all of these hold:

1. `client_data_json` is a JSON object without duplicate keys.
2. Its `type` is `webauthn.get`.
3. Its `challenge` is the base64url (no padding) of the 32 raw bytes of the
   approval digest. The digest is SHA-256 of the domain-separated canonical
   approval payload. It equals the receipt's `approval_sha256`.
4. Its `origin` equals the trusted `origin` exactly.
5. `crossOrigin` is absent or `false`.
6. `authenticator_data` is at least 37 bytes. Bytes 0..32 are SHA-256 of
   `rp_id`. The flags byte has user present (0x01) and user verified (0x04).
7. The ECDSA P-256 / SHA-256 signature verifies over
   `authenticator_data || SHA-256(client_data_json)` with the trusted key.
   High-S signatures are accepted.

The sign counter is not used. Synced passkeys always report 0.

`from_sequence` is set to the receiver's head plus one when the passkey is set
up. History from before the passkey still verifies under the new trust.

Once a receiver or witness state has installed a trust with a passkey, every
later trust must carry the identical passkeys. Removing or replacing one is
refused, even with a valid root signature. The one exception is the
administrator's replacement (above). The owner's own verifier follows a
replacement: it accepts a root-signed trust that keeps the passkeys it
pinned and adds later ones, but only a passkey whose start is after the
receipts that it has already verified. The Go archive verifier applies the
same rule across the trusts in an archive. So in both, each added passkey
still needs its `passkey` receipt. The owner's gate also follows; it
verifies no history and is not trusted.

## Honest limits

- A compromised host can still change what the screen shows before you touch
  the passkey. The challenge binds the approval digest, not the pixels. Read
  the content on the review page and only confirm what you meant to approve.
  The page's own check protects against defects in the owner app's server
  side, not against code that controls the browser or the owner account.
- Another local program can serve its own page at the same localhost address
  while the owner app is not running. It can then ask for an assertion. Only
  confirm a passkey prompt that you started from the owner app.
- Synced passkeys are as safe as the platform account that syncs them (for
  example your Apple Account).
- The sign counter is not used, so a cloned authenticator is not detected.
- `rp_id` is `localhost`. The passkey works only with this machine's owner
  app, at the registered port.
- A lost passkey is replaced through the administrator ("Replace a lost
  passkey", above). Without separate role accounts there is no replacement:
  such a home cannot approve new changes after the loss.
- The receiver, witness and root key still run under the owner's account on
  a single-host setup. A process with that account can change their state
  directly. The passkey protects the approval itself; the roles need separate
  accounts or hosts for G1 to hold against a compromised owner account.
- This feature has not yet been independently reviewed.

## Tests

- Rust: `crates/openproof-receiver/src/passkey.rs` (software P-256 keys).
- The review page's check and challenge: `scripts/tests/test_review_page.py`
  (the digest against a Rust vector, and every single difference refused).
- Go: `reference/go-witness/passkey_test.go`.
- Approval gate: `crates/openproof-witness/src/gate_tests.rs` (pending
  approval not executable, assertion for another digest, replay, expiry,
  passkey pin).
- Rust and Go agreement: the `passkey-*` cases in
  `scripts/witness_conformance.py`.
- Python owner-app routes: `scripts/tests/test_passkey.py`.
- Browser: `scripts/passkey_smoke.mjs` with the Chrome DevTools virtual
  authenticator. It also changes the owner app's answer in flight (other
  content, document, version or digest) and checks that the page refuses
  before any prompt.
