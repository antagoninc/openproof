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

Both fields are optional. A trust or request without them has the same bytes,
digest and signature as before.

## The exact rule

A request needs an assertion exactly when the trust has `owner_passkey` and
the receipt sequence is at least `from_sequence`. Otherwise it must not carry
one. The receiver is stricter: with a passkey in the trust, every new
admission needs an assertion.

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

Once a receiver, witness or verifier state has installed a trust with a
passkey, every later trust must carry the identical `owner_passkey`. Removing
or replacing it is refused, even with a valid root signature. The Go archive
verifier applies the same rule across the trusts in an archive.

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
- Replacing a lost passkey is not supported yet. It needs a reviewed handover
  procedure. Until then, a home whose passkey is lost cannot approve new
  changes.
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
