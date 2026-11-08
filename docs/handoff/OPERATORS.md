# Independent operator pilot

For current signed trust distribution, persistent verifier setup, authenticated export, staging and clock recovery, follow [REVIEW-HARDENING.md](../REVIEW-HARDENING.md). The older plain-trust manual flow below is a low-level synthetic exercise, not the recommended acceptance path.

Status: prepared for private handoff; no external host or operator enrolled.

## Ownership before deployment

Assign an owner authority, a receiver operator, a witness operator, and a verifier. Record each organization's identity, host administrator, incident contact, public-key fingerprint, and authenticated exchange channel. The witness must have separate administrative control and credentials from the receiver. Separate processes, accounts on one administrator's host, or AI agents controlled by one owner do not establish independent operation.

Each operator builds the reviewed source with `cargo build --release --locked --workspace` on its own Unix host. Linux execution must be tested before acceptance; the existing v0.7 results were obtained on macOS. Do not distribute local demonstration keys or databases. Generate new role keys on their destination hosts. Keep the authority key off the receiver and witness.

## First pilot: signed file exchange

Use the existing CLI and an operator-approved authenticated file-transfer channel. This is a manual pilot, not a deployed network service. Do not expose CLI commands through an arbitrary remote shell or invent an unauthenticated HTTP wrapper. Transfer authentication, access controls, retention and confidentiality must be agreed and tested by operators. Signed evidence authenticates statements; it does not encrypt document contents.

On each of the three role hosts, from a private working directory:

```sh
umask 077
mkdir role
chmod 700 role
./openproof-witness keygen role/key.secret > role/public-key.json
```

Only receiver and witness initialize state:

```sh
./openproof-witness init role/state
```

Exchange only public keys using an authenticated channel and verify fingerprints independently. Provision identical `trust.json` on all roles, containing:

- `version`: `openproof-witness/1`
- `epoch`: positive integer, initially 1
- `expires_at`: agreed Unix timestamp in the future
- `authority`, `receiver`, `witness`: the respective public keys
- `previous_authorities`, `revoked_authorities`: initially empty arrays

Receiver and witness each run `./openproof-witness install role/state trust.json`. Trust is an operator-provisioned root; receiving a file from a caller is not sufficient to trust it. Compare its complete SHA-256 digest out of band. Clocks and durable host state remain trusted.

1. Authority owner inspects the complete proposal JSON, document ID, expected version and intended receiver. The low-level command is privileged and does not prompt for consent:
   `./openproof-witness approve role/key.secret trust.json < proposal.json > request.json`
2. Send request.json to the receiver through the agreed channel within its five-minute validity window. Receiver runs:
   `./openproof-witness receive role/state role/key.secret trust.json < request.json > receipt.json`
3. Receiver sends receipt.json to the witness. Witness runs:
   `./openproof-witness witness role/state role/key.secret trust.json < receipt.json > checkpoint.json`
4. Witness sends checkpoint.json directly to the verifier through its independently authenticated channel and sends a copy to the receiver. Receiver runs:
   `./openproof-witness export role/state trust.json < checkpoint.json > package.json`
5. Verifier obtains package.json from receiver, its trust configuration from the agreed trust administrator, and its checkpoint from the witness. It runs:
   `./openproof-witness verify trust.json checkpoint.json < package.json`

Check every exit status before transferring output: shell redirection can leave empty files after failure. Never interpret a receipt alone as witness confirmation. Never obtain both trust roots and the checkpoint solely from an untrusted evidence producer.

## Acceptance exercise

Record timestamps, source archive digest, binary digests, host platforms, role owners and public keys. Keep private keys and real confidential documents out of the report. Use synthetic content initially.

- Complete one authorized update and verify directly provisioned checkpoint.
- Reject altered content, wrong receiver, unapproved input and expired approval.
- Retry the identical still-valid request; observe the original receipt and one document version.
- Stop witness delivery after a receiver commit. Mark outcome committed but unwitnessed. Recover receipts in order; do not create another update as a retry.
- Reject a truncated package against the later checkpoint and a conflicting receipt at an existing sequence.
- Exercise trust expiry and the same retained next-epoch configuration across both stores. Stop admission during change; partial installation requires completion, not rollback.
- Test backups and recovery on expendable state. Never silently restore older state into service; reconcile witness pins before reopening admission.

Attach operator-signed attestations of who controls each host and key. Technical signatures alone cannot prove organizational independence. No production acceptance until transport, recovery and key custody are reviewed and the selected hosts pass these exercises.

## Limits

The receiver is trusted to report its own SQLite outcome. A witness does not establish document truth, model correctness, universal completeness or physical effects. An old pinned checkpoint cannot establish that no newer event exists. Receiver/witness key migration, hardware key custody, remote authenticated delegation, production supervision and automated reconciliation remain unimplemented. The local broker expects all roles on one host and must not be represented as a remote client.
