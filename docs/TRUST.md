# Key lifecycle and offline trust — v0.3

A separately provisioned Anchor pins root_key, audience and minimum_revision. The root signs a TrustBundle with version openproof-trust/1, revision, issued_at, expires_at and role-specific key entries. Each entry contains public_key, role, not_before, expires_at and optional revoked_at. See schemas/openproof-trust-v1.schema.json and fixtures/trust-v1. The schema describes structure; Rust also enforces key validity, duplicate roles, timestamps, signatures and cross-field constraints.

Signing preimage uses the existing OpenProof/v1/trust-bundle NUL domain followed by OPEC-1 bytes. Payload version is distinct from evidence version. Revision is 1..2^63-1 for SQLite storage compatibility. The authority's entire authorization interval must fit its key window; actor and executor event times must fit theirs.

## Operations

```text
sign-trust INPUT ROOT_SECRET OUTPUT
install-trust STATE SNAPSHOT ANCHOR
verify-trusted BUNDLE CONTEXT SNAPSHOT ANCHOR current|historical
execute-trusted BUNDLE CONTEXT POLICY ARGUMENTS EXECUTOR_SECRET STATE SNAPSHOT ANCHOR
```

Use new output files for signing. For role-key rotation, retain old keys for historical verification, add replacement keys with explicit roles/windows, increment revision, sign with the pinned root, and install the snapshot. For revocation, set revoked_at, increment revision and install the signed snapshot. Distribution and minimum revision updates are operator responsibilities. Private keys stay in separate files or memory; the trust snapshot contains only public material. Planned root rotation is available in v0.4 through a dual-signed transition and atomic local state migration. Independently redistribute the successor anchor to offline verifiers; this does not provide recovery from a compromised root. See RECOVERY.md.

Current verification uses the host clock in the CLI and requires currently valid authorization and role keys. Historical mode evaluates evidence at Context.now and allows expired unrevoked role keys, while still requiring a fresh root-signed trust snapshot at today's evaluation time. Any key revoked at or before the current evaluation time is rejected even in historical mode. This conservative policy prevents an attacker using a compromised key from gaining acceptance by backdating evidence. It may also reject legitimate old evidence after revocation. There is no trusted timestamp service: historical verification authenticates timestamp assertions, not their real creation time.

## State and rollback

install-trust persists the highest installed revision and its payload digest per root/audience in the replay database, even if all requests under that snapshot would be revoked. Same-revision different-content snapshots and lower revisions fail. Successful trusted dispatch also pins its snapshot within the reservation transaction. Trusted nonce identity uses root key + audience + nonce, so rotating an authority key does not reset it. The original low-level execute command retains its authority-key namespace.

A signed snapshot does not prove it is the latest. A standalone offline verifier relies on its independently supplied minimum_revision and freshness window. The runtime rejects rollback against its intact installed floor. State deletion, stale backups, separate state directories and root replacement can reset that knowledge; there is no external monotonic checkpoint. Back up and protect the whole database consistently.

A deployment requiring revocation must expose execute-trusted, not the legacy execute path. Both remain available for explicit local operator use. Neither API is a hostile-process sandbox. The root anchor, policy, host clock, executor key, operator account and state-directory ancestors are trusted. Same-user filesystem tampering is outside this boundary.

## v0.4 planned root rotation

Dual-signed root transitions preserve the original replay namespace and retire the previous root in the local trusted gate. See [RECOVERY.md](RECOVERY.md) for commands, backup limitations and compromised-root exclusions. Stateless verifiers require independently updated anchors.

## Admission and revocation semantics

Installing a newer trust snapshot governs subsequent nonce reservations. A job whose reservation already committed may finish using its captured snapshot; installation does not cancel it. If an operational change requires all earlier work to stop, halt admission and drain or reconcile active jobs before installing it. Root handover always requires stopped admission and drained jobs. Post-reservation snapshot checks enforce captured signatures and time windows, not a continuously reloaded revocation list.
