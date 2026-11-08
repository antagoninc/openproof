# OpenProof evidence protocol 1 (experimental)

The JSON schema is original to this project. Payload `version` is exactly `openproof/1`. Schema IDs are `urn:antagon-openproof:schema:1`. Unknown versions fail closed; changes to signing semantics require a new version and domain. No compatibility with TRACE is implied.

## Types and meaning

`Authorization` binds `run_id`, `nonce`, `audience`, `actor_key`, `policy_sha256`, an exact `ActionSpec`, and inclusive `not_before`/`expires_at` integer Unix seconds. `ActionSpec` binds exact UTF-8 tool/resource strings and a SHA-256 digest of the exact argument bytes. Integrators define and preserve those bytes; this library does not interpret or fetch them. `policy_sha256` identifies policy bytes; it does not evaluate policy or assert its safety.

`Action` binds the domain-separated authorization payload digest, the same exact action, and `claimed_at`. It is an actor's claim, not a dispatch log or an execution receipt. `Receipt` binds the action payload digest, `observed_at`, `succeeded|failed`, and `output_sha256`. Output digest is an executor's statement; output bytes are not supplied to or checked by this verifier.

`Signed<T>` contains only `payload` and lowercase-hex `signature`. There is no evidence-selected algorithm, public key, or key lookup URL. Role keys are supplied separately by the verifier. `Bundle` contains signed authorization, signed action, and optional receipt (missing or JSON null both mean absent). A bundle itself is not signed; removing its receipt deliberately reduces assurance to a claim. Consumers requiring receipts must reject that report level.

All typed objects reject unknown and duplicate fields, including nested objects. JSON trailing data, invalid UTF-8, lone surrogates, and invalid numeric types fail parsing. Counts/times are u64, not floating point; decimals and negative values in time fields are rejected. Nonempty text fields have a maximum of 1,024 UTF-8 bytes and forbid Unicode control characters. Digests/keys are exactly 64 lowercase hex characters, signatures exactly 128. JSON Schema describes shape; Rust validation additionally enforces byte limits, key validity, cross-field equality, timestamps, and signatures. JSON Schema cannot detect duplicate source keys after a parser discards them. Use the Rust typed parser at the trust boundary.

CLI input files and `parse` input are limited to 1 MiB. Serde's default nesting limit remains enabled. The generic in-memory canonicalizer checks its output size after construction, so it is not a universal allocation budget for arbitrary library callers.

## OPEC-1 canonical bytes

OPEC-1 is a deliberately small, original binary encoding of the typed JSON data model. It is **not RFC 8785/JCS**. The library first serializes a typed payload into a JSON value; it never canonicalizes arbitrary unvalidated JSON source for signing.

Start with hexadecimal `4f50454301` (`OPEC`, byte 1), then encode one value:

| Value | Encoding |
|---|---|
| null | byte `00` |
| false / true | byte `01` / `02` |
| u64 integer | byte `03` followed by eight-byte unsigned big-endian integer |
| string | byte `04`, eight-byte big-endian UTF-8 byte count, then exact UTF-8 bytes |
| array | byte `05`, eight-byte big-endian item count, then each encoded item |
| object | byte `06`, eight-byte big-endian property count; for each entry, encoded string key then encoded value |

Object keys sort lexicographically by unsigned UTF-8 bytes. Arrays preserve order. No Unicode normalization occurs; composed and decomposed strings remain distinct. Floats and negative numbers are unsupported. There are no separators or terminators beyond the length frames. No whitespace or JSON escape choices survive typed parsing.

Known vectors (complete OPEC bytes):

- null: `4f5045430100`
- string `a`: `4f5045430104000000000000000161`
- integer 1: `4f50454301030000000000000001`
- object `{"b":true,"a":null}`: `4f5045430106000000000000000204000000000000000161000400000000000000016202`

## Signatures and digests

Signing preimage = ASCII `OpenProof/v1/` + evidence domain + NUL byte + OPEC-1 payload bytes. Domains are exactly `authorization`, `action`, `receipt`. The version and domain are authenticated. Ed25519 (ordinary Ed25519, not Ed25519ph) signs the entire preimage using ed25519-dalek 2.2. Verification uses `verify_strict` and rejects weak public keys. No alternative algorithms or legacy fallback exist.

Reference digest = lowercase hex SHA-256 of that same full signing preimage, excluding the signature envelope. Thus action → authorization → scope and receipt → action → authorization form a bound chain. This is not a Merkle tree, consensus protocol, transparency log, or proof of completeness.

The CLI `canonical` command writes the **complete domain-separated signing preimage**. The library `canonical` function returns only the OPEC-1 bytes; `signing_bytes` returns the complete preimage.

## Verification order and trust

1. Verify authorization against the externally trusted authority key.
2. Require its actor key to equal the externally expected actor key; verify action with that key.
3. Match expected run, nonce, audience, policy digest, and exact action scope.
4. Check action's authorization digest and `not_before <= now <= expires_at`; require `not_before <= claimed_at <= now`.
5. If receipt exists, require the executor key to differ from both other role keys, verify its signature, match its action digest, and require `claimed_at <= observed_at <= now`.
6. Return `authorized_claim_only`, `executor_reported_success`, or `executor_reported_failure`. External effects and replay enforcement remain false.

`now` is verifier-provided; no machine clock is read. This verifier checks currently valid authorization, not archival historical validity after expiration. There is no trusted timestamp authority. Different keys do not prove different administrators or honest observers. The authority and actor can share a key; integrations wanting role separation must enforce that separately.

No persistent nonce consumption exists. Wrong-context replay is rejected, but the same bundle and context can verify repeatedly. A future execution gate needs atomic durable nonce consumption and dispatch binding. All context fields, clock, key distribution, key revocation, private-key custody, expected policy/action bytes, and acceptance thresholds are caller responsibilities.

## References used, not copied implementations

- [ed25519-dalek 2.2 documentation](https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/) for cryptographic API usage.
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) for the standard Ed25519 known-answer test.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) as background on canonicalization; OpenProof does not implement it.

## v0.2 runtime layer

The v1 signed format is unchanged. The offline verifier remains stateless. The new local execution gate enforces policy and consumes nonces in its own persistent SQLite directory; see EXECUTION.md. Its local enforcement result is distinct from an offline assurance report.

## v0.3 trust layer

See [TRUST.md](TRUST.md) for root-signed snapshots, rotation/revocation, explicit historical verification and install-trust/execute-trusted. These supersede earlier statements that key lifecycle is entirely unimplemented. Legacy verification and execution remain available with their original narrower guarantees.

## Root handover extension (v0.4)

`openproof-root-transition/1` is an original separate evidence payload with `version`, `audience`, `old_root`, `new_root`, `next_revision`, `not_before`, and `expires_at`. Its signature preimage is `OpenProof/v1/root-transition\0` followed by the existing OPEC-1 canonical payload. Both signatures must cover exactly the same payload, verified under the pinned old root and named new root. Neither a snapshot signature nor an action signature can substitute. The revision must advance both the independently pinned minimum and the installed state floor. The successor snapshot must have exactly that revision. The schema is `schemas/openproof-root-transition-v1.schema.json`; signature envelopes retain the existing `payload`/`signature` form. Cross-field, UTF-8 byte bounds and cryptographic validation remain authoritative in code, beyond what the descriptive JSON schema checks.

The runtime preserves the original root's replay namespace across each planned handover and locally retires predecessors. Fresh state or a restored database cannot inherit missing history automatically. See RECOVERY.md before rotation or restoration.
