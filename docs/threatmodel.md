# OpenProof v0.1 threat model

## Overview

Scope is the local Cargo workspace. User requirements: independently authored execution assurance, no proprietary Antagon material, all project artifacts local on the Desktop, and no publication without explicit approval. This is a design model, not a vulnerability audit or proof of security. A separate read-only architecture pass reviewed the two crates; the author reconciled its observations with the implementation.

| Component | Flow and inspected source |
|---|---|
| Typed evidence | Authorization, action, receipt, and bundle: `crates/openproof-core/src/lib.rs:29`, `:36`, `:49`, `:63`, `:78` |
| Verifier-owned context | External keys, expected scope, run identity, and time: `crates/openproof-core/src/lib.rs:86` |
| Encoding and signing | Typed parse → canonical bytes → domain prefix → signature/digest: `crates/openproof-core/src/lib.rs:112`, `:139`, `:251`, `:257`, `:260` |
| Verification | Strict signatures and full chain/context checks: `crates/openproof-core/src/lib.rs:264`, `:270` |
| Local CLI | Argument dispatch, bounded file input, new-file output: `crates/openproof-cli/src/main.rs:11`, `:21`, `:56` |

The authority signs scope; the actor signs a claim bound to it; an optional distinct-key executor signs a reported outcome bound to the claim. No actual executor or external service is part of this version.

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
|---|---|---|---|---|---|---|
| Local key generation | Secret seed and public key files | Explicit CLI paths; relative to current directory | User-selected local files | Operator and host principals permitted by filesystem | New files only; secret mode 0600 on Unix; no non-Unix secret creation | CLI `write`, line 21; pair creation is not transactional |
| Local signing | Existing hex secret seed | Explicit seed file argument | User-selected local file, decoded into process memory | Signing process | Bounded read; 32-byte decoded key; individual payload validation | CLI `key`, line 41; no ownership/mode check or guaranteed full memory erasure |
| Offline verification | Bundle and trusted context | Two explicit input paths, no fallback or environment override | User-selected local files | Verifier process; report on stdout | Bounded typed parsing; external keys and expected scope | CLI `run`, line 56; context provenance is caller responsibility |
| Canonical/digest export | Signing bytes / digest | Explicit kind and payload file | New output file / stdout | Operator | Typed evidence validation and domain separation | Core `signing_bytes`, line 251 |
| Synthetic demo | Public synthetic evidence and context | Explicit new directory | bundle.json, context.json, report.json | Operator | Fresh directory; in-memory generated keys discarded | CLI `demo`, line 70; no real execution |
| Library integration | In-memory evidence and policy inputs | Explicit function arguments | Caller process | Calling application | Library parse size cap; output-size check after canonicalization allocation | Core lines 112, 139, 270; no universal allocation cap or process sandbox |

## Threat Model, Trust Boundaries, and Assumptions

Assets: signing-key secrecy, authenticity of scoped authorization, integrity of evidence links, correct interpretation of assurance, and local output integrity. The adversary may craft, alter, reorder, truncate, splice, omit, or replay bundle bytes and may hold its own unrelated signing keys. It does not initially control trusted context, valid role private keys, the verifier binary, or the operator's account.

Boundary 1: untrusted bytes → typed objects. Unknown/duplicate fields, malformed JSON, unsupported versions, invalid evidence text, noncanonical hex, and invalid keys must fail. The CLI bounds reads; library callers should use typed `parse`, not a permissive Value parser that discards duplicates first.

Boundary 2: statements → verifier decisions. The verifier chooses trust keys and expected action independently. Authorization must match exact run/nonce/audience/policy/action, action must reference that authorization, and receipt must reference that action. An embedded arbitrary key is never sufficient authority. The signed actor key must match the external actor key.

Boundary 3: signature → assurance interpretation. A successful signature verifies a statement, not its truth. A receipt requires a key different from actor and authority, but that does not establish different operators, honest observation, trusted hardware, or actual effects. Receipt removal lowers assurance; consumers must reject lower levels if receipts are mandatory. Output hashes are signed assertions, not checked artifacts.

Boundary 4: CLI → local filesystem. The caller already has local filesystem authority and chooses paths. There is no remote user or directory confinement. New-file creation prevents overwrites; parent-directory trust and filesystem permissions remain host responsibilities. Multi-file generation may leave partial outputs on failure.

Assumptions and exclusions: verifier context is authentic, clock is supplied honestly, role keys are provisioned securely, and integrators hash the intended exact policy/argument bytes. No persistent replay state, revocation service, policy engine, execution broker, hardware attestation, trusted timestamp, external-effect witness, or model correctness evaluator exists. Authority and actor separation is not required. Verifying the same context again succeeds. Expired evidence cannot be verified in an archival mode. No network/runtime publication path exists; build dependency installation is separate and may use the registry.

## Attack Surface, Mitigations, and Attacker Stories

These are design scenarios and residual risks, not confirmed vulnerability findings.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
|---|---|---|---|---|---|---|
| High | Substitute action/resource/argument scope | Untrusted bundle control | Accept unauthorized scope | Exact expected action and chained digests | Preserve these invariants; adversarial tests | Core `verify`, line 270 |
| High | Forge a trusted actor or authority | Attacker has own keys, not trusted keys | False authorization | Externally pinned keys, strict verification, weak-key rejection | Review key distribution and revocation before deployment | Core `public_key`, line 210; `verify_signature`, line 264 |
| High | Replace verifier context with attacker keys/scope | Deployment accepts producer-controlled context | Vacuous verification | Library labels context trusted; CLI makes no provenance assertion | Provision context through a trusted independent channel | Core `Context`, line 86; CLI `run`, line 56 |
| High | Interpret a self-report as proof of effects | Consumer ignores assurance semantics | Unsafe downstream decisions | Distinct assurance values; effects flag always false | Require independently witnessed effects in a future adapter | Core `Report`, line 105; `verify`, line 270 |
| High | Replay valid evidence for another dispatch | Integrator treats verification as a single-use execution gate | Duplicate effects | Wrong context rejected; same-context replay deliberately allowed | Atomic durable nonce consumption and dispatch broker before enforcement use | Core `verify`, line 270 |
| Medium | Alternate encoding changes signed meaning | Crafted JSON or cross-language implementation disagreement | Signature/content ambiguity | Typed parsing, deterministic length framing, fixed domain/version | Independent implementation, fuzzing, schema conformance | Core lines 112, 139, 251 |
| Medium | Exhaust resources with malformed input | Access to library or CLI input | Local denial of service | 1 MiB file/parser bound and default JSON recursion limit | Add service-level budgets if exposed remotely; fuzz parser | CLI `read`, line 11; core `parse`, line 112 |
| Medium | Steal seed from host/file/memory | Host access or unsafe key provisioning | Sign as trusted role | Unix 0600 on creation; no key stdout | Use secure key storage before production; avoid secret-bearing logs | CLI `write`, line 21; `key`, line 41 |
| Low | Generate partial output on disk/full or second-file conflict | Local I/O failure | Operational confusion | No existing files overwritten; errors returned | Inspect output state; transactional generation is future work | CLI `write`, line 21 |

## Severity Calibration (Critical, High, Medium, Low)

Critical would require broad unauthorized privileged execution across a deployed enforcement boundary. No such execution service exists here, so a critical remote-execution claim is unsupported by this architecture alone.

High examples: accepting attacker-signed authorization as a pinned authority, accepting a different action under valid authorization, or an integration performing privileged actions from producer-controlled context. A compromised trusted signer or dishonest receipt producer is a stated trust failure, not evidence of a cryptographic bypass.

Medium examples: a reachable malformed input crashes a deployed verifier, or an adapter silently changes argument bytes while preserving a misleading scope claim. The present bounded local parser and absence of an adapter reduce those specific exposures; future deployment assumptions must be demonstrated.

Low examples: confusing errors or partial new output files requiring local cleanup. Ordinary operator-selected file paths are not an arbitrary-file-write vulnerability without a less-privileged attacker reaching that interface.

Confidence is limited to source review and local test evidence. No fuzz campaign, independent crypto audit, dependency vulnerability scan, production deployment assessment, or hardware verification has been performed. Future security findings require separate validation against the relevant version and deployment.

## v0.2 runtime addendum — supersedes earlier absence of execution/state

The runtime architecture is implemented in crates/openproof-runtime/src/lib.rs: init_state creates private SQLite state; execute_inner validates signatures, captured arguments, exact policy bytes and live host time, commits a nonce reservation, writes a bounded artifact, signs a receipt, then records completion. connect rejects missing/symlinked/public state roots; records exposes consumed states. CLI run exposes execute, execution-demo, state and verify-artifact.

New boundary: untrusted signed request and raw argument bytes enter a trusted gate configured by an operator-owned context, policy, executor key and state directory. A hostile request must not change arguments, invoke an ungranted capability, reuse a nonce, or replace an artifact without failing validation. SQLite serializes reservations across processes; no automatic recovery retries are permitted. State deletion/rollback, same-user modification, untrusted parent directories, compromised keys/clock and lying storage are outside the enforced boundary. No network or arbitrary subprocess adapter exists.

Process-exit, race, tampering and policy-denial tests exercise these controls. Power-cut durability is not tested. A local receipt is an executor statement plus an artifact hash, not independent external witnessing. The architecture review for this update was performed sequentially by the implementation author after an attempted independent reviewer was unavailable; this is not an independent audit. See EXECUTION.md for effective files and crash semantics.

## v0.3 trust boundary addendum

crates/openproof-trust/src/lib.rs owns TrustBundle validation, validate_snapshot and verify_trusted. The operator-provisioned Anchor pins the root, audience and minimum revision. Signer role windows and a fresh signed snapshot are required. Revocation effective by the evaluation time rejects both current and historical evidence; past timestamps are assertions without external timestamps.

crates/openproof-runtime/src/lib.rs owns install_trust and pin_snapshot. The latter persists the highest root/audience revision and rejects same-revision different digests inside a SQLite transaction. execute_trusted checks trust before reservation, after lock acquisition, before adapter work and before accepting the receipt. Its nonce namespace uses the root key, preserving consumed nonces across authority-key rotation. State rollback, deletion, root replacement and separate directories remain outside this monotonicity guarantee.

CLI install-trust writes an authenticated floor without dispatch. The same-account operator still controls key files, anchors and paths. The legacy execute API deliberately bypasses trust snapshots and is not a revocation-enforcing endpoint. examples/agent/worker.py receives only actor signing input from the supervisor but runs under the same OS account; it is not an isolated hostile process. .github/workflows/validate.yml has read-only permissions and no publication step. scripts/validate.py emits unsigned local provenance, not trusted build attestation. Independent security review for this change is incomplete because the managed scanner failed during setup.

## v0.4 boundary additions

Planned root rotation requires signatures from both roots and an advancing installed revision; it preserves original replay identity and retires old roots locally. A compromised old root is outside this handover guarantee. Trusted operations persist a clock watermark, but state restoration and privileged clock manipulation require external controls. Process-crash tests do not establish hardware durability. The Python trust verifier is a separate implementation and not an independent security review.

## v0.5 isolated report workflow

Historical, for an experiment (kept at the git tag `experiments-2026-11-08`): The host claude_report adapter sends only a fixed public prompt to the fixed HTTPS Messages endpoint. It uses the host environment credential, bounded output, verified TLS and no redirects/tools/automatic retries. The trusted host broker signs only a bounded fixed-resource report operation. A local Docker actor receives public authorization, exact report bytes and an ephemeral actor seed over stdin. No mounts or network are available; default seccomp, dropped capabilities, non-root UID, no-new-privileges and resource bounds are configured and inspected. Host keys/state remain trusted and outside the worker. Docker/kernel escape resistance is not established by the probes. The model is external, not running inside the container. The offline HTML viewer checks evidence at render time and escapes untrusted text; its supplied anchor and static age must be understood. This new boundary is outside the v0.4 Rust-only independent review.
