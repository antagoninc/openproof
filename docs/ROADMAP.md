# Development roadmap

The goal is an advanced independent execution-assurance system. No superiority over TRACE is established. Future comparison requires a named version, reproducible corpus, and public evidence after owner-approved publication.

| Stage | Deliverable | Acceptance gate |
|---|---|---|
| 0 — current foundation | Original v1 schema, canonical bytes, signatures, exact authorization binding, receipt distinction, CLI | Local unit/integration tests, negative cases, known-answer vectors, documented limitations |
| 1 — protocol stabilization | Independent implementation, schema/code conformance corpus, property testing and fuzzing, immutable vectors, error taxonomy | Cross-language identical bytes/digests; sustained malformed-input campaigns; independent cryptographic protocol review |
| 2 — execution enforcement | Capability broker, exact argument byte capture, policy evaluation, atomic nonce consumption, crash-safe dispatch state | Race, crash/restart, TOCTOU, replay, and unauthorized dispatch tests; explicit fail-closed behavior |
| 3 — useful receipts | Real executor adapters, signed output/artifact manifests, externally witnessed effect receipts | A self-reported claim never reaches an externally corroborated assurance level; substitution/omission tests |
| 4 — key lifecycle and archive | Rotation, revocation, trusted timestamps, offline trust bundles, historical verification mode | Revoked/expired/mis-scoped keys and stale trust bundles handled under a documented policy |
| 5 — transparency and provenance | Merkle inclusion/consistency proofs, signed checkpoints, reproducible builds and dependency provenance | Equivocation and rollback tests; completeness limits stated precisely |
| 6 — hardware-backed evidence | Optional TDX/SEV-SNP/GPU attestation adapters with explicit measurement and freshness policy | Real hardware validation, collateral/revocation tests, independent review; no hardware trust claims from synthetic fixtures |
| 7 — assurance analysis | Evidence-backed claims with explicit support/contradiction/unknown states | Adversarial evaluation against independent labeled evidence; model confidence never replaces cryptographic verification |
| 8 — publication readiness | Naming/IP review, dependency license inventory, security contact, signed reproducible release, migration policy | Owner explicitly approves GitHub publication and each public release |

Near-term priorities: add a second implementation before freezing OPEC-1, durable replay enforcement before claiming single-use authorization, and a real executor before claiming observed execution. Benchmark throughput and memory on disclosed hardware; do not publish speculative numbers. No dates or unsupported performance promises are assigned.

## v0.2 progress

Protocol hardening now includes a separate Python verifier, fixed cross-language vectors, differential cases, property tests and bounded fuzz campaigns. External cryptographic review and sustained fuzzing are still open. Execution enforcement now covers two local artifact capabilities, exact-byte capture, policy grants, durable reservations and process-crash/race tests. General agent dispatch, third-party witnesses, key lifecycle, transparency and hardware-backed evidence remain open; stages 1–3 are partially implemented, not declared fully complete.

## v0.3 progress

Role-key rotation, conservative revocation, signed offline trust snapshots, installed revision floors, explicit historical verification, a separate-process deterministic agent pilot, CI configuration, advisory/license checks and unsigned local provenance are implemented. Root rotation, trusted timestamps, external witnesses, independent audit, hostile-agent isolation and cross-host build verification remain open. No hosted job or public release has been triggered.

## v0.4 progress

Planned root handover, preserved replay lineage, backwards-clock watermark, six crash boundaries, 94 trust differential vectors, diagnostics and a tamper-rejection demonstration are implemented. See outputs/v0.4/VALIDATION.md for measured checks. Independent AI review of all 12 crate files is complete; macOS and Linux validation both passed. External human review remains open. Compromised-root recovery, external backup rollback witnesses, hostile-process isolation, hardware power-loss validation and externally corroborated execution remain open.

## v0.5 progress

A Claude report adapter, restricted Docker actor, fixed-policy host broker, adversarial isolation probes and offline evidence viewer are implemented. The Rust executor remains bounded. Next gates include independent review of the new host/container boundary, deployment-specific key custody, sustained adversarial testing and external human review before production claims. No publication is implied.

## v0.6 delivered locally

Interactive approval of captured report bytes, offline portable evidence with separately supplied root, setup/readiness/history commands, explicit seccomp and cleanup checks, crash/timeout/interrupt tests, and shared fuzz/build dependency alignment. See DAILY-WORKFLOW.md for limitations. Next acceptance gates: independent review of these changes, operational long-lived key custody and fresh trust distribution, then a separately approved release.

## v0.7 local implementation

Implemented: Rust transactional document receiver, separately keyed witness and checkpoint verifier, ordered history/gap handling, persistent local key custody and trust floors, authority retirement/revocation, MCP propose/commit adapter, Python client and timeline, and version-pinned TRACE experiments. See WITNESSED-WORKFLOW.md for acceptance tests and limits. Independent operators, authenticated remote transport, HSM custody, holder-bound delegation, receiver/witness key migration and external human audit remain open. No superiority claim or publication is authorized by completion of local tests.

## v0.7.1 review fixes

Confirmed Claude findings F1/F2/F5 addressed through bounded transactional history admission, indexed approval lookup, read-only historical receipt recovery, ordered witness catch-up, checkpoint-prefix export, cross-process broker locks and unsigned-proposal lifecycle. Local regression validation is recorded in outputs/v0.7.1/VALIDATION.md. Remaining gates include a new independent retest, human audit, transport/custody review, pagination/migration and independent operators. Capacity exhaustion is an explicit admission stop, not an archival migration mechanism.

## v0.7.2 remaining review items

Signed witness trust with pinned roots and persistent verifier floors, local-only result labels, opaque MCP IDs/fixed errors, descriptor key reads and zeroized buffers, unambiguous trust lists, conservative signed-time clock recovery, verified checkpoint export, and approved/evidence storage budgets. See REVIEW-HARDENING.md for compatibility and unresolved deployment/design gates.

## v0.8 local implementation

Separate Go full-package verifier, bounded durable pages, six-party planned witness/root/receiver handover, Docker Linux role pilot, read-only owner dashboard, and signed local build evidence. See V08-OPERATIONS.md for explicit opt-in workflows and unsupported combinations. Next gates: independent operators and authenticated transport, human review of this exact source snapshot, emergency recovery/fork policy, cross-epoch broker migration, Go page/rotation support, physical store archival, and independent build reproduction. No public release is implied.

## v0.9 integrated local workspace

Implemented: session-protected local owner app; exact-content approval and retry; paged broker evidence; retained/resumable same-owner handover jobs; public-only archive export; Go archive verification across pages and rotations; experimental mTLS role endpoints; browser workflow, interruption/storage/corruption tests and a bounded stateful fuzz target. New local build evidence v2 additionally binds the Go executable and retains v1 verification support.

Open: independent host deployment/operators, fresh human review, sustained stateful fuzzing, expired partial handover reconciliation, physical power-loss testing, safe live-state pruning/migration, certificate lifecycle and independent-machine build reproduction. Local repeat-build comparison is not independent reproduction.

## Private preview improvements

One-command first-run setup, eight real synthetic tamper/retry experiments with an interactive recorded-results explorer, script-free archive viewer, separate offline verification report, crash-after-commit/concurrent-retry regression coverage, expanded stateful fuzz operations, reproducible validated-source reviewer packaging, current separate-host handoff, compatibility policy and controlled release checklist.

These are local implementation work, not evidence of external deployment or review. Independent hosts/operators, human review, independent build reproduction and explicit public publication approval remain open. See the current validation report for measured outcomes; do not infer those gates from passing CI.
