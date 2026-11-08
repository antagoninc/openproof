# External security review brief

Status: ready for private reviewer selection. No external review has been commissioned or completed for v0.9. An AI review must be labeled as such and cannot be reported as a human audit or certification.

## Engagement target

Review the exact source archive and its SHA-256 manifest. Report its digest with every finding. Original Rust execution-assurance prototype, version 0.9.0, with new signed document approvals, transactional receiver receipts and separate witness checkpoints. The proposed independent-operator pilot is described in OPERATORS.md. Experimental mTLS role services are implemented and tested locally; independent deployment has not occurred.

Primary scope: `crates/openproof-witness`, its use of `openproof-core`, `scripts/witness_workflow.py`, `scripts/witness_mcp.py`, `scripts/witness_client.py`, trust lifecycle, parsing, private key handling, SQLite state, crash behavior and verifier assumptions. Review other workspace crates where they cross these boundaries. Review existing tests skeptically rather than treating passing tests as security proof.

## Required questions

1. Can input without a valid, active, correctly bound approval mutate receiver state?
2. Can replay, conflicting nonces, concurrency or crashes create duplicate effects or misleading receipts?
3. Do duplicate fields, numeric representations, unknown fields, cross-domain signatures or noncanonical encodings bypass verification?
4. Can a package omit, reorder, replace or fork events while matching an independently supplied checkpoint?
5. What is trusted about clock, roots, revocation, checkpoint freshness, filesystem and database restoration? Are failures reported without overstating assurance?
6. Can agent-facing tools select credentials, paths, commands, approval authority or unintended destinations?
7. Are content disclosure, denial of service, oversized history, partial trust updates and expired retry behavior acceptable for the stated pilot?
8. Which properties fail when authority, receiver or witness is compromised separately? Identify assumptions, not only implementation defects.
9. What must change before authenticated remote operation and independent custody can be accepted?

## Reproduction

Build with `cargo build --workspace --locked`; run `cargo test --workspace --locked` and `cargo clippy --workspace --all-targets --locked -- -D warnings`. Python dependencies and validation workflow are documented in docs/BUILD.md and scripts/validate.py. Prior output summaries in this archive are historical evidence, not a fresh run on the reviewer's platform. Some scripts expect locally provisioned tooling; inspect prerequisites before running. Generate fresh test keys; do not use fixture public keys for production.

Fixtures are public synthetic evidence. They contain time-bounded trust, so current-time verification can reject old fixtures legitimately; use controlled test clocks in test APIs rather than disabling production freshness checks.

## Findings and deliverables

For each finding provide: affected source digest and file/line, trust boundary, realistic attacker prerequisite, reproducible test or minimal proof, observed versus expected behavior, impact and limitations, suggested correction, and regression test. Distinguish confirmed vulnerability, unconfirmed candidate, design limitation and informational observation. Do not imply absence of findings proves safety.

Deliver a coverage map, exclusions, test logs, prioritized findings and an independent retest of fixes. Preserve the original reviewed snapshot; fixes create a new digest. A different model should review without inheriting the implementer's conclusions, then independently run checks. Disclose provider/model/version, date, tools, human involvement and limits. AI-only review does not satisfy the external human review deployment gate.

## Handling and authorization

Local preparation is authorized. Recipient, private transfer channel, provider data-retention terms, budget and permission to send must be selected before sharing. No public repository, public issue, unsolicited reviewer message or paid engagement is authorized by this package. No proprietary Antagon code, models, data or credentials belong in scope. Do not send output directories, development private keys, environment files or databases.

Reviewer access is limited to the approved snapshot. Do not probe external infrastructure, use production credentials or test real users. Coordinate privately if a finding affects upstream software.

## v0.8 review additions

Include pages.rs, rotation.rs, the Go witness verifier, Docker build/pilot, page driver, owner dashboard and signed-build evidence. Review cross-page nonce/version/issuer state, pending-prefix resets, mixed trust epochs, six-signature equality, partial three-role handover, rollback/backup assumptions and historical packaging. The v0.8 reference initially covered stateless v1 packages; v0.9 added Go cross-epoch archive verification and integrated paged/rotated local homes. Verify the Docker runtime image excludes build-stage test state, private mounts are distinct, and shared host control is clearly disclosed. No AI review or local tests satisfy this human-review gate.

## v0.9 review additions

Review the local HTTP owner session, exact review tokens, CSP/text rendering, archived evidence exports, paged broker controller, interrupted key publication, Go cross-epoch archive reconstruction, historical versus current checkpoint times, mTLS fingerprint authorization and bounded operations. Review expired partial handover behavior and trusted-local-account assumptions. Test the normal browser flow and boundary failures, not only direct library calls. New local signed build evidence v2 also binds the Go artifact and supports v1 verification. A human review has not been commissioned; reviewer identity, budget, recipient/transfer authorization and independently administered hosts are still external prerequisites.

## Private preview review additions

Review `history_viewer.py`, `verify_history.py`, `assurance_lab.py`, `quickstart.py` and `package_external_review.py`. Distinguish inert unverified record display from a real Go verification result. Test hostile markup, path traversal, stale/future checkpoints, archive-local verifier substitution and accidental use of bundled trust. The recorded report is mutable and cannot become an attestation by being rendered in HTML. Demo approvals are simulated; the owner workspace requires separate review and execution.

Exercise process death after receiver commit followed by concurrent retries, monotonic review expiry despite wall-clock changes, and the expanded stateful fuzz operations. Review source-only packaging, exact source digest checks and the systemd template against the eventual host configuration. Template preparation is not evidence of deployment. Request fresh certificate lifecycle, host-abuse and recovery tests from the real operators.

The reviewer package now requires `--validation COMPLETED_VALIDATION_DIRECTORY` and rejects modified source or missing required checks. Its deterministic archive contains source and a bounded validation summary, not private runtime logs or state. Record the SHA256SUMS digest in the engagement and in every finding. Local build signature keys are development-only and must not become release trust anchors.

## Daily operations review additions

Review `certificate_lifecycle.py`, the role service's pre-connection and pre-operation generation checks, `recovery_center.py` and `Broker.commit(recover_only=True)`. Confirm missing receipts cannot dispatch, bad TLS generation data does not fall back to retired permissions, accepted connections cannot cross an authorization-generation change, and expired partial handovers remain paused. Inspect private directory/key permissions, activation compare-and-swap and flush boundaries, chain/hostname responsibilities, and local-time assumptions. Test owner HTTP authorization on the new routes.

Reproduce the benchmark and longer seeded process-crash campaign. Distinguish process boundaries from power-loss testing and largest-child RSS from aggregate memory. Review the actual independent-host CA renewal and retirement procedure before deployment. No new local tests satisfy the human-review gate.
