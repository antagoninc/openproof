# Security policy

OpenProof 0.4 is an experimental local protocol implementation, not production security infrastructure. There are no supported public releases or published reporting endpoints yet. Keep any reports local and share privately with the project owner through an already authorized channel; never include production secrets or proprietary traces.

Review scope: parser ambiguity, canonical encoding collisions, signature verification, version/domain confusion, role-key trust, authorization/action/receipt binding, input bounds, timestamps, and CLI key-file handling. Read `docs/threatmodel.md` and `docs/PROTOCOL.md` before interpreting assurance.

A signature authenticates a statement. It does not prove honest execution. Same-context replay, attacker-controlled context, compromised trusted signers, policy interpretation, hardware attestation, remote transport, and output correctness are not solved by this prototype. These exclusions must remain visible in reports and integrations.

Security-sensitive changes require negative tests and updated protocol semantics. Never silently broaden accepted algorithms or versions. Do not publish a security claim based only on passing tests. Independent review, fuzzing, dependency advisory/license checks, and operational key handling are release prerequisites.

## Local execution scope

The v0.2 gate adds policy grants, captured argument bytes, local artifact execution and scoped nonce consumption. Review replay transactions, crash states, storage integrity and role separation. The original offline verifier remains stateless. See docs/EXECUTION.md for exact trust assumptions.

## v0.4 review scope

Review openproof-trust and runtime install_trust/execute_trusted for root pinning, snapshot freshness, conservative revocation, installed revision floors, role windows and replay across authority rotation. Legacy execute is a lower-level operator API and must not be exposed as a revocation-enforcing endpoint. See docs/TRUST.md for rollback and historical-time assumptions. Independent AI static review of all 12 crate files completed for v0.4 with no reportable findings under documented assumptions; see outputs/v0.4/security-review/report.md. External human review and deployment certification remain open.

## v0.5 adapter boundary

Historical, for an experiment (kept at the git tag `experiments-2026-11-08`): New Python host adapter and Docker worker require separate review from the completed v0.4 crates scan. The host broker owns the API key and executor authority. Worker has no host mounts/network and only its actor seed. Treat model output as untrusted plain report bytes; never interpret it as commands or filesystem destinations. See docs/ISOLATED-AGENT.md for actual enforcement, bounded probes, provider metadata limitations and static viewer freshness.
