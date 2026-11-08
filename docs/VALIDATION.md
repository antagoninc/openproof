# v0.9 recorded local validation

Recorded on **2026-11-08**, before GitHub import. This is a sanitized summary of local evidence, not a human audit, certificate, hosted CI result or production-readiness claim. The repository import updates documentation, exclusions and CI configuration; it does not change the tested Rust/Python/Go protocol implementation.

| Check | Recorded result |
|---|---|
| macOS Rust workspace | 117 tests; formatting and Clippy passed |
| Linux Rust workspace | 117 tests in each of two clean builds |
| Python workflows | 57 tests passed |
| Go unit tests | 3 passed |
| Differential cases | 224 evidence + 94 trust + 202 witness cases passed |
| Browser workflow | Desktop/mobile proposal, exact review, approval, execution and retry passed |
| Linux isolated-role pilot | 11 assertions passed |
| mTLS integration | Missing/unlisted identities and wrong-role operations rejected; service-backed owner execution/recovery/export passed |
| Fault handling | Interrupted handover process, damaged database, simulated evidence-write failure, altered/missing/reordered evidence and incorrect trust/checkpoint tested |
| Bounded fuzzing | 4,390,141 executions across five campaigns, no crash artifacts; only 78 stateful sequences |
| Linux repeat build | Byte-identical witness executable using the same host and pinned image, with build cache disabled on repeat |
| Local build statements | v2 signature verification and backwards v1 verification passed |

The final local source-manifest digest was `8a7d36c0cf8fc5a25c67b06b019b015397674d7481ea1293120c91f78716903b`. This refers to the pre-import local snapshot, not the later Git commit. Original logs and runtime artifacts remain local and are not uploaded. Reproduce current checks with the commands in [BUILD.md](BUILD.md).

## Limits

- The Go experiment used the locally installed Go 1.20.3 toolchain. Hosted CI is separately configured with Go 1.27.3. A current Go vulnerability audit was not part of the recorded milestone.
- TLS tests used local endpoints and disposable certificates. No independently administered receiver/witness hosts were deployed.
- The repeat build used one machine and one pinned image. Independent-machine reproduction remains open.
- The fuzz campaigns were short; stateful coverage was especially limited. They preceded final metadata/documentation freezing and are not an exact-build coverage attestation.
- The UI displays recorded local assessments. The Go archive verifier requires independently provisioned root/checkpoint inputs and does not maintain a second persistent rollback database.
- Planned local handover is not compromise recovery. An expired partial handover remains paused for operator reconciliation.
- Human review of the current milestone has not been commissioned. No superiority over TRACE, SLSA level or physical-world execution proof is claimed.

An initial build/validation attempt was interrupted by disk exhaustion. Generated build caches were cleared, Docker was recovered without a data reset, and the final full validation and guarded repeat build passed. Failed attempts were not counted.

Fixed test seeds are intentional public fixtures. Generated private keys, model credentials, databases, browser sessions, private reviewer archives and raw output directories are excluded from Git.

## Private repository import checks

Gitleaks 8.30.1 initially identified 385 occurrences of four fixed public Ed25519 fixture keys. Three derive from deliberately public repeated-byte test seeds; the fourth is the RFC 8032 known-answer public key already exercised in the Rust tests. `.gitleaks.toml` retains default rules and narrows exceptions to those exact values and fixture paths. The selected source is rescanned before upload. No raw output directory, generated signing key, database or browser session is part of the commit.
