# Repeatable validation and build records

Run `python3 scripts/validate.py --out outputs/my-validation` using a new directory. It runs format, Clippy, all Rust tests, schema and differential checks, the real local agent pilot, declared-license policy checks, RustSec auditing and a release build. Python requirements: cryptography 46.0.3 and jsonschema 4.25.1. cargo-audit 0.22.2 must be in PATH or outputs/tooling/bin. --skip-audit explicitly marks that check skipped; it is not the default.

.github/workflows/validate.yml configures macOS/Linux CI with read-only repository permissions, pinned action commits and tool versions, and no publication step. The repository is prepared for private GitHub development. A configured job is not evidence of a passing hosted run; inspect the actual run result. Generated outputs are not uploaded by this workflow.

The dependency license gate accepts only listed exact declarations and records a permitted choice from each expression in scripts/license-policy.json. New expressions fail for review. This is a metadata policy check, not legal clearance or a scan of every vendored license file. Runtime dependencies retain their notices.

The build record includes an executable, source-manifest.json, Cargo.lock hash, toolchain, command and unsigned SLSA-format provenance.json. The script rejects source changes during validation. It does not claim a SLSA level: local provenance can be forged by an operator, the environment is not hermetic, and independent cross-host reproducibility is untested. No signing key or release upload is configured.

`python3 scripts/fuzz_campaign.py --seconds 180 --out outputs/my-fuzz` runs five address-sanitized targets with the isolated nightly/cargo-fuzz tools in outputs/tooling. It retains corpus, logs and crash artifacts. Bounded campaigns measure exercised inputs, not absence of vulnerabilities.

References: [RustSec](https://rustsec.org/) and [SLSA provenance](https://slsa.dev/spec/v1.2/provenance).

## v0.4 reliability validation

Validation also runs 94 retained Python/Rust trust vectors, `doctor`, and `assurance-demo`. Root transitions and actual backup restoration have Rust negative tests. Bounded fuzzing covers malformed root-transition payloads through the trust target. Keep the final source unchanged while the validation script captures provenance.

A local Linux check can run in a disposable container with only a copy of this public project mounted. Do not mount the user home, Docker socket, proprietary code, credentials or model stores. Record the image digest and retain Linux logs inside the project. Advisory checking may be explicitly skipped on Linux when the same final Cargo.lock was independently checked on macOS; state that scope in the results.

CI explicitly provisions Go 1.27.3 for the independent verifier and disables incremental Rust compilation to reduce cache growth. The local owner workspace and CI never require proprietary Antagon data or an external model API key.
