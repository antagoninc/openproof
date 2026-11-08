# Controlled public preview checklist

**This is a gate checklist for a versioned release.** Making the source repository public is a separate owner decision. No versioned release, package publication or deployment is performed by the validation workflow.

## Technical evidence

- [ ] Freeze a source snapshot; full validation, secret scan, dependency/license review and both hosted platforms pass on that exact revision.
- [ ] Record all toolchain versions, source manifest hash and build artifact hashes; explain skipped tests and platform differences.
- [ ] Run the first-run flow on a fresh clone, including offline rejection and untrusted-content rendering.
- [ ] Run bounded stateful fuzzing; retain duration, seed, executed sequence count and any minimized regressions. No coverage or absence-of-vulnerability claim from a zero-finding run.
- [ ] Build twice from clean inputs and obtain a reproduction from a genuinely separate machine/operator. Same-host matching bytes do not satisfy independence.
- [ ] Sign local build evidence using `scripts/release_evidence.py`; verify against an independently retained builder public key, builder identity and source-manifest digest. Local signing is not hosted SLSA attestation or an independent builder claim.
- [ ] Check [compatibility policy](COMPATIBILITY.md), exact supported formats and recovery limits.

## Review and operation

- [ ] Deliver the exact private snapshot to a selected human reviewer through an approved channel; record scope/exclusions, findings and independent retest.
- [ ] Complete separate-host operator acceptance and record separate control; Docker alone does not satisfy this gate.
- [ ] Confirm naming, dependency licensing, security contact and disclosure procedure. (Licensing of the source under Apache-2.0 was cleared by counsel on 8 Nov 2026.)
- [ ] Review all distributable files for secrets and confidential document content; exclude runtime outputs, test homes, private keys, sessions and databases. Do not upload whole validation directories.
- [ ] Release notes clearly state experimental scope, trusted actors, known limitations and what was actually tested.

## Owner decision

- [ ] Owner explicitly approves changing repository visibility (a separate decision from publishing a version).
- [ ] Owner explicitly approves the exact release revision, assets and claims.

All unchecked items remain open. Preparing a package, passing CI or obtaining AI feedback does not check the human-review, independent-operator or publication-approval boxes.
