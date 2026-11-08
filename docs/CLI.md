# CLI and manual signing workflow

Run `cargo run --locked -p openproof-cli -- --help`, or after building use `target/debug/openproof` / `target/release/openproof`.

| Command | Behavior |
|---|---|
| `keygen SECRET PUBLIC` | Generate Ed25519 seed from OS randomness; write hex seed and public key to new files |
| `sign KIND INPUT SECRET OUTPUT` | Strictly parse and validate a payload; sign with a 32-byte hex seed file |
| `canonical KIND INPUT OUTPUT` | Write exact domain-separated signing bytes |
| `digest KIND INPUT` | Print SHA-256 of signing bytes |
| `verify BUNDLE TRUSTED_CONTEXT` | Offline verification; JSON report on stdout |
| `demo NEW_DIRECTORY` | Synthetic authorization/claim/receipt plus context and report; no actual execution |

KIND is `authorization`, `action`, or `receipt`. Outputs refuse to overwrite existing files. Paths are operator-selected and relative paths resolve from the working directory. This is a local command-line application, not a file-access sandbox or remote service. Errors go to stderr and exit 1; accepted commands exit 0. A successful verification can report a failed execution or a claim without a receipt; examine `assurance`.

## Sign your own synthetic chain

1. Generate three role keypairs into a private directory with `keygen authority.secret authority.public`, then actor and executor. Secret creation uses mode 0600 on Unix and is refused on non-Unix. Key files are unencrypted. Never put production keys in this prototype. `keygen` creates two files sequentially; an error on the second can leave the first. It never overwrites or rolls back unrelated files.
2. Start from `examples/authorization.json`, insert the actor public key, choose meaningful synthetic run/nonce/audience, exact action hashes, and time window. Sign it using `sign authorization ...`.
3. Run `digest authorization ...` and put the result in `examples/action.json`'s `authorization_sha256`. Keep the identical action. Sign with the actor key.
4. Run `digest action ...` and put that result into a receipt's `action_sha256`. Sign the receipt with the executor key.
5. Assemble the three signed JSON envelopes under `authorization`, `action`, and `receipt`. A missing receipt is permitted. The CLI deliberately does not execute tools.
6. Independently create a context with pinned role public keys, expected action, policy digest, run/nonce/audience, and trusted current time. Verify with `verify BUNDLE CONTEXT`.

Example templates contain dummy hashes and a public test key. They are shapes to edit, not production authorizations. Each `sign` validates only its individual payload; `verify` checks the complete chain. Key-file ownership/permissions are not checked on import, and complete secret-memory erasure is not guaranteed (input hex buffers exist).

For a no-edit walkthrough, use `demo` instead. Its context accompanies synthetic test evidence only; supplying attacker-chosen evidence and attacker-chosen context to a verifier provides no useful trust.

## v0.2 execution commands

See [the execution guide](EXECUTION.md) for init-state, state, execute, execution-demo and verify-artifact. These add real bounded local artifact execution; the original demo remains synthetic.

## v0.3 trust layer

See [TRUST.md](TRUST.md) for root-signed snapshots, rotation/revocation, explicit historical verification and install-trust/execute-trusted. These supersede earlier statements that key lifecycle is entirely unimplemented. Legacy verification and execution remain available with their original narrower guarantees.

## v0.4 commands

- `doctor [STATE]`: local environment or readable state diagnostics; uncertain jobs are reported, not retried.
- `assurance-demo NEW_DIRECTORY`: authorization, actual artifact execution, signed receipt verification, replay and tamper rejection.
- `sign-root-transition INPUT SECRET OUTPUT`: sign a planned transition.
- `rotate-root STATE OLD_SIGNED NEW_SIGNED OLD_ANCHOR NEW_SNAPSHOT`: atomically hand over and print the next anchor; stop admission first.
- `verify-trusted-at BUNDLE CONTEXT SNAPSHOT ANCHOR current|historical TRUSTED_UNIX_TIME`: reproducible offline evaluation at an operator-supplied time. This does not establish wall-clock freshness; use `verify-trusted` for the host clock.
