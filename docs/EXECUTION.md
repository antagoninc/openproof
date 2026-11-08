# Local execution gate — v0.2

The runtime implements two bounded local capabilities: `artifact.write` persists the exact authorized input bytes; `artifact.sha256` persists their SHA-256 digest. It does not launch arbitrary processes, access the network, or provide a general agent sandbox.

```sh
cargo run --locked -p openproof-cli -- execution-demo outputs/my-execution
```

Use a new directory. The demo generates temporary role keys, executes a real local write, verifies its signed receipt against the output bytes, and checks that a duplicate dispatch is rejected. Keys are discarded. See execution.json, artifact-report.json, replay-report.json and state/jobs/ inside the demo directory.

Manual commands:

```text
init-state NEW_DIRECTORY
execute BUNDLE TRUSTED_CONTEXT POLICY ARGUMENTS EXECUTOR_SECRET STATE_DIRECTORY
state STATE_DIRECTORY
verify-artifact BUNDLE TRUSTED_CONTEXT OUTPUT
```

The gate reads arguments once, validates their exact byte hash, validates a separately trusted policy whose exact file bytes match the authorization digest, checks the role keys, and uses the host clock instead of context.now. Policy grants constrain tool, resource, argument size and authorization lifetime. Policy version is openproof-policy/1; see fuzz/corpus/policy/valid-policy for a synthetic shape.

SQLite stores a unique reservation keyed by authority key, audience and nonce, excluding run ID so reissuing the nonce for a different run cannot bypass this state directory. A BEGIN IMMEDIATE transaction commits the reservation before adapter work. WAL, synchronous=FULL, fullfsync and checkpoint_fullfsync are configured. This relies on the local filesystem and hardware honoring synchronization; power-loss durability has not been experimentally established.

State transitions are reserved → completed or indeterminate. Abrupt exit may leave reserved state. Both reserved and indeterminate stay consumed: never retry them automatically. This provides at-most-one dispatch attempt per nonce in this intact state directory, not exactly-once completion. A crash can consume authorization without producing an artifact. Independent state directories, rollback, deletion or restoration of stale state defeat this scope of replay prevention.

Keep the state directory private and on a trusted local filesystem. Symlinked/public state roots and absent databases are rejected. The operator, parent directories, host clock, trusted context, policy and private keys are trusted. An attacker with the same OS account or database-write authority is outside this boundary. There is no remote service or multi-tenant isolation.

Completed jobs contain output.bin, arguments.bin, policy.json, bundle.json and context.json. verify-artifact authenticates the evidence and compares supplied output bytes to the signed digest. It does not prove that an external system received an effect. Offline v1 reports still set replay_protection_enforced=false because they cannot inspect or attest the gate's state; the local execution result separately records its scoped enforcement.

Expired authorization or a clock reversal after writing leaves an indeterminate operation, not a fabricated success receipt. Authority/actor key rotation, revocation, hardware attestation and third-party witnessing remain future work.

References: [SQLite transactions](https://www.sqlite.org/lang_transaction.html), [WAL durability](https://www.sqlite.org/wal.html), [synchronization pragmas](https://www.sqlite.org/pragma.html).

## v0.3 trust layer

See [TRUST.md](TRUST.md) for root-signed snapshots, rotation/revocation, explicit historical verification and install-trust/execute-trusted. These supersede earlier statements that key lifecycle is entirely unimplemented. Legacy verification and execution remain available with their original narrower guarantees.
