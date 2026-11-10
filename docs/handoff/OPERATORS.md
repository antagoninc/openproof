# Independent operator handoff

**Prepared locally. No independent hosts, operators or human reviewer enrolled.** Containers on one host remain controlled by that host administrator. Neither this package nor successful local tests establish organizational independence.

**Since 10 Nov 2026 the role service runs only on the same computer, on a Unix socket (`openproof-role serve`, [LOCAL-ROLES.md](../LOCAL-ROLES.md)).** The TLS steps below describe the remote role service at commit `51c0978` ([EXPERIMENTS.md](../EXPERIMENTS.md)). A remote deployment needs a reviewed remote transport first.

## Assign responsibility first

Copy `deployment/operator-record.example.json` into your private operational records. Receiver and witness need separately administered Linux hosts, separate role keys, separate TLS credentials and incident contacts. Record the reviewed source archive digest and actual identities. The authority signs approvals; the root custodian signs trust. Keep both keys off receiver and witness hosts. Agree on authenticated public-key and checkpoint exchange channels. Do not fill unknown fields with demo identities or claim acceptance while records are incomplete.

## Build and provision

1. Each operator obtains the same reviewed source archive and verifies SHA256SUMS through the agreed channel. Build `cargo build --workspace --locked` on each host. The current Python adapter expects `target/debug/openproof-witness` relative to the source tree; retain that path. Install Python dependencies in a private environment; do not copy the development environment or state.
2. Generate the role signing key on its destination host using `openproof-witness keygen`. Initialize its private state with `init`. Exchange only public keys. Verify fingerprints through the agreed channel. Pin the root with `role-pin`, then `install-signed` the root-signed trust. Enable paging on the receiver before use. See [authenticated services](../AUTHENTICATED-SERVICES.md) and `openproof-witness` usage for the exact supported commands; do not use the older unsigned trust pilot.
3. Provision operator-managed TLS certificates with the correct server DNS names/IP SANs, TLS private keys, the client CA and an explicit client certificate fingerprint allowlist. Test missing, unlisted, wrong-host and expired certificates. CA membership alone must not authorize a client. Decide expiry monitoring, renewal overlap and restart procedure before pilot acceptance; local staged TLS generation activation is available; CA issuance and remote lifecycle automation remain unimplemented.
4. Install source read-only under `/opt/openproof`, a Python environment at `/opt/openproof/venv`, private role state at `/var/lib/openproof/state`, and role/TLS configuration under `/etc/openproof`. The `openproof` service user needs read access to its role key and TLS key, and write access only to its state. Never provision root/authority keys to this account.
5. Review `deployment/systemd/openproof-role.service`. It is a template, not an installed or remotely tested service. Provide owner-controlled `/etc/openproof/role.env` with `ROLE=receiver` (or `witness`), `BIND_ADDRESS` set to the chosen private interface, and one exact `CLIENT_FINGERPRINT`. Multiple clients require explicit repeated arguments in the unit. Restrict port 8443 to the selected clients at the host/network firewall. Keep the owner UI loopback-only.
6. Before enabling supervision, run the service manually on the actual host. Confirm the root-pinned state and signed/plain trust agree. Run `systemd-analyze verify` on the final unit on that host. Then enable it using the operator's change procedure. Do not expose an admin endpoint or remote shell wrapper.
7. Provision the owner client by writing `service-client.json` in the owner home (see [LOCAL-ROLES.md](../LOCAL-ROLES.md) for the format the installer writes). It receives only authority credentials, public trust and TLS client credentials; it does not receive role/root signing keys. Confirm endpoint hostname verification remains enabled and redirects/proxies remain disabled.

## Acceptance evidence

Use synthetic documents, fresh destination keys and a disposable pilot database. Record toolchain, platform, source/binary hashes, timestamp, role identities, expected outcome, actual outcome and logs for each check:

| Exercise | Required observation |
|---|---|
| Approve, execute, verify | Exact content/version bound; independently obtained fresh checkpoint matches |
| Changed content / signer / receiver | Rejected without a document update |
| Simultaneous identical retries | One durable version and original receipt |
| Lost receiver reply | Recover the exact request; do not create a replacement authorization |
| Witness unavailable after commit | Committed but unwitnessed; catch up in sequence after recovery |
| Omitted/reordered/duplicated history | Rejected against the later trusted checkpoint |
| Server/client identity errors | TLS or allowlist rejection; no downgrade |
| Process stop and host restart | Recovery retains receipt, nonce and checkpoint state |
| Clock rollback / expiry | Fail closed or explicitly report stale/unknown; never backdate production verification |
| Backup restore | Stop admission, reconcile independently retained checkpoint; never silently accept rollback |
| Certificate renewal | Operator-reviewed rotation, authorized clients retained, retired certificate rejected |

Attach signed statements of separate control from both operators. Signature verification does not itself prove the statements true. Have the verifier obtain its genesis root and current checkpoint through its own authenticated channels. A bundled checkpoint is not an independent pin.

## Recovery and limits

Retain backups, public epoch records and trusted checkpoint floors. An uncertain effect is recovered with the original request. Local convenience rotation is disabled for remote homes; coordinate planned operator handover offline. Expired partial handover, emergency compromised-root recovery and live-state pruning remain unsupported operational gates. Stop admission and escalate instead of improvising rollback.

The receiver attests its database outcome; the witness records signed order. Neither proves model truth, physical effects or honest operators. The bounded single-threaded Python TLS server has not undergone production network-abuse testing. The unit's resource limits are provisional and must be measured on the selected hosts. Independent machine build reproduction and human review remain required before stronger claims.

## Current operational additions

Historical (kept at the git tag `experiments-2026-11-08`): Use [daily operations](../EXPERIMENTS.md) for receipt-only recovery, expiry inspection, staged TLS renewal, client retirement, longer crash campaigns and disclosed measurements. The existing systemd template uses manual TLS files; operators may replace its manual TLS flags with `--tls-bundle /etc/openproof/tls` after reviewing and provisioning private generations. Do not add both forms. Test service-user access and unit syntax on the actual Linux host. Benchmark before choosing limits, and capture independent-host certificate/connection retirement results in the acceptance record.

## Storage and retention acceptance additions

Historical (kept at the git tag `experiments-2026-11-08`): The owner selected local S3-compatible preparation only. A real provider/bucket/credential environment and permission for a synthetic upload are still required. Follow [storage pilot](../EXPERIMENTS.md) before any provider call; verify conditional creation, redirects/region behavior, checksum and read-back behavior on the actual service. Do not copy fixture credentials or imply the adapter signature is a provider signature.

Historical (kept at the git tag `experiments-2026-11-08`): Follow [archive retention](../EXPERIMENTS.md) to retain a verified public copy and separately pinned seal, leaving live databases intact. Record the real backup mechanism, permissions, newer independent checkpoint and restore result on an expendable separate host. No pruning, automatic restoration or trust reset is authorized by this package.
