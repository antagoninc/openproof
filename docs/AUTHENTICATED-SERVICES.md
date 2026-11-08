# Authenticated role transport · experimental

`role_service.py` exposes only bounded receiver or witness operations. Administrative key generation, trust changes, rotation, revocation and filesystem selection remain offline owner operations. It uses TLS 1.3, requires client certificates and additionally checks an explicit SHA-256 certificate fingerprint allowlist. A certificate from the configured CA is insufficient unless its fingerprint is allowed. Clients must verify the server certificate and hostname. These mechanisms follow Python's [SSLContext and client certificate verification documentation](https://docs.python.org/3/library/ssl.html).

```sh
outputs/local-venv/bin/python scripts/role_service.py \
  --role receiver --state RECEIVER_STATE --key RECEIVER_KEY \
  --trust TRUST.json --signed-trust SIGNED_TRUST.json \
  --cert SERVER_CERT.pem --tls-key SERVER_KEY.pem --ca CLIENT_CA.pem \
  --client-fingerprint ALLOWED_CLIENT_CERT_SHA256 --port 8443
```

Default bind is loopback. Non-loopback deployment requires the operator to select an interface explicitly. No non-loopback listener, public hostname or remote host was deployed by this milestone. The UI/broker can use an explicitly provisioned service-client home; the integration is tested against local TLS endpoints. It has not been deployed to independent hosts.

## Fixed API

All operations use POST, `application/json`, no chunked encoding, and at most 1 MiB of input. There are no caller-supplied commands, key paths or trust roots. Health/head access also requires client authentication. Errors do not expose internal paths or echo request bodies. An uncertain receiver response must be recovered using the exact original request.

| Role | Route | Body |
|---|---|---|
| Either | `/v1/head` | `{}` |
| Receiver | `/v1/receive` | `{"request": SIGNED_REQUEST}` |
| Receiver | `/v1/recover` | `{"request": SIGNED_REQUEST}` |
| Receiver | `/v1/receipt` | `{"sequence": 1}` |
| Receiver | `/v1/page` | `{"start": 1, "checkpoint": SIGNED_CHECKPOINT}` |
| Witness | `/v1/witness` | `{"receipt": SIGNED_RECEIPT}` |
| Witness | `/v1/checkpoint` | `{}` |

The transport's authenticated client is not the authorization authority: the Rust receiver still requires a valid bound approval. The witness still verifies the configured receiver signature. Trust is root-pinned locally before serving; the plain configuration must match its signed payload at startup and the runtime role enforces its installed configuration.

## What was exercised

The local test creates disposable one-hour fixture certificates, starts separately configured receiver/witness TLS endpoints, rejects missing and unlisted client identities, rejects a wrong-role operation and altered report, then checks receive/retry/recovery/witness behavior. Certificate generation lives only in test helpers; no development CA or private key belongs in a release.

## Independent operation remains an external gate

Deploy receiver and witness on separately administered hosts, provision distinct role/TLS keys, distribute root/checkpoint trust through an agreed channel, and define an operational response to stale/forked histories before claiming independent operation. Select operators and human reviewer first. Do not share private state from this project.

This server intentionally serializes requests, has a small connection backlog and five-second socket deadlines. It is a bounded prototype, not an internet-scale HTTP stack. Certificate lifecycle/revocation distribution, monitoring integration, network abuse testing, firewall policy, service supervision, HSM custody and an independently operated production pilot need deployment-specific engineering/review. The owner interface must stay local. Nothing in the TLS test demonstrates independence from the host administrator.

## Provision a service-backed owner home

Prepare the remote roles and enable paged receiver storage locally at those operators. Give the owner only its authority key, separately trusted public root, signed trust and mTLS client credentials. `scripts/role_transport.py --help` provisions a new owner home with no root, receiver or witness private key. The UI and broker route only fixed operations using `service-client.json`; agents cannot supply transport configuration. HTTPS hostname verification remains on, and redirects/proxies are disabled.

Configuration version `openproof-service-client/1` contains `receiver` and `witness` objects, each with `url`, `ca`, `cert` and `key` fields. URLs must be explicit HTTPS origins; certificate paths are trusted owner configuration. Additional authenticated read-only routes are `/v1/status`, `/v1/document`, `/v1/export` and `/v1/page-historical`. Historical export may use supplied old public trust only for a read; it never installs that trust or authorizes effects. Allowed clients have read access to the role's retained history.

Remote role administration is rejected by the client. Local convenience key rotation is disabled for service-backed homes; those operators must coordinate their own handover and public epoch-record distribution. Provisioning a client is not proof of separate administrators. The integration fixture verifies that the client has none of the root/receiver/witness private keys and still completes approval, execution, recovery and archive export.

## Operator-managed certificate lifecycle

The role service now also accepts `--tls-bundle PRIVATE_DIRECTORY` in place of the manual TLS arguments. See [daily operations](OPERATIONS.md) for staged generation activation, expiry inspection, client overlap/retirement and fail-closed reload behavior. Manual private TLS keys must now be owner-only. Local tests include server certificate replacement, stale activation rejection, reconnect on generation changes and recovery from invalid active configuration without restoring retired clients. These tests use local fixtures and do not establish remote deployment or CA lifecycle automation.
