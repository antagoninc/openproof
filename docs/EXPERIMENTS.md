# Experiments kept in history

The repository now holds the trusted path and the code that checks it. The
experiments that used to sit beside it are kept, unchanged and runnable, at
the git tag **`experiments-2026-11-08`**. Check out that tag to use them; they
run against the code of that revision, not against the current binary.

| Experiment | Files at the tag |
|---|---|
| Python owner app, broker and MCP adapter (replaced by `openproof-witness owner-app`, the Rust broker and `openproof-witness mcp`) | `scripts/owner_app.py`, `scripts/witness_mcp.py`, `scripts/recovery_center.py` |
| Python mTLS role service and certificate generations (replaced by `openproof-witness serve-role`, then by `openproof-role serve`) | `scripts/role_service.py`, `scripts/role_transport.py`, `scripts/certificate_lifecycle.py`, `deployment/` |
| Planned key handover from the owner app | `scripts/owner_rotation.py`, `scripts/prepare_rotation.py` |
| S3 storage pilot and archive retention | `scripts/storage_adapter.py`, `scripts/storage_demo.py`, `scripts/archive_store.py` |
| Isolated report agent and container worker | `isolation/`, `scripts/isolated_agent.py`, `scripts/isolation_runner.py`, `scripts/claude_report.py` |
| Comparisons, labs, benchmarks and viewers | `scripts/compare_*.py`, `scripts/assurance_lab.py`, `scripts/operations_benchmark.py`, `scripts/history_viewer.py`, `scripts/render_evidence.py` |
| v1 action-bundle CLI wrapper | `scripts/openproof.py`, `scripts/approval.py`, `scripts/portable.py` |

The Rust `experimental` feature (`rotation.rs`, `storage.rs`, and its commands
in `openproof-tool`) stays in this tree, off by default, so the format code
keeps building and being tested.

The Rust role service over TLS 1.3 with pinned client certificates
(`openproof-witness serve-role`, `serve.rs`, `transport.rs`, the certificate
generation in `scripts/local_roles.py` and `scripts/tests/tls_fixtures.py`) was
replaced on 10 Nov 2026 by `openproof-role serve` on a Unix socket. It is at
commit `51c0978`, the parent of that change. It was the only way to run a role
service on another host; that now needs a reviewed remote transport.

No guarantee depends on anything listed here.
