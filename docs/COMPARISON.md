# Evidence-based TRACE comparison

OpenProof does not claim security or performance superiority over TRACE. The relevant comparison target is AgenTrust TRACE, not an unrelated product with the same name.

## Reproducible shared-property checks

`scripts/compare_properties.py` uses an isolated, version-pinned `agentrust-trace==0.11.0` environment and the current Rust storage authorization verifier. It checks valid input, modified signed data, incorrect independently supplied keys, corrupt signatures, expired windows and future windows. The approval dispatch window and TRACE record-age policy have different semantics; passing analogous checks does not make the evidence formats interchangeable.

```sh
outputs/local-venv/bin/python scripts/compare_properties.py \
  --trace-python PATH_TO_PINNED_TRACE_ENV/bin/python --out outputs/NEW_COMPARISON
```

Use `scripts/trace-comparison-requirements.txt` in a separate environment. Do not install its different cryptography dependencies into the main OpenProof environment. The report records the TRACE version, comparison script hash and Rust binary hash. It makes no timing or memory ranking. The older `compare_trace.py` is retained as a historical workload experiment; its records and language-runtime costs differ and its measurements are not an overall performance comparison.

## Scope and evidence tiers

| Topic | OpenProof evidence | TRACE evidence | Comparison status |
|---|---|---|---|
| Basic signature/key/tamper checks | Executed local tests | Executed SDK 0.11.0 tests | Comparable acceptance properties within stated fixtures |
| Approval, bounded effect and recovery | Local document workflow; new loopback storage pilot | Broader runtime integrations described in upstream docs | No end-to-end comparative result |
| Hardware attestation | No validated hardware adapter | Upstream documents hardware bindings and associated runtime verification | Not reproduced here; do not mark absent |
| Independent witnessing | Operators still unassigned | Upstream reports an independently countersigned checkpoint with limits | Not reproduced here; no continuity claim inferred |
| Revocation and offline trust | Root-pinned local trust and explicit checkpoint freshness for document history | SDK API includes revocation and signed-bundle options | Not fully compared by this suite |
| Real provider/runtime deployment | No real S3 interoperability claim | Not evaluated by our SDK-only experiment | Unassessed |

Upstream references reviewed on 2026-11-08: [TRACE repository](https://github.com/agentrust-io/trace-spec), [roadmap](https://github.com/agentrust-io/trace-spec/blob/main/ROADMAP.md), [verification documentation](https://trace.agentrust-io.com/docs/verification/), and [limitations](https://github.com/agentrust-io/trace-spec/blob/main/LIMITATIONS.md). Documentation and published SDK behavior may differ; the executed version is the authority for test results. Described capabilities are not independent reproductions.

A future fair end-to-end evaluation needs a pinned TRACE runtime—not only its record library—the same observable effect, matching trust/attacker assumptions, equivalent retained evidence, declared hardware/toolchains and reviewed failure cases. Human integration effort and independent custody must be measured rather than inferred from code or passing tests.
