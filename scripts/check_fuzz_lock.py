#!/usr/bin/env python3
"""Fail when fuzzing resolves a shared dependency outside the ordinary build's pinned graph."""
import json,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
a=tomllib.loads((ROOT/'Cargo.lock').read_text())['package'];b=tomllib.loads((ROOT/'fuzz/Cargo.lock').read_text())['package']
names={p['name'] for p in a};identity=lambda p:(p['name'],p['version'],p.get('source'),p.get('checksum'))
allowed={identity(p) for p in a};bad=[identity(p) for p in b if p['name'] in names and identity(p) not in allowed]
if bad:raise SystemExit('Fuzz/build dependency drift: '+json.dumps(bad))
print('PASS: shared fuzz/build package versions, sources and checksums match ('+str(sum(p['name'] in names for p in b))+ ' packages)')
