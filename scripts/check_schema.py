#!/usr/bin/env python3
"""Optional schema and independent encoding checks. Requires Python jsonschema, no network."""
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/openproof-v1.schema.json").read_text())
Draft202012Validator.check_schema(SCHEMA)
def validate(value, kind):
    schema = dict(SCHEMA, **{"$ref": "#/$defs/" + kind})
    Draft202012Validator(schema).validate(value)

def frame(n):
    return struct.pack(">Q", n)
def encode(v):
    if v is None: return b"\x00"
    if v is False: return b"\x01"
    if v is True: return b"\x02"
    if isinstance(v, int) and 0 <= v <= 2**64-1: return b"\x03" + frame(v)
    if isinstance(v, str):
        s = v.encode("utf-8")
        return b"\x04" + frame(len(s)) + s
    if isinstance(v, list): return b"\x05" + frame(len(v)) + b"".join(map(encode,v))
    if isinstance(v, dict):
        return b"\x06" + frame(len(v)) + b"".join(encode(k)+encode(v[k]) for k in sorted(v,key=lambda s:s.encode("utf-8")))
    raise ValueError("unsupported canonical type")

binary = ROOT / "target/debug/openproof"
checks=0
with tempfile.TemporaryDirectory(dir=ROOT / "outputs", prefix="schema-check-") as tmp:
    for kind in ["authorization", "action", "receipt"]:
        path=ROOT / "examples" / (kind+".json")
        value=json.loads(path.read_text())
        validate(value,kind.title())
        canonical=b"OpenProof/v1/"+kind.encode()+b"\x00OPEC\x01"+encode(value)
        dest=Path(tmp)/(kind+".bin")
        subprocess.run([binary,"canonical",kind,path,dest],check=True,capture_output=True)
        assert dest.read_bytes()==canonical
        actual=subprocess.check_output([binary,"digest",kind,path],text=True).strip()
        assert actual==hashlib.sha256(canonical).hexdigest()
        checks+=3
    demo=Path(tmp)/"demo"
    subprocess.run([binary,"demo",demo],check=True,capture_output=True)
    bundle=json.loads((demo/"bundle.json").read_text())
    validate(bundle,"Bundle")
    validate(json.loads((demo/"context.json").read_text()),"Context")
    checks+=2
    for kind in ["Authorization","Action","Receipt"]:
        value=json.loads((ROOT/"examples"/(kind.lower()+".json")).read_text())
        value["version"]="openproof/999"
        assert not Draft202012Validator(dict(SCHEMA,**{"$ref":"#/$defs/"+kind})).is_valid(value)
        checks+=1
print(f"PASS: {checks} schema/independent-byte/digest checks")

trust_schema=json.loads((ROOT/'schemas/openproof-trust-v1.schema.json').read_text())
Draft202012Validator(trust_schema).validate(json.loads((ROOT/'fixtures/trust-v1/snapshot.json').read_text()))
transition_schema=json.loads((ROOT/'schemas/openproof-root-transition-v1.schema.json').read_text())
Draft202012Validator.check_schema(transition_schema)
Draft202012Validator(transition_schema).validate(json.loads((ROOT/"fuzz/corpus/trust/root-transition.json").read_text()))
print('PASS: trust fixture and root-transition schema structure')

witness_schema=json.loads((ROOT/"schemas/openproof-witness-v1.schema.json").read_text())
Draft202012Validator.check_schema(witness_schema)
Draft202012Validator(witness_schema).validate(json.loads((ROOT/"fixtures/witness-v1/package.json").read_text()))
print("PASS: witnessed document package structural schema")

signed_witness_schema=json.loads((ROOT/'schemas/openproof-witness-trust-v1.schema.json').read_text())
Draft202012Validator.check_schema(signed_witness_schema)
Draft202012Validator(signed_witness_schema).validate(json.loads((ROOT/'fixtures/witness-trust-v1/trust-signed.json').read_text()))
print('PASS: signed witness trust structural schema')

for name in ['openproof-history-page-v1.schema.json','openproof-rotation-v1.schema.json','openproof-portable-history-v1.schema.json']:
    Draft202012Validator.check_schema(json.loads((ROOT/'schemas'/name).read_text()))
print('PASS: page and planned handover schema structure (semantic rules enforced in Rust)')
