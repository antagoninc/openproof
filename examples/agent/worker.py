#!/usr/bin/env python3
"""Deterministic local agent: turns a requested report into an actor-signed action.
No language model, network access or authority/executor signing keys are used here.
"""
import base64,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'reference/python'))
import openproof_ref as ref
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
job=ref.load_bytes(sys.stdin.buffer.read(ref.MAX+1))
arguments=('OpenProof agent report\n\n'+job['goal']+'\n').encode()
assert len(arguments)<=4096
scope=dict(job['authorization']['payload']['action'])
if job['mode']=='denied':scope['resource']='urn:unapproved:destination'
action=dict(version='openproof/1',authorization_sha256=ref.digest('authorization',job['authorization']['payload']),action=scope,claimed_at=job['time'])
key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(job['actor_seed']))
signed=dict(payload=action,signature=key.sign(ref.preimage('action',action)).hex())
print(json.dumps(dict(action=signed,arguments=base64.b64encode(arguments).decode())))
