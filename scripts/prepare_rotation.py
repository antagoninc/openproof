#!/usr/bin/env python3
"""Prepare public planned handover proposal; each operator signs separately."""

import argparse, hashlib, json, time
from pathlib import Path
from witness_workflow import call, save, ref

p = argparse.ArgumentParser(description=__doc__)
for name in [
    "old-signed-trust",
    "old-root",
    "new-root",
    "new-trust",
    "checkpoint",
    "out",
]:
    p.add_argument("--" + name, required=True)
a = p.parse_args()
old = call(["trust-payload", a.old_root], ref.read(a.old_signed_trust))
now = int(time.time())
proposal = dict(
    version="openproof-rotation/1",
    old_root=a.old_root,
    new_root=a.new_root,
    old_trust_sha256=hashlib.sha256(ref.canonical(old)).hexdigest(),
    new_trust=ref.read(a.new_trust),
    checkpoint=ref.read(a.checkpoint),
    not_before=now,
    expires_at=now + 300,
)
save(Path(a.out), proposal)
print(
    "Public proposal written; collect six signatures and check the assembled handover before applying."
)
