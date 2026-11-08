#!/usr/bin/env python3
"""Create a private, explicit-list review snapshot; never publish or copy runtime state."""
import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'outputs/v0.9/validation-complete/source-manifest.json'
EXTRA = ['docs/handoff/OPERATORS.md', 'docs/handoff/REVIEW-BRIEF.md',
         'scripts/package_external_review.py']


def package(out):
    original = json.loads(BASE.read_text())
    payload = {}
    for name in sorted(set(original) | set(EXTRA)):
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or any(
                x in {'outputs', 'target', '.git', '__pycache__'} for x in path.parts):
            raise ValueError('unsafe archive path')
        if path.suffix in {'.secret', '.db', '.sqlite', '.env'}:
            raise ValueError('private runtime file')
        source = ROOT / path
        if any(p.is_symlink() for p in [source, *source.parents]):
            raise ValueError('symlink in source path')
        raw = source.read_bytes()
        if name in original and hashlib.sha256(raw).hexdigest() != original[name]:
            raise ValueError('validated source changed: ' + name)
        payload[name] = raw
    # Historical results only; never recursively copy outputs.
    for name in ['VALIDATION.md']:
        payload['prior-validation/' + name] = (ROOT / 'outputs/v0.9' / name).read_bytes()
    manifest = {n: hashlib.sha256(b).hexdigest() for n, b in sorted(payload.items())}
    payload['REVIEW-MANIFEST.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    archive = out / 'openproof-0.9-private-review.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        for name, raw in sorted(payload.items()):
            info = tarfile.TarInfo('openproof-review/' + name)
            info.size = len(raw)
            info.mode = 0o644
            info.mtime = 0
            tar.addfile(info, io.BytesIO(raw))
    archive.chmod(0o600)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (out / 'SHA256SUMS').write_text(digest + '  ' + archive.name + '\n')
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'archive': str(archive), 'sha256': digest,
                      'files': len(payload), 'shared': False}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    package(parser.parse_args().out)
