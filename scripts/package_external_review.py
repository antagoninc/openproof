#!/usr/bin/env python3
"""Package exactly a completed validation snapshot. No runtime state or publication."""
import argparse,gzip,hashlib,io,json,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
EXCLUDED={'outputs','target','.git','__pycache__','.venv','work'}
PRIVATE={'.secret','.key','.pem','.p12','.pfx','.db','.sqlite','.sqlite3','.pyc'}
def package(out,validation):
    validation=Path(validation);original=json.loads((validation/'source-manifest.json').read_text())
    steps=json.loads((validation/'steps.json').read_text())
    required={'format','clippy','tests','python-agent-tests','go-tests','witness-conformance','release','rustsec'}
    if not steps or any(s['exit_code']!=0 for s in steps) or not required.issubset({s['name'] for s in steps}):raise ValueError('Complete successful validation including advisory audit required')
    if not original:raise ValueError('Empty source snapshot')
    payload={}
    for name,digest in sorted(original.items()):
        path=Path(name)
        if path.is_absolute() or '..' in path.parts or any(x in EXCLUDED for x in path.parts) or path.suffix in PRIVATE or path.name=='.env' or path.name.startswith('.env.'):raise ValueError('Unsafe or private archive path')
        source=ROOT/path
        if any(p.is_symlink() for p in [source,*source.parents]):raise ValueError('Symlink in source path')
        raw=source.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('Validated source changed: '+name)
        payload[name]=raw
    # Only this public summary is copied; no test logs, keys, homes or binary outputs.
    payload['review-validation/SUMMARY.md']=(validation/'SUMMARY.md').read_bytes()
    payload['review-validation/source-manifest.json']=(validation/'source-manifest.json').read_bytes()
    manifest={n:hashlib.sha256(b).hexdigest() for n,b in sorted(payload.items())}
    payload['REVIEW-MANIFEST.json']=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
    out=Path(out);out.mkdir(parents=True,exist_ok=False,mode=0o700);archive=out/'openproof-private-review.tar.gz'
    with archive.open('xb') as f,gzip.GzipFile(filename='',mode='wb',fileobj=f,mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w') as tar:
        for name,raw in sorted(payload.items()):
            info=tarfile.TarInfo('openproof-review/'+name);info.size=len(raw);info.mode=0o755 if (ROOT/name).is_file() and (ROOT/name).stat().st_mode&0o111 else 0o644;info.mtime=0
            tar.addfile(info,io.BytesIO(raw))
    archive.chmod(0o600);digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    (out/'SHA256SUMS').write_text(digest+'  '+archive.name+'\n');(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    result={'archive':str(archive),'sha256':digest,'files':len(payload),'shared':False};print(json.dumps(result,indent=2));return result
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True);p.add_argument('--validation',required=True);a=p.parse_args();package(a.out,a.validation)
