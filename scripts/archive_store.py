#!/usr/bin/env python3
"""Verify then copy bounded public history into a hash-pinned archive. Never prune live state."""
import argparse,hashlib,json,os,re,shutil,subprocess,time,uuid
from pathlib import Path
from history_viewer import bounded_json,render

def verify(directory,root,pin,binary):
    r=subprocess.run([str(Path(binary).resolve()),'verify-archive',root,str(Path(pin).resolve()),str(directory),str(int(time.time()))],capture_output=True,text=True,timeout=60)
    if r.returncode:raise ValueError('Archive failed current trust/checkpoint verification')
    result=json.loads(r.stdout)
    if result.get('status')!='portable_history_verified' or not result.get('complete_history'):raise ValueError('Complete history required for this archival path')
    return result

def seal(source,root,pin,binary,out):
    source=Path(source).resolve();out=Path(out).resolve();pin=Path(pin).resolve();binary=Path(binary).resolve()
    if pin.is_relative_to(source) or binary.is_relative_to(source):raise ValueError('Use independently supplied checkpoint and verifier outside the archive')
    if out.exists() or out.is_relative_to(source):raise ValueError('New destination outside source required')
    verify(source,root,pin,binary);manifest=bounded_json(source/'manifest.json');out.parent.mkdir(parents=True,exist_ok=True)
    stage=out.parent/('.archive-'+uuid.uuid4().hex);stage.mkdir(mode=0o700)
    try:
        names=['manifest.json','checkpoint-copy.json']+[e['file'] for e in manifest['entries']]
        if len(names)>4098 or len(names)!=len(set(names)):raise ValueError('Archive count/duplicate bound')
        total=0
        for name in names:
            if name not in ['manifest.json','checkpoint-copy.json'] and not re.fullmatch(r'entry-[0-9]{6}\.json',name):raise ValueError('Unsafe entry')
            p=source/name
            if p.is_symlink():raise ValueError('Symlink evidence')
            with p.open('rb') as f:raw=f.read(1048577)
            total+=len(raw)
            if len(raw)>1048576 or total>256*1024*1024:raise ValueError('Archive size bound')
            with (stage/name).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        result=verify(stage,root,pin,binary);render(stage)
        (stage/'verification-record.json').write_text(json.dumps({'checked_at':int(time.time()),'result':result,'scope':'Recorded check only. An archive seal is not a continuously fresh verification or independent custody.'},indent=2)+'\n')
        if any(p.stat().st_size>256*1024*1024 for p in stage.iterdir()):raise ValueError('Rendered archive file limit')
        files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(stage.iterdir()) if p.is_file()};raw=(json.dumps({'version':'openproof-archive-seal/1','files':files},sort_keys=True,indent=2)+'\n').encode();(stage/'seal.json').write_bytes(raw)
        for p in stage.iterdir():
            with p.open('rb') as f:os.fsync(f.fileno())
            p.chmod(0o400)
        fd=os.open(stage,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
        stage.rename(out);fd=os.open(out.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
        return {'archive':str(out),'seal_sha256':hashlib.sha256(raw).hexdigest(),'files':len(files),'live_state_pruned':False,'independent_custody':False,'note':'Retain the seal digest through a separate trusted channel. File permissions do not prevent an administrator from changing data.'}
    except Exception:
        if stage.exists():shutil.rmtree(stage)
        raise

def check(directory,expected):
    d=Path(directory);path=d/'seal.json'
    if path.is_symlink() or path.stat().st_size>1048576:raise ValueError('Invalid seal')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('Pinned seal mismatch')
    m=json.loads(raw)
    if m.get('version')!='openproof-archive-seal/1' or len(m['files'])>4100:raise ValueError('Seal version/bound')
    if {p.name for p in d.iterdir()}!=set(m['files'])|{'seal.json'}:raise ValueError('Archive membership changed')
    for name,digest in m['files'].items():
        if Path(name).name!=name or name in ['.','..']:raise ValueError('Unsafe sealed path')
        p=d/name
        if p.is_symlink() or not p.is_file() or p.stat().st_size>256*1024*1024:raise ValueError('Invalid sealed file')
        h=hashlib.sha256()
        with p.open('rb') as f:
            for part in iter(lambda:f.read(65536),b''):h.update(part)
        if h.hexdigest()!=digest:raise ValueError('Sealed bytes changed')
    return {'status':'matches_separately_pinned_seal','fresh_trust_checked':False,'live_state_pruned':False}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='cmd',required=True);a=s.add_parser('seal');a.add_argument('source')
    for n in ['root','checkpoint','go-binary','out']:a.add_argument('--'+n,required=True)
    a=s.add_parser('check');a.add_argument('directory');a.add_argument('--expected-sha256',required=True);a=p.parse_args()
    print(json.dumps(seal(a.source,a.root,a.checkpoint,a.go_binary,a.out) if a.cmd=='seal' else check(a.directory,a.expected_sha256),indent=2))
