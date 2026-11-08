#!/usr/bin/env python3
"""Compare independently implemented Go and Rust v1 witness verifiers."""
import argparse,copy,json,subprocess,time
from pathlib import Path
from witness_workflow import ROOT,BINARY,Broker,initialize,save

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--go-binary',default=str(ROOT/'outputs/v0.8/openproof-go-verify'));a=p.parse_args()
    out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=False)
    home=out/'home';initialize(home);b=Broker(home)
    q=b.propose('report',0,'Public synthetic report: café — verified bytes.');b.approve(q['proposal_id'],reader=lambda _:'APPROVE '+q['content_sha256'][:12]);r=b.commit(q['proposal_id'])
    assert r['verification_status']=='local_consistency_verified',r
    package=json.loads((Path(r['evidence_directory'])/'package.json').read_text());trust=json.loads((home/'trust.json').read_text());pin=package['checkpoint'];cases=[]
    def add(name,path,value):
        x=copy.deepcopy(package);node=x
        for k in path[:-1]:node=node[k]
        node[path[-1]]=value;cases.append((name,x))
    cases.append(('valid',package))
    for name,path in [('approval',['requests',0,'approval','payload']),('receipt',['receipts',0,'payload']),('checkpoint',['checkpoint','payload'])]:
        node=package
        for k in path:node=node[k]
        for field in node:
            for i,value in enumerate([None,False,[],{},'changed',0,2**64-1]):add(f'{name}-{field}-{i}',path+[field],value)
        sigpath=path[:-1]+['signature'];node=package
        for k in sigpath:node=node[k]
        for i in range(0,len(node),16):add(f'{name}-signature-{i}',sigpath,node[:i]+('0' if node[i]!='0' else '1')+node[i+1:])
    add('content',['requests',0,'content'],'tampered');add('missing-receipts',['receipts'],[]);add('missing-requests',['requests'],[])
    add('duplicate-receipt',['receipts'],package['receipts']*2);add('duplicate-request',['requests'],package['requests']*2)
    results=[];now=str(int(time.time()));save(out/'trust.json',trust);save(out/'pin.json',pin)
    def check(name,raw):
        (out/'case.json').write_bytes(raw)
        rust=subprocess.run([str(BINARY),'verify',str(out/'trust.json'),str(out/'pin.json')],input=raw,capture_output=True,timeout=20)
        go=subprocess.run([str(Path(a.go_binary).resolve()),'verify',str(out/'trust.json'),str(out/'pin.json'),str(out/'case.json'),now],capture_output=True,timeout=20)
        accepted=rust.returncode==0
        assert accepted==(go.returncode==0),(name,rust.stderr,go.stderr)
        if accepted:
            left=json.loads(rust.stdout);right=json.loads(go.stdout)
            for k in ['status','complete_history','physical_effects_proven']:assert left[k]==right[k],(name,k,left,right)
        results.append({'case':name,'accepted':accepted})
    for name,data in cases:check(name,json.dumps(data,ensure_ascii=False).encode())
    raw=json.dumps(package).encode()
    for name,bad in [('trailing',raw+b' {}'),('duplicate',b'{"version":"bad",'+raw[1:]),('surrogate',raw.replace(b'Public',b'\\ud800')),('float',raw.replace(b'"sequence": 1',b'"sequence": 1.0'))]:
        check(name,bad);assert not results[-1]['accepted'],name
    save(out/'results.json',{'cases':len(results),'results':results,'scope':'stateless v1 full packages; shared author, separate implementation'})
    print(f"PASS {len(results)} Go/Rust differential cases")
if __name__=='__main__':main()
