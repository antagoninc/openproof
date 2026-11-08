#!/usr/bin/env python3
"""Bounded instrumented campaigns with explicit targets, seed and sequence counts."""
import argparse,concurrent.futures,json,os,re,subprocess,time
from pathlib import Path
TARGETS=['evidence','policy','trust','witness','witness_state']
def main():
    root=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser(description=__doc__);p.add_argument('--seconds',type=int,default=180);p.add_argument('--out',required=True);p.add_argument('--targets',nargs='+',choices=TARGETS,default=TARGETS);p.add_argument('--workers',type=int,choices=[1,2,3],default=1);p.add_argument('--seed',type=int,default=20261108);a=p.parse_args()
    if not 1<=a.seconds<=86400 or not 0<=a.seed<=4294967295:p.error('Invalid bounded duration or seed')
    out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=False)
    env=os.environ.copy();env['RUSTUP_HOME']=str(root/'outputs/tooling/rustup');env['PATH']=str(root/'outputs/tooling/bin')+':'+str(Path.home()/'.cargo/bin')+':'+env['PATH'];env['CARGO_TARGET_DIR']=str(root/'target/fuzz')
    def run(name):
        corpus=out/('corpus-'+name);corpus.mkdir()
        for f in (root/'fuzz/corpus'/name).iterdir():(corpus/f.name).write_bytes(f.read_bytes())
        artifacts=out/('artifacts-'+name);artifacts.mkdir();start=time.monotonic()
        cmd=[str(Path.home()/'.cargo/bin/cargo'),'+nightly','fuzz','run',name,str(corpus),'--',f'-max_total_time={a.seconds}','-max_len=8192','-rss_limit_mb=768',f'-seed={a.seed}','-artifact_prefix='+str(artifacts)+'/']
        logpath=out/(name+'.log')
        with logpath.open('w') as log:r=subprocess.run(cmd,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
        matches=re.findall(r'Done (\d+) runs in',logpath.read_text());count=int(matches[-1]) if matches else None
        result=dict(target=name,exit_code=r.returncode,executions=count,seed=a.seed,requested_seconds=a.seconds,elapsed_seconds=round(time.monotonic()-start,2),crash_artifacts=len(list(artifacts.iterdir())))
        print(json.dumps(result),flush=True);return result
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:results=list(pool.map(run,dict.fromkeys(a.targets)))
    (out/'summary.json').write_text(json.dumps({'results':results,'scope':'Bounded local fuzzing; no exhaustive coverage or absence-of-vulnerability claim.'},indent=2)+'\n')
    return int(any(r['exit_code'] or r['crash_artifacts'] or r['executions'] is None for r in results))
if __name__=='__main__':raise SystemExit(main())
