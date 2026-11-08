#!/usr/bin/env python3
"""Run bounded instrumented campaigns. Default local setup uses tools installed inside this project."""
import argparse,concurrent.futures,os,subprocess
from pathlib import Path
p=Path(__file__).resolve().parents[1];a=argparse.ArgumentParser();a.add_argument('--seconds',type=int,default=180);a.add_argument('--out',required=True);args=a.parse_args();assert 1<=args.seconds<=86400
out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=False)
env=os.environ.copy();env['RUSTUP_HOME']=str(p/'outputs/tooling/rustup');env['PATH']=str(p/'outputs/tooling/bin')+':'+str(Path.home()/'.cargo/bin')+':'+env['PATH'];env['CARGO_TARGET_DIR']=str(p/'target/fuzz')
def run(name):
 corpus=out/('corpus-'+name);corpus.mkdir()
 for f in (p/'fuzz/corpus'/name).iterdir():(corpus/f.name).write_bytes(f.read_bytes())
 artifacts=out/('artifacts-'+name);artifacts.mkdir()
 command=[str(Path.home()/'.cargo/bin/cargo'),'+nightly','fuzz','run',name,str(corpus),'--',f'-max_total_time={args.seconds}','-max_len=8192','-rss_limit_mb=768','-seed=20261107','-artifact_prefix='+str(artifacts)+'/']
 with (out/(name+'.log')).open('w') as log:r=subprocess.run(command,cwd=p,env=env,stdout=log,stderr=subprocess.STDOUT)
 print(name+': exit '+str(r.returncode),flush=True);return r.returncode
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(run,['evidence','policy','trust','witness','witness_state']))
raise SystemExit(int(any(results)))
