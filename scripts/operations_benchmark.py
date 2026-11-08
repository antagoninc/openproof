#!/usr/bin/env python3
"""Disclosed local workflow measurements, not production throughput claims."""
import argparse,concurrent.futures,hashlib,json,math,os,platform,resource,statistics,subprocess,sys,time
from pathlib import Path
from witness_workflow import initialize,call,ref
from owner_app import Owner
from paged_workflow import enable
from portable_history import export_history
ROOT=Path(__file__).resolve().parents[1]
def distribution(values):
    ordered=sorted(values)
    return {'samples':len(values),'median_ms':round(statistics.median(values)*1000,3),'p95_ms':round(ordered[math.ceil(.95*len(values))-1]*1000,3),'max_ms':round(max(values)*1000,3)}
def storage(path):return sum(p.stat().st_size for p in Path(path).rglob('*') if p.is_file())
def run(out,binary,samples=64,content_bytes=1024,concurrency=(1,4,8)):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700);binary=Path(binary).resolve();rows=[]
    env={**os.environ,'PYTHONPATH':str(ROOT/'scripts')}
    for workers in concurrency:
        h=out/f'private-home-{workers}';initialize(h);enable(h);owner=Owner(h);ids=[]
        for i in range(samples):
            text=f'Synthetic benchmark document {i}. ';text+= 'x'*(content_bytes-len(text));identity=owner.broker.propose(f'bench-{i}',0,text)['proposal_id'];r=owner.review(identity);owner.approve(identity,r['review_token']);ids.append(identity)
        before=storage(h)
        def execute(identity):
            start=time.perf_counter();r=subprocess.run([sys.executable,str(ROOT/'scripts/witness_workflow.py'),'commit',str(h),identity],capture_output=True,text=True,timeout=120,env=env)
            if r.returncode:raise RuntimeError('Benchmark request failed')
            result=json.loads(r.stdout)
            if result.get('verification_status')!='local_consistency_verified':raise RuntimeError('Benchmark evidence not verified')
            return time.perf_counter()-start
        start=time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:latencies=list(pool.map(execute,ids))
        elapsed=time.perf_counter()-start
        if call(['head',h/'receiver/state'])['count']!=samples:raise AssertionError('Unexpected effect count')
        after=storage(h);archive=out/f'archive-{workers}';export_history(h,archive);root=ref.read(h/'root-public.json')['public_key'];verifications=[]
        for _ in range(5):
            start=time.perf_counter();r=subprocess.run([str(binary),'verify-archive',root,str(archive/'checkpoint-copy.json'),str(archive),str(int(time.time()))],capture_output=True,timeout=60)
            if r.returncode:raise RuntimeError('Archive did not verify')
            verifications.append(time.perf_counter()-start)
        rows.append({'clients':workers,'effects':samples,'commit':distribution(latencies),'elapsed_seconds':round(elapsed,3),'effects_per_second':round(samples/elapsed,3),'home_bytes_before_commits':before,'home_bytes_after_commits':after,'growth_bytes':after-before,'archive_bytes':storage(archive),'offline_verify':distribution(verifications)})
    memory=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss*(1 if sys.platform=='darwin' else 1024)
    result={'version':'openproof-operations-benchmark/1','platform':platform.platform(),'machine':platform.machine(),'logical_cpus':os.cpu_count(),'python':platform.python_version(),'content_bytes_per_document':content_bytes,'go_verifier_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'witness_binary_sha256':hashlib.sha256((ROOT/'target/debug/openproof-witness').read_bytes()).hexdigest(),'max_child_process_peak_rss_bytes':memory,'memory_scope':'Largest child-process peak RSS over this invocation, not aggregate concurrent memory or service residency. Darwin bytes; Linux KiB converted to bytes.','rows':rows,'limits':['Local debug Rust binary and Python process-per-request broker; includes startup, signing, durable storage and evidence overhead.','Broker serializes commits with a home lock; more clients do not imply parallel effects.','Approvals are synthetic and created before timing. Five warm-cache offline checks per workload.','Same-host filesystem and independent Go binary; no external network or independent operator.','No service-level objective, capacity recommendation or TRACE comparison from these small samples.']}
    (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    lines=['# Local operating measurements','',result['platform'],'','| Clients | Effects/s | Commit median ms | Commit p95 ms | Offline median ms | Storage growth bytes |','|---|---:|---:|---:|---:|---:|']
    for r in rows:lines.append(f"| {r['clients']} | {r['effects_per_second']} | {r['commit']['median_ms']} | {r['commit']['p95_ms']} | {r['offline_verify']['median_ms']} | {r['growth_bytes']} |")
    lines+=['','Maximum child-process peak RSS: '+str(memory)+' bytes. '+result['memory_scope'],'',*result['limits']];(out/'REPORT.md').write_text('\n'.join(lines)+'\n');return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True);p.add_argument('--go-binary',required=True);p.add_argument('--samples',type=int,default=64);p.add_argument('--content-bytes',type=int,default=1024);p.add_argument('--concurrency',type=int,nargs='+',default=[1,4,8]);a=p.parse_args()
    if not 1<=a.samples<=256 or not 128<=a.content_bytes<=8192 or len(a.concurrency)!=len(set(a.concurrency)) or any(not 1<=c<=16 for c in a.concurrency):p.error('Use 1..256 samples, 128..8192 content bytes and unique concurrency values 1..16')
    r=run(a.out,a.go_binary,a.samples,a.content_bytes,a.concurrency);print(json.dumps({'workloads':len(r['rows']),'report':str(Path(a.out)/'REPORT.md')}))
if __name__=='__main__':main()
