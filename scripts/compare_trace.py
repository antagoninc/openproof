#!/usr/bin/env python3
"""Pinned comparative experiments. Different verification workloads; no blanket winner or security grade."""
import argparse,copy,hashlib,json,os,platform,re,resource,statistics,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def metrics(samples):
    v=sorted(samples);return {'samples':len(v),'median_ms':statistics.median(v)/1e6,'p95_ms':v[int(.95*(len(v)-1))]/1e6}
def trace_worker():
    import importlib.metadata
    from agentrust_trace import generate_key,sign_record,verify_record
    assert importlib.metadata.version('agentrust-trace')=='0.11.0'
    key=generate_key();other=generate_key();now=int(time.time())
    record={'eat_profile':'tag:agentrust-io.com,2026:trace-v0.2','iat':now,'subject':'spiffe://example.test/openproof-comparison','model':{'provider':'synthetic','model_id':'none'},'runtime':{'platform':'software-only','measurement':'sha256:'+'0'*64},'policy':{'bundle_hash':'sha256:'+'a'*64,'enforcement_mode':'enforce'},'data_class':'public','build_provenance':{'slsa_level':0,'digest':'sha256:'+'b'*64},'appraisal':{'status':'none','verifier':'https://example.test/offline'}}
    signed=sign_record(record,key);verify_record(signed,public_key_or_jwk=key.public_key(),now=now)
    checks={'valid_record':True}
    changed=copy.deepcopy(signed);changed['data_class']='restricted'
    for label,value,k in [('signed_field_tamper_rejected',changed,key),('wrong_trusted_key_rejected',signed,other)]:
        try:verify_record(value,public_key_or_jwk=k.public_key(),now=now)
        except Exception:checks[label]=True
        else:checks[label]=False
    old=copy.deepcopy(record);old['iat']=now-100000;old=sign_record(old,key)
    try:verify_record(old,public_key_or_jwk=key.public_key(),now=now)
    except Exception:checks['record_freshness_rejected']=True
    else:checks['record_freshness_rejected']=False
    samples=[]
    for _ in range(200):
        start=time.perf_counter_ns();verify_record(signed,public_key_or_jwk=key.public_key(),now=now);samples.append(time.perf_counter_ns()-start)
    rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {'implementation':'agentrust-trace 0.11.0','checks':checks,'latency':metrics(samples),'peak_process_rss_bytes':rss if sys.platform=='darwin' else rss*1024,'record_bytes':len(json.dumps(signed).encode()),'workload':'Python SDK software-only TrustRecord schema/signature/freshness; no receiver execution, hardware, registry or external receipt evaluation tested'}
def main():
    p=argparse.ArgumentParser();p.add_argument('--trace-worker',action='store_true');p.add_argument('--trace-python');p.add_argument('--demo');p.add_argument('--out');a=p.parse_args()
    if a.trace_worker:print(json.dumps(trace_worker()));return
    out=Path(a.out);out.mkdir(parents=True,exist_ok=False);home=Path(a.demo).resolve();demo=json.loads((home/'demo-result.json').read_text());run=Path(demo['assessment']['evidence_directory']);package=json.loads((run/'package.json').read_text());binary=ROOT/'target/release/openproof-witness'
    env={k:v for k,v in os.environ.items() if k in ['PATH','HOME','LANG']}
    trace=json.loads(subprocess.check_output([a.trace_python,__file__,'--trace-worker'],env=env,text=True,timeout=60))
    def verify(value,trust):return subprocess.run([str(binary),'verify',str(trust),str(run/'checkpoint.json')],input=json.dumps(value),text=True,capture_output=True,env=env,timeout=10).returncode==0
    checks={'valid_record':verify(package,home/'trust.json')};changed=copy.deepcopy(package);changed['receipts'][0]['payload']['content_sha256']='0'*64;checks['signed_field_tamper_rejected']=not verify(changed,home/'trust.json')
    wrong=json.loads((home/'trust.json').read_text());from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    wrong['receiver']=Ed25519PrivateKey.from_private_bytes(bytes([77])*32).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex();(out/'wrong-trust.json').write_text(json.dumps(wrong));checks['wrong_trusted_key_rejected']=not verify(package,out/'wrong-trust.json')
    expired=json.loads((home/'trust.json').read_text());expired['expires_at']=1;(out/'expired-trust.json').write_text(json.dumps(expired));checks['trust_snapshot_freshness_rejected']=not verify(package,out/'expired-trust.json')
    command=[str(binary),'bench',str(home/'trust.json'),str(run/'checkpoint.json'),'200']
    # OS memory measurement includes process startup; inner latency samples exclude startup/parsing.
    timed=['/usr/bin/time','-l']+command if sys.platform=='darwin' else ['/usr/bin/time','-v']+command
    measured=subprocess.run(timed,input=json.dumps(package),text=True,capture_output=True,env=env,timeout=60);assert measured.returncode==0,measured.stderr
    (out/'openproof-time.txt').write_text(measured.stderr);bench=json.loads(measured.stdout)
    rss=re.search(r'(\d+)\s+maximum resident set size',measured.stderr) if sys.platform=='darwin' else re.search(r'Maximum resident set size \(kbytes\):\s*(\d+)',measured.stderr)
    own={'implementation':'OpenProof Rust 0.7.0 release','checks':checks,'latency':metrics(bench['samples_ns']),'peak_process_rss_bytes':int(rss[1])*(1 if sys.platform=='darwin' else 1024) if rss else None,'record_bytes':len(json.dumps(package).encode()),'workload':bench['workload']}
    assert all(checks.values()) and all(trace['checks'].values())
    result={'platform':platform.platform(),'python':sys.version,'trace':trace,'openproof':own,'comparable_checks':['valid signed input','signed field mutation','wrong independently supplied trust key'],'not_equivalent':['TRACE record age vs OpenProof current trust-configuration expiry','one TRACE TrustRecord vs approval/receiver/checkpoint chain; signature counts and schema work differ','Python SDK vs Rust release process memory includes runtime overhead'],'not_tested_for_trace':['mandatory execution authorization','receiver/witness deployment','receipt omission detection across complete histories','hardware attestation','integration effort with real users'],'security_superiority_established':False}
    (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'REPORT.md').write_text('# Version-pinned comparison experiment\n\nBoth implementations accepted valid signed input and rejected signed-field mutation and incorrect trusted keys. This establishes those checks for these fixtures, not overall superiority.\n\n| Implementation | Median verification ms | p95 ms | Peak process RSS bytes |\n|---|---:|---:|---:|\n'+''.join(f'| {x["implementation"]} | {x["latency"]["median_ms"]:.4f} | {x["latency"]["p95_ms"]:.4f} | {x["peak_process_rss_bytes"]} |\n' for x in [trace,own])+'\nThese are different workloads. TRACE verifies a software-only TrustRecord through its Python SDK; OpenProof verifies a complete one-document authorization/receiver/witness chain through Rust. Timings exclude startup; memory includes language runtime/startup. No performance winner is inferred. See results.json for precise scope, package sizes and exclusions.\n\nTRACE execution enforcement, receiver/witness integrations, omission detection, hardware and human integration effort were not evaluated. They are not scored as missing or failed. OpenProof integration was exercised through six local MCP tests, not a usability study. Versions/dependencies and distribution hashes are retained alongside this experiment. Nothing was published.\n')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
