#!/usr/bin/env python3
"""Shared acceptance/rejection properties, with explicit non-comparable runtime scope."""
import argparse,copy,hashlib,importlib.metadata,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def trace_worker():
    from agentrust_trace import generate_key,sign_record,verify_record
    version=importlib.metadata.version('agentrust-trace')
    if version!='0.11.0':raise ValueError('Expected the pinned TRACE 0.11.0 environment')
    k=generate_key();other=generate_key();now=int(time.time())
    base={'eat_profile':'tag:agentrust-io.com,2026:trace-v0.2','iat':now-5,'subject':'spiffe://example.test/openproof-properties','model':{'provider':'synthetic','model_id':'none'},'runtime':{'platform':'software-only','measurement':'sha256:'+'0'*64},'policy':{'bundle_hash':'sha256:'+'a'*64,'enforcement_mode':'enforce'},'data_class':'public','build_provenance':{'slsa_level':0,'digest':'sha256:'+'b'*64},'appraisal':{'status':'none','verifier':'https://example.test/offline'}}
    signed=sign_record(base,k)
    def accepts(value,key=k):
        try:verify_record(value,public_key_or_jwk=key.public_key(),now=now,max_age_seconds=300,max_future_skew_seconds=0);return True
        except Exception:return False
    changed=copy.deepcopy(signed);changed['data_class']='restricted';sig=copy.deepcopy(signed);sig['signature']='broken'
    expired=sign_record(dict(base,iat=now-601),k);future=sign_record(dict(base,iat=now+600),k)
    return {'implementation':'agentrust-trace '+version,'checks':{'valid':accepts(signed),'changed_signed_field':not accepts(changed),'wrong_trusted_key':not accepts(signed,other),'corrupt_signature':not accepts(sig),'expired_window':not accepts(expired),'future_window':not accepts(future)},'scope':'Software TrustRecord with explicit trusted key, 300-second maximum age and zero future skew. No runtime, registry or hardware evaluation.'}
def run(out,trace_python):
    from witness_workflow import call,save
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700);now=int(time.time());authority=call(['keygen',out/'test-authority.secret'])['public_key'];wrong=call(['keygen',out/'test-other.secret'])['public_key']
    p={'version':'openproof-storage-upload/1','authority':authority,'endpoint':'https://127.0.0.1:8443','bucket':'test-bucket','object_key':'report.txt','content_sha256':hashlib.sha256(b'Public synthetic report').hexdigest(),'content_bytes':23,'nonce':'ab'*32,'not_before':now-5,'expires_at':now+295}
    def signed(value):return call(['storage-authorize',out/'test-authority.secret'],value)
    def accepts(value,key=authority):
        try:call(['storage-check',key],value);return True
        except RuntimeError:return False
    a=signed(p);changed=copy.deepcopy(a);changed['payload']['object_key']='changed.txt';sig=copy.deepcopy(a);sig['signature']='00'*64
    checks={'valid':accepts(a),'changed_signed_field':not accepts(changed),'wrong_trusted_key':not accepts(a,wrong),'corrupt_signature':not accepts(sig),'expired_window':not accepts(signed(dict(p,not_before=now-601,expires_at=now-301))),'future_window':not accepts(signed(dict(p,not_before=now+600,expires_at=now+900)))}
    env={k:v for k,v in os.environ.items() if k in ['PATH','HOME','LANG']};trace=json.loads(subprocess.check_output([str(trace_python),__file__,'--trace-worker'],env=env,text=True,timeout=60))
    result={'version':'openproof-property-comparison/1','openproof':{'checks':checks,'scope':'Rust upload authorization with a 300-second window, explicit authority and exact destination/content binding.'},'trace':trace,'shared_property_scope':'The approval dispatch window and record-age window have different meanings. Acceptance/rejection properties only. Records, schemas, canonicalization, signature workloads and intended use differ. No timing or memory winner is inferred.','unassessed_trace_ecosystem':['cMCP/AGT policy enforcement','hardware attestation and platform appraisal','registry and independently operated witness','real users and deployment effort'],'unassessed_openproof':['real S3 provider interoperability','independent operators','human audit','production capacity'],'security_superiority_established':False,'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'comparison_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'witness_binary_sha256':hashlib.sha256((ROOT/'target/debug/openproof-witness').read_bytes()).hexdigest()}
    save(out/'results.json',result)
    lines=['# Shared-property comparison','','TRACE SDK 0.11.0 and this OpenProof snapshot were tested separately.','', '| Property | OpenProof | TRACE SDK |','|---|---|---|']
    for name in checks:lines.append('| '+name.replace('_',' ')+' | '+('passed' if checks[name] else 'FAILED')+' | '+('passed' if trace['checks'][name] else 'FAILED')+' |')
    lines+=['',result['shared_property_scope'],'','TRACE runtime/hardware/registry capabilities were not exercised and are not scored as absent. OpenProof provider interoperability, independent operation and human audit remain unassessed. No overall security or performance winner is established.'];(out/'REPORT.md').write_text('\n'.join(lines)+'\n')
    if not all(checks.values()) or not all(trace['checks'].values()):raise AssertionError('A shared property failed; see results.json')
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--trace-worker',action='store_true');p.add_argument('--trace-python');p.add_argument('--out');a=p.parse_args()
    if a.trace_worker:print(json.dumps(trace_worker()))
    else:
        if not a.out or not a.trace_python:p.error('--out and --trace-python required')
        r=run(a.out,a.trace_python);print(json.dumps({'shared_properties':len(r['openproof']['checks']),'security_superiority_established':False}))
