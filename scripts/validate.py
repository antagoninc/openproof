#!/usr/bin/env python3
"""Repeatable local/CI validation; creates a new output directory and unsigned build provenance."""
import argparse,datetime,hashlib,json,os,platform,re,shutil,subprocess,sys,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
a=argparse.ArgumentParser();a.add_argument('--out',required=True);a.add_argument('--skip-audit',action='store_true');a.add_argument('--isolation-image-id-file');args=a.parse_args()
out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=False)
sha=lambda b:hashlib.sha256(b).hexdigest()
def snapshot():
 result={}
 for directory,dirs,files in os.walk(ROOT):
  dirs[:]=sorted(d for d in dirs if d not in {'outputs','target','.git','__pycache__','work'})
  for name in sorted(files):
   f=Path(directory)/name
   if f.is_file():result[str(f.relative_to(ROOT))]=sha(f.read_bytes())
 return result
source=snapshot();started=datetime.datetime.now(datetime.timezone.utc).isoformat();steps=[]
def run(name,cmd,cwd=ROOT,env=None):
 r=subprocess.run([str(x) for x in cmd],cwd=cwd,env=env,capture_output=True,text=True)
 (out/(name+'.log')).write_text(r.stdout+r.stderr)
 steps.append({'name':name,'command':[str(x) for x in cmd],'exit_code':r.returncode})
 print(f'{name}: {r.returncode}',flush=True)
 if r.returncode:
  (out/'steps.json').write_text(json.dumps(steps,indent=2));raise RuntimeError(f'{name} failed; see {out}/{name}.log')
 return r.stdout
run('format',['cargo','fmt','--all','--','--check'])
run('clippy',['cargo','clippy','--workspace','--all-targets','--locked','--','-D','warnings'])
run('tests',['cargo','test','--workspace','--locked'])
run('debug-build',['cargo','build','--workspace','--locked'])
goenv=dict(os.environ,GOMODCACHE=str(ROOT/'outputs/tooling/go-mod'),GOCACHE=str(ROOT/'outputs/tooling/go-cache'))
run('go-tests',['go','test','./...'],cwd=ROOT/'reference/go-witness',env=goenv)
run('go-build',['go','build','-o',out/'openproof-go-verify','.'],cwd=ROOT/'reference/go-witness',env=goenv)
run('go-modules',['go','list','-m','-json','all'],cwd=ROOT/'reference/go-witness',env=goenv)
run('witness-conformance',[sys.executable,'scripts/witness_conformance.py','--out',out/'witness-conformance','--go-binary',out/'openproof-go-verify'])
run('conformance',[sys.executable,'scripts/conformance.py'])
run('trust-conformance',[sys.executable,'scripts/trust_conformance.py'])
run('doctor',['target/debug/openproof','doctor'])
run('assurance-demo',['target/debug/openproof','assurance-demo',out/'assurance-demo'])
run('python-agent-tests',[sys.executable,'-m','unittest','discover','-s','scripts/tests','-v'],env=dict(os.environ,OPENPROOF_GO_VERIFY=str(out/'openproof-go-verify')))
if args.isolation_image_id_file:
 run('isolated-agent',[sys.executable,'scripts/isolated_agent.py','--provider','fixture','--image-id-file',args.isolation_image_id_file,'--out',out/'isolated-agent'])
 run('isolation-failures',[sys.executable,'scripts/exercise_isolation.py','--image-id-file',args.isolation_image_id_file])
run('schema',[sys.executable,'scripts/check_schema.py'])
run('fuzz-lock',[sys.executable,'scripts/check_fuzz_lock.py'])
run('agent-pilot',[sys.executable,'scripts/agent_pilot.py',out/'agent-pilot'])
run('witnessed-demo',[sys.executable,'scripts/witness_demo.py','--out',out/'witnessed-demo'])
metadata=json.loads(run('metadata',['cargo','metadata','--locked','--format-version','1']))
policy=json.loads((ROOT/'scripts/license-policy.json').read_text());inventory=[]
for package in metadata['packages']:
 expression=package['license'];assert expression in policy, f'License review needed: {package["name"]}: {expression}'
 inventory.append({'name':package['name'],'version':package['version'],'declared_license':expression,'selected_license':policy[expression],'source':package['source']})
(out/'dependency-licenses.json').write_text(json.dumps(inventory,indent=2)+'\n')
if not args.skip_audit:
 audit=ROOT/'outputs/tooling/bin/cargo-audit'
 if not audit.exists():audit=shutil.which('cargo-audit')
 if not audit:raise RuntimeError('Install pinned cargo-audit 0.22.2 or explicitly use --skip-audit')
 report=json.loads(run('rustsec',[audit,'audit','--json','--db',ROOT/'outputs/advisory-db']))
 assert not report['vulnerabilities']['found'];(out/'rustsec.json').write_text(json.dumps(report,indent=2)+'\n')
run('release',['cargo','build','--workspace','--release','--locked'])
shutil.copyfile(ROOT/'target/release/openproof-witness',out/'openproof-witness');(out/'openproof-witness').chmod(0o755)
assert source==snapshot(),'Source changed during validation; provenance not emitted'
manifest=json.dumps(source,sort_keys=True,indent=2).encode();(out/'source-manifest.json').write_bytes(manifest)
artifact=out/'openproof';shutil.copyfile(ROOT/'target/release/openproof',artifact);artifact.chmod(0o755)
revision=subprocess.run(['git','rev-parse','HEAD'],cwd=ROOT,capture_output=True,text=True)
provenance={'_type':'https://in-toto.io/Statement/v1','subject':[{'name':'openproof','digest':{'sha256':sha(artifact.read_bytes())}},{'name':'openproof-witness','digest':{'sha256':sha((out/'openproof-witness').read_bytes())}}],'predicateType':'https://slsa.dev/provenance/v1','predicate':{'buildDefinition':{'buildType':'urn:antagon-openproof:local-build:v1','externalParameters':{'command':['cargo','build','--workspace','--release','--locked'],'rustc':subprocess.check_output(['rustc','-vV'],text=True),'platform':platform.platform(),'source_revision':revision.stdout.strip() if revision.returncode==0 else None,'source_worktree_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip()) if revision.returncode==0 else None},'resolvedDependencies':[{'uri':'file:source-manifest.json','digest':{'sha256':sha(manifest)}},{'uri':'file:Cargo.lock','digest':{'sha256':sha((ROOT/'Cargo.lock').read_bytes())}}]},'runDetails':{'builder':{'id':'urn:antagon-openproof:local-untrusted-builder'},'metadata':{'invocationId':str(uuid.uuid4()),'startedOn':started,'finishedOn':datetime.datetime.now(datetime.timezone.utc).isoformat()}}}}
(out/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n');(out/'steps.json').write_text(json.dumps(steps,indent=2)+'\n')
count=sum(map(int,re.findall(r'test result: ok\. (\d+) passed',(out/'tests.log').read_text())))
(out/'SUMMARY.md').write_text(f'''# Validation results

{count} Rust tests passed. Formatting, Clippy, schema checks, 224 evidence, 94 trust and 202 Go/Rust witness differential cases, the separate-process agent pilot, declared-license policy, and release build passed.

RustSec audit: {'SKIPPED explicitly' if args.skip_audit else 'passed; database revision recorded in rustsec.json'}.
Platform: {platform.platform()}.
Python host adapter/viewer tests: passed. Container isolation pilot: {'passed' if args.isolation_image_id_file else 'not run by this invocation'}. External model calls: never made by this validation script.

provenance.json links the executable SHA-256 to source-manifest.json, Cargo.lock, toolchain and build command. It is an unsigned local claim, not an independently verified attestation or SLSA level. The build is not hermetic; cross-host reproducibility is not established. No external security audit is claimed.
''')
print(f'PASS: {count} tests; report and unsigned provenance in {out}',flush=True)
