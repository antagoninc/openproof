#!/usr/bin/env python3
"""Build only a minimal public worker context; never send the project or home to Docker."""
import argparse,json,shutil,subprocess
from pathlib import Path
from isolation_runner import ENV,docker
ROOT=Path(__file__).resolve().parents[1]
def main():
    a=argparse.ArgumentParser();a.add_argument('--out',required=True);args=a.parse_args()
    out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=False)
    endpoint=json.loads(docker(['context','inspect','--format','{{json .Endpoints.docker.Host}}']).stdout)
    if not endpoint.startswith('unix://') or not ENV.get('DOCKER_HOST','unix://').startswith('unix://'):raise RuntimeError('local Docker engine required for builds')
    subprocess.run(['docker','pull','python:3.11-slim-bookworm'],check=True,env=ENV)
    base=subprocess.check_output(['docker','image','inspect','python:3.11-slim-bookworm','--format','{{index .RepoDigests 0}}'],text=True,env=ENV).strip()
    for src,name in [('isolation/Dockerfile','Dockerfile'),('isolation/worker.py','worker.py'),('reference/python/openproof_ref.py','openproof_ref.py'),('reference/python/openproof_trust.py','openproof_trust.py'),('reference/python/requirements.txt','requirements.txt')]:shutil.copy2(ROOT/src,out/name)
    subprocess.run(['docker','build','--build-arg','BASE='+base,'--iidfile',str(out/'image-id'),str(out)],check=True,env=ENV)
    (out/'build.json').write_text(json.dumps({'base':base,'image':(out/'image-id').read_text().strip(),'context_files':['Dockerfile','worker.py','openproof_ref.py','openproof_trust.py','requirements.txt']},indent=2)+'\n')
    print('Worker image ID saved to',out/'image-id')
if __name__=='__main__':main()
