#!/usr/bin/env python3
"""Stage only public Cargo source, build and test Linux role executable locally."""
import argparse,json,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--out',required=True);a=p.parse_args();out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=False)
endpoint=json.loads(subprocess.check_output(['docker','context','inspect','--format','{{json .Endpoints.docker.Host}}']))
if not endpoint.startswith('unix://'):raise RuntimeError('local Docker endpoint required')
for name in ['Cargo.toml','Cargo.lock']:shutil.copy2(ROOT/name,out/name)
shutil.copytree(ROOT/'crates',out/'crates',ignore=shutil.ignore_patterns('target','outputs','.DS_Store'))
shutil.copytree(ROOT/'fixtures',out/'fixtures')
shutil.copytree(ROOT/'examples',out/'examples')
shutil.copy2(ROOT/'deployment/Dockerfile.roles',out/'Dockerfile')
with (out/'build.log').open('w') as log:subprocess.run(['docker','build','--progress=plain','--iidfile',str(out/'image-id'),str(out)],stdout=log,stderr=subprocess.STDOUT,check=True)
print((out/'image-id').read_text().strip())
