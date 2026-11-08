#!/usr/bin/env python3
"""Synthetic loopback HTTPS demonstration. Never contacts an external storage provider."""
import argparse,html,json,shutil,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts/tests'))
from test_storage import Storage
from history_viewer import document

def run(out):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700);fixture=Storage();fixture.setUp()
    try:
        first=fixture.run_job();again=fixture.run_job()
        if fixture.server.writes!=1 or fixture.server.attempts!=1 or not first['read_back_matches']:raise AssertionError('Local storage demonstration failed')
        for name in ['authorization.json',*first['observations'],*again['observations']]:shutil.copyfile(fixture.d/'job'/name,out/name)
        result={'approval_mode':'simulated_fixture_review','transport':'loopback HTTPS S3-shaped fixture; not a real provider','external_uploads':0,'put_attempts':fixture.server.attempts,'object_creations':fixture.server.writes,'first':first,'retry':again,'demo_public_keys':{'authority':fixture.authority,'adapter':fixture.adapter},'independent_storage_proof':False,'fixture_limit':'The server checks request shape and conditional creation; it is not a full S3 implementation or independent SigV4 verifier.'}
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');(out/'demo.html').write_text(document('Approve the destination. Follow the observations.','<article><h2>One creation. Separate evidence claims.</h2><p>This run used synthetic approval and a local HTTPS fixture. Provider acknowledgment and matching read-back are adapter observations. Neither proves independent custody or that this request caused a pre-existing object.</p></article><pre>'+html.escape(json.dumps(result,indent=2))+'</pre>'));return result
    finally:fixture.tearDown()
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True);a=p.parse_args();r=run(a.out);print(json.dumps({'object_creations':r['object_creations'],'external_uploads':0,'viewer':str(Path(a.out)/'demo.html')}))
