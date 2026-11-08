#!/usr/bin/env python3
"""Export only signed public evidence. Trust anchor and checkpoint are provisioned separately."""
import argparse,hashlib,json,shutil
from pathlib import Path
from witness_workflow import call,save,ref,home_lock,require_admission

def export_history(home,out):
    h=Path(home).resolve();out=Path(out).resolve()
    with home_lock(h):
        require_admission(h);out.mkdir(parents=True,exist_ok=False,mode=0o700);entries=[];start=1
        def entry(value):
            name=f'entry-{len(entries):06}.json';save(out/name,value)
            entries.append({'file':name,'sha256':hashlib.sha256((out/name).read_bytes()).hexdigest()})
            if len(entries)>4096:raise ValueError('Archive entry capacity')
        def pages(signed,cp):
            nonlocal start
            # Historical mode verifies signatures at the recorded checkpoint time;
            # current freshness is the offline verifier's separate final-pin requirement.
            trust_path=out/'working-trust.json';trust_path.write_text(json.dumps(signed['payload']))
            while start<=cp['payload']['count']:
                page=call(['export-page-historical',h/'receiver/state',trust_path,start],cp)
                entry(dict(kind='page',signed_trust=signed,page=page));start+=len(page['receipts'])
            # Always retain a final checkpoint, including an empty epoch after handover.
            page=dict(version='openproof-history-page/1',start=start,receipts=[],requests=[],checkpoint=cp)
            entry(dict(kind='page',signed_trust=signed,page=page));trust_path.unlink()
        for epoch in sorted((h/'epochs').glob('*')) if (h/'epochs').exists() else []:
            old=ref.read(epoch/'old-trust-signed.json');handover=ref.read(epoch/'handover.json');pages(old,handover['old_root']['payload']['checkpoint'])
            entry(dict(kind='handover',old_signed_trust=old,handover=handover))
        signed=ref.read(h/'trust-signed.json');cp=call(['checkpoint',h/'witness/state',h/'witness/key.secret',h/'trust.json'])
        if cp['payload']['count']!=call(['head',h/'receiver/state'])['count']:raise RuntimeError('Witness must catch up before archive export')
        pages(signed,cp)
        save(out/'manifest.json',{'version':'openproof-portable-history/1','entries':entries})
        # This copy is convenient evidence, not a substitute for a separately trusted pin.
        save(out/'checkpoint-copy.json',cp)
        from history_viewer import render
        render(out)
        return {'archive':str(out),'entries':len(entries),'count':cp['payload']['count'],'trust_root_included':False,'checkpoint_requires_independent_provisioning':True}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('home');p.add_argument('--out',required=True);a=p.parse_args();print(json.dumps(export_history(a.home,a.out),indent=2))
