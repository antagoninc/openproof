#!/usr/bin/env python3
"""Incremental broker evidence retained before durable verifier advancement."""
import hashlib,json,os,uuid
from pathlib import Path
from witness_workflow import call,save,ref,home_lock,require_admission

def replace_json(path,value):
    path=Path(path);tmp=path.with_name('.'+path.name+'-'+uuid.uuid4().hex);save(tmp,value);os.replace(tmp,path)
    fd=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def enable(home):
    home=Path(home).resolve()
    with home_lock(home):
        require_admission(home)
        call(['enable-pages',home/'receiver/state',home/'trust.json'])
        if not (home/'genesis-root.json').exists():save(home/'genesis-root.json',ref.read(home/'root-public.json'))
        if not (home/'paging.json').exists():save(home/'paging.json',{'version':1})
    return {'paging_enabled':True}

def finish_paged(home,identity,checkpoint,base):
    h=Path(home);signed=ref.read(h/'trust-signed.json')
    eid=hashlib.sha256(ref.canonical([identity,checkpoint,signed])).hexdigest();run=h/'evidence'/eid
    run.mkdir(mode=0o700,exist_ok=True)
    for name,value in [('checkpoint.json',checkpoint),('trust-signed.json',signed)]:
        if not (run/name).exists():save(run/name,value)
        elif ref.read(run/name)!=value:raise ValueError('evidence identity conflict')
    initial=call(['page-progress',h/'verifier'])['count'];progress=initial
    while True:
        if progress==checkpoint['payload']['count']:
            page=dict(version='openproof-history-page/1',start=progress+1,receipts=[],requests=[],checkpoint=checkpoint)
        else:page=call(['export-page',h/'receiver/state',h/'trust.json',progress+1],checkpoint)
        name=f'page-{progress+1:08}.json';path=run/name
        if path.exists():
            if ref.read(path)!=page:raise ValueError('saved page conflict')
        else:save(path,page)
        result=call(['verify-page',h/'verifier',h/'trust-signed.json',run/'checkpoint.json'],page)
        if result['checkpoint_complete']:break
        if result['processed']<=progress:raise RuntimeError('verification made no progress')
        progress=result['processed']
    result.update(base,evidence_status=result['status'],status='local_consistency_check' if result['complete_history'] else 'unknown_due_to_disclosed_gap',verification_status='local_consistency_verified',witness_status='confirmed',evidence_format='incremental_pages',standalone_history=False)
    replace_json(run/'assessment.json',result)
    return dict(result,evidence_id=eid,evidence_directory=str(run))
