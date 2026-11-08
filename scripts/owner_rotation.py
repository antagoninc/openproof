#!/usr/bin/env python3
"""Stopped-admission planned handover for locally owned development roles."""
import argparse,hashlib,json,os,shutil,time,uuid
from pathlib import Path
from witness_workflow import call,save,ref,home_lock,require_admission
from paged_workflow import finish_paged,replace_json

def copy_private(source,destination):
    source=Path(source);destination=Path(destination);tmp=destination.with_name('.'+destination.name+'-'+uuid.uuid4().hex)
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(source.read_bytes());f.flush();os.fsync(f.fileno())
    os.replace(tmp,destination)
    fd=os.open(destination.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def prepare(home):
    h=Path(home).resolve()
    with home_lock(h):
        require_admission(h)
        if (h/'service-client.json').exists():raise ValueError('Remote operators must coordinate their own handover; local key rotation is unavailable')
        if not (h/'paging.json').exists():raise ValueError('Enable paging first')
        # Do not invalidate still-pending approvals through a receiver-key transition.
        for f in (h/'approved').glob('*.json'):
            if call(['recover',h/'receiver/state'],ref.read(f)) is None:raise ValueError('Resolve every approved action before key handover')
        old=ref.read(h/'trust-signed.json');root=ref.read(h/'root-public.json')['public_key']
        count=call(['head',h/'receiver/state'])['count'];start=call(['head',h/'witness/state'])['count']+1
        for sequence in range(start,count+1):call(['witness',h/'witness/state',h/'witness/key.secret',h/'trust.json'],call(['receipt',h/'receiver/state',sequence]))
        cp=call(['checkpoint',h/'witness/state',h/'witness/key.secret',h/'trust.json'])
        finish_paged(h,hashlib.sha256(ref.canonical(cp)).hexdigest(),cp,{'verification_scope':'local_consistency_check','physical_effects_proven':False,'independent_operators':False})
        jobs=h/'rotations';jobs.mkdir(mode=0o700,exist_ok=True);job=jobs/uuid.uuid4().hex;job.mkdir(mode=0o700)
        newkeys={r:call(['keygen',job/(r+'.secret')])['public_key'] for r in ['root','receiver','witness']}
        nt=dict(old['payload'],epoch=old['payload']['epoch']+1,expires_at=int(time.time())+86400,receiver=newkeys['receiver'],witness=newkeys['witness'])
        save(job/'old-trust-signed.json',old);save(job/'new-trust.json',nt)
        proposal=dict(version='openproof-rotation/1',old_root=root,new_root=newkeys['root'],old_trust_sha256=hashlib.sha256(ref.canonical(old['payload'])).hexdigest(),new_trust=nt,checkpoint=cp,not_before=int(time.time()),expires_at=int(time.time())+300)
        keys={'old_root':h/'root/key.secret','new_root':job/'root.secret','old_receiver':h/'receiver/key.secret','new_receiver':job/'receiver.secret','old_witness':h/'witness/key.secret','new_witness':job/'witness.secret'}
        handover={role:call(['sign-rotation',key],proposal) for role,key in keys.items()}
        call(['check-rotation',root,job/'old-trust-signed.json'],handover);save(job/'handover.json',handover)
        call(['signer-init',job/'signer',newkeys['root']]);signed=call(['sign-trust',job/'root.secret',job/'signer'],nt);save(job/'new-trust-signed.json',signed)
        for role in ['root','receiver','witness']:copy_private(h/role/'key.secret',job/('old-'+role+'.secret'))
        # Persist the admission pause before any role changes. The job retains all
        # old/new keys and signed public records needed to reconcile interruption.
        replace_json(h/'rotation-pending.json',{'job':job.name})
        return {'prepared':True,'job':job.name,'expires_at':proposal['expires_at'],'scope':'same-owner planned rotation, not compromise recovery'}

def resume(home):
    h=Path(home).resolve()
    with home_lock(h):
        pending=ref.read(h/'rotation-pending.json');name=pending['job']
        if not isinstance(name,str) or len(name)!=32 or any(c not in '0123456789abcdef' for c in name):raise ValueError('Invalid rotation job')
        job=h/'rotations'/name;handover=ref.read(job/'handover.json')
        for role,path in [('receiver',h/'receiver/state'),('witness',h/'witness/state'),('verifier',h/'verifier')]:
            if not call(['rotation-applied',path],handover)['applied']:call(['rotate-state',path,job/'old-trust-signed.json'],handover)
        # Idempotent file publication while admission remains paused.
        for role in ['root','receiver','witness']:copy_private(job/(role+'.secret'),h/role/'key.secret')
        signer=h/'root/signer';oldsigner=job/'old-signer'
        if not oldsigner.exists():os.rename(signer,oldsigner)
        if not signer.exists():
            stage=job/'signer-publish'
            if stage.exists():shutil.rmtree(stage)
            shutil.copytree(job/'signer',stage);os.rename(stage,signer)
        nt=ref.read(job/'new-trust.json');signed=ref.read(job/'new-trust-signed.json');root=handover['old_root']['payload']['new_root']
        call(['verifier-install',h/'verifier'],signed)
        for role in ['receiver','witness']:call(['install-signed',h/role/'state',root],signed)
        epoch=h/'epochs'/f'{nt["epoch"]:020}';epoch.mkdir(parents=True,mode=0o700,exist_ok=True)
        for n in ['old-trust-signed.json','handover.json']:copy_private(job/n,epoch/n)
        replace_json(h/'trust-signed.json',signed);replace_json(h/'trust.json',nt);replace_json(h/'root-public.json',{'public_key':root})
        replace_json(job/'complete.json',{'epoch':nt['epoch'],'completed_at':int(time.time())})
        (h/'rotation-pending.json').unlink()
        fd=os.open(h,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
        return {'completed':True,'epoch':nt['epoch'],'admission_resumed':True}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['prepare','resume']);p.add_argument('home');a=p.parse_args();print(json.dumps(globals()[a.operation](a.home),indent=2))
