#!/usr/bin/env python3
"""Local Linux role separation experiment. No network services or independent admins."""
import argparse,copy,json,os,subprocess,time,uuid
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--image-id-file',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    out=Path(a.out).resolve();out.mkdir(parents=True,mode=0o700,exist_ok=False);public=out/'public';public.mkdir()
    image=Path(a.image_id_file).read_text().strip();assert image.startswith('sha256:')
    endpoint=json.loads(subprocess.check_output(['docker','context','inspect','--format','{{json .Endpoints.docker.Host}}']))
    if not endpoint.startswith('unix://'):raise RuntimeError('local Docker endpoint required')
    names={r:'openproof-'+r+'-'+uuid.uuid4().hex[:12] for r in ['owner','receiver','witness','verifier']};created=[];checks={}
    def command(args,raw=None,ok=True):
        r=subprocess.run(['docker',*map(str,args)],input=raw,capture_output=True,timeout=120)
        if ok and r.returncode:raise RuntimeError(r.stderr.decode(errors='replace')[:1000])
        return r
    def call(role,args,value=None,ok=True):
        raw=None if value is None else json.dumps(value,ensure_ascii=False).encode()
        r=command(['exec','-i',names[role],'openproof-witness',*args],raw,ok)
        return json.loads(r.stdout) if ok else r
    def save(name,v): (public/name).write_text(json.dumps(v,indent=2)+'\n')
    try:
        for role,name in names.items():
            folder=out/role;folder.mkdir(mode=0o700)
            command(['run','-d','--name',name,'--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=64','--memory=256m','--cpus=1','--user',f'{os.getuid()}:{os.getgid()}','--mount',f'type=bind,src={folder},dst=/role','--mount',f'type=bind,src={public},dst=/public,readonly','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--entrypoint','/bin/sleep',image,'infinity']);created.append(name)
        root=call('owner',['keygen','/role/root.secret'])['public_key'];authority=call('owner',['keygen','/role/authority.secret'])['public_key']
        keys={r:call(r,['keygen','/role/key.secret'])['public_key'] for r in ['receiver','witness']}
        trust=dict(version='openproof-witness/1',epoch=1,expires_at=int(time.time())+86400,authority=authority,previous_authorities=[],revoked_authorities=[],**keys);save('trust.json',trust)
        call('owner',['signer-init','/role/signer',root]);signed=call('owner',['sign-trust','/role/root.secret','/role/signer'],trust);save('signed-trust.json',signed);save('root-public.json',{'public_key':root})
        for r in ['receiver','witness']:
            call(r,['role-init','/role/state',root]);call(r,['install-signed','/role/state',root],signed)
        call('verifier',['verifier-init','/role/state',root]);call('verifier',['verifier-install','/role/state'],signed)
        call('receiver',['enable-pages','/role/state','/public/trust.json'])
        q=call('owner',['approve','/role/authority.secret','/public/trust.json'],{'document':'pilot','expected_version':0,'content':'Public synthetic Linux role pilot. Approval is simulated.'});save('request.json',q)
        bad=copy.deepcopy(q);bad['content']='tampered';checks['tampered_request_rejected']=call('receiver',['receive','/role/state','/role/key.secret','/public/trust.json'],bad,False).returncode!=0
        command(['stop','--time','1',names['witness']])
        receipt=call('receiver',['receive','/role/state','/role/key.secret','/public/trust.json'],q);save('receipt.json',receipt)
        checks['witness_outage_observed']=call('witness',['head','/role/state'],ok=False).returncode!=0
        recovered=call('receiver',['recover','/role/state'],q);checks['durable_receipt_recovered']=recovered==receipt
        repeat=call('receiver',['receive','/role/state','/role/key.secret','/public/trust.json'],q);checks['retry_exactly_once']=repeat==receipt and call('receiver',['document','/role/state','pilot'])['version']==1
        command(['start',names['witness']]);cp=call('witness',['witness','/role/state','/role/key.secret','/public/trust.json'],recovered);save('checkpoint.json',cp)
        page=call('receiver',['export-page','/role/state','/public/trust.json','1'],cp);save('page.json',page)
        bad=copy.deepcopy(page);bad['requests'][0]['content']='tampered'
        checks['tampered_page_rejected']=call('verifier',['verify-page','/role/state','/public/signed-trust.json','/public/checkpoint.json'],bad,False).returncode!=0
        result=call('verifier',['verify-page','/role/state','/public/signed-trust.json','/public/checkpoint.json'],page);save('assessment.json',result)
        checks['checkpoint_complete']=result['checkpoint_complete']
        checks['page_replay_rejected']=call('verifier',['verify-page','/role/state','/public/signed-trust.json','/public/checkpoint.json'],page,False).returncode!=0
        package=call('receiver',['export','/role/state','/public/trust.json'],cp);save('package.json',package)
        inspections=json.loads(command(['inspect',*names.values()]).stdout)
        checks['network_disabled']=all(x['HostConfig']['NetworkMode']=='none' for x in inspections)
        checks['nonroot_readonly']=all(x['Config']['User']==f'{os.getuid()}:{os.getgid()}' and x['HostConfig']['ReadonlyRootfs'] for x in inspections)
        checks['separate_private_mounts']=all(len([m for m in x['Mounts'] if m['Destination']=='/role'])==1 for x in inspections)
        checks['receiver_cannot_read_owner_key']=command(['exec',names['receiver'],'test','-e','/owner/root.secret'],ok=False).returncode!=0
        assert all(checks.values()),checks
        (out/'result.json').write_text(json.dumps({'status':'passed','checks':checks,'image_id':image,'engine':command(['version','--format','{{.Server.Version}}']).stdout.decode().strip(),'approval':'simulated synthetic fixture','transport':'host pipes; no remote authenticated service','independent_operators':False,'physical_effects_proven':False,'human_security_review':False},indent=2)+'\n')
        print(json.dumps(checks,indent=2))
    finally:
        for name in created:command(['rm','-f',name],ok=False)
if __name__=='__main__':main()
