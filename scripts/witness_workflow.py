#!/usr/bin/env python3
"""Owner CLI and narrowly scoped document broker. Agent tools cannot approve or select keys/paths."""
import argparse,hashlib,json,os,re,subprocess,sys,time,uuid,fcntl
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from isolation_runner import ENV
ROOT=Path(__file__).resolve().parents[1];BINARY=ROOT/'target/debug/openproof-witness'
sys.path.insert(0,str(ROOT/'reference/python'))
import openproof_ref as ref

def call(args,value=None):
    # Only an owner-created home configuration enables transport. Agent arguments
    # cannot choose destinations, certificate paths, keys or operation routes.
    if len(args)>1:
        state=Path(str(args[1]))
        if state.name=='state' and state.parent.name in ['receiver','witness'] and (state.parent.parent/'service-client.json').exists():
            from role_transport import dispatch
            return dispatch(state.parent.parent,state.parent.name,args,value)
    raw=None if value is None else json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
    if raw and len(raw)>ref.MAX:raise ValueError('input limit')
    r=subprocess.run([str(BINARY),*map(str,args)],input=raw,capture_output=True,env=ENV,timeout=20)
    if r.returncode:raise RuntimeError(r.stderr.decode(errors='replace')[:1000])
    return ref.load_bytes(r.stdout)

def save(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump(value,f,indent=2,ensure_ascii=False);f.flush();os.fsync(f.fileno())

def initialize(home):
    home=Path(home).resolve();home.mkdir(mode=0o700,parents=True,exist_ok=False)
    keys={}
    for role in ['authority','receiver','witness']:
        folder=home/role;folder.mkdir(mode=0o700)
        keys[role]=call(['keygen',folder/'key.secret'])['public_key']
        if role!='authority':call(['init',folder/'state'])
    (home/'proposals').mkdir(mode=0o700);(home/'approved').mkdir(mode=0o700);(home/'evidence').mkdir(mode=0o700)
    (home/'root').mkdir(mode=0o700)
    root=call(['keygen',home/'root/key.secret'])['public_key']
    save(home/'root-public.json',{'public_key':root})
    call(['verifier-init',home/'verifier',root])
    call(['signer-init',home/'root/signer',root])
    save(home/'trust.json',dict(version='openproof-witness/1',epoch=1,expires_at=int(time.time())+86400,previous_authorities=[],revoked_authorities=[],**keys))
    for role in ['receiver','witness']:call(['role-pin',home/role/'state',root])
    signed=call(['sign-trust',home/'root/key.secret',home/'root/signer'],ref.read(home/'trust.json'))
    save(home/'trust-signed.json',signed)
    for role in ['receiver','witness']:call(['install-signed',home/role/'state',root],signed)
    call(['verifier-install',home/'verifier'],signed)
    return {'initialized':str(home),'trust_expires_in_seconds':86400,'roles':'separate keys/processes/state; same host owner'}

@contextmanager
def home_lock(home):
    # One lock inode per private home; never unlink it. All broker processes cooperate.
    fd=os.open(Path(home)/'.broker.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)

def serialized(method):
    @wraps(method)
    def run(self,*args,**kwargs):
        with home_lock(self.home):return method(self,*args,**kwargs)
    return run

class Broker:
    def __init__(self,home):
        self.home=Path(home).resolve()
        if self.home.stat().st_mode&0o077:raise ValueError('broker directory must be private')
    def file(self,folder,identity):
        if not isinstance(identity,str) or not re.fullmatch('[0-9a-f]{64}',identity):raise ValueError('invalid proposal id')
        p=self.home/folder/(identity+'.json')
        if p.is_symlink():raise ValueError('symlinked broker input')
        return p
    @serialized
    def propose(self,document,expected_version,content):
        require_admission(self.home)
        if not isinstance(document,str) or not re.fullmatch('[a-zA-Z0-9_-]{1,80}',document):raise ValueError('invalid document id')
        if type(expected_version)!=int or not 0<=expected_version<2**63-1:raise ValueError('invalid version')
        if not isinstance(content,str) or not 0<len(content.encode())<=8192:raise ValueError('content must be 1..8192 UTF-8 bytes')
        # Only unsigned pending proposals are reclaimable. Approved requests/evidence
        # are never evicted. Owner review captures its own immutable in-memory snapshot.
        pending=sorted((self.home/'proposals').glob('*.json'),key=lambda p:(p.stat().st_mtime_ns,p.name))
        for old in pending:
            if time.time()-old.stat().st_mtime>86400:old.unlink()
        pending=[p for p in pending if p.exists()]
        for old in pending[:max(0,len(pending)-999)]:old.unlink()
        p=dict(document=document,expected_version=expected_version,content=content)
        identity=hashlib.sha256(uuid.uuid4().bytes+json.dumps(p).encode()).hexdigest();save(self.file('proposals',identity),p)
        return {'proposal_id':identity,'state':'awaiting_owner_approval','content_sha256':hashlib.sha256(content.encode()).hexdigest()}
    def approve(self,identity,*,reader=None):
        # Capture exactly what is reviewed, then release the global lock during input.
        # Eviction of the pending file cannot change this captured proposal.
        with home_lock(self.home):
            require_admission(self.home);p=ref.read(self.file('proposals',identity))
        digest=hashlib.sha256(p['content'].encode()).hexdigest()
        if reader is None:
            if not sys.stdin.isatty():raise RuntimeError('owner approval requires interactive terminal')
            reader=input
        print('DOCUMENT UPDATE REVIEW\n'+json.dumps(p,ensure_ascii=True,indent=2))
        print('Receiver-owned document database; no caller-selected filesystem path. SHA-256: '+digest)
        if reader('Type APPROVE '+digest[:12]+': ')!='APPROVE '+digest[:12]:raise RuntimeError('approval declined')
        with home_lock(self.home):
            require_admission(self.home)
            if len(list((self.home/'approved').glob('*.json')))>=1000:raise RuntimeError('approved request capacity; owner archival required')
            q=call(['approve',self.home/'authority/key.secret',self.home/'trust.json'],p)
            save(self.file('approved',identity),q)
            self.file('proposals',identity).unlink(missing_ok=True)
        return {'proposal_id':identity,'state':'approved','expires_at':q['approval']['payload']['expires_at']}
    @serialized
    def commit(self,identity,*,recover_only=False):
        require_admission(self.home)
        q=ref.read(self.file('approved',identity));h=self.home
        if not (h/'trust-signed.json').exists() or not (h/'verifier').is_dir():raise RuntimeError('owner must run upgrade-trust before dispatch')
        root=ref.read(h/'root-public.json')['public_key']
        if any(call(['role-status',h/role/'state'])['root']!=root for role in ['receiver','witness']):raise RuntimeError('owner must run upgrade-trust before dispatch')
        base=dict(proposal_id=identity,verification_scope='local_consistency_check',
                  independent_operators=False,physical_effects_proven=False)
        # Read-only recovery cannot authorize a new mutation. Current admission checks
        # remain unchanged in receive, including expiry, retirement and revocation.
        receipt=call(['recover',h/'receiver/state'],q)
        if receipt is None:
            if recover_only:raise ValueError('No durable receipt; recovery cannot execute an action')
            if not evidence_capacity(h):return dict(base,status='not_committed',execution_status='not_committed',verification_status='not_verified',error_code='evidence_storage_capacity')
            try:receipt=call(['receive',h/'receiver/state',h/'receiver/key.secret',h/'trust.json'],q)
            except Exception:
                # A lost reply may follow commit. Inspect durable state before reporting.
                try:receipt=call(['recover',h/'receiver/state'],q)
                except Exception:return dict(base,status='outcome_unknown',execution_status='unknown',verification_status='not_verified',error_code='receiver_response_unavailable')
                if receipt is None:return dict(base,status='not_committed',execution_status='not_committed',verification_status='not_verified',error_code='admission_failed')
        base.update(execution_status='committed',document=receipt['payload']['document'],document_version=receipt['payload']['document_version'])
        try:
            target=call(['head',h/'receiver/state'])['count']
            start=call(['head',h/'witness/state'])['count']+1
            if target-start>4096:raise RuntimeError('catch-up capacity')
            for sequence in range(start,target+1):
                stored=call(['receipt',h/'receiver/state',sequence])
                call(['witness',h/'witness/state',h/'witness/key.secret',h/'trust.json'],stored)
            # Replaying this exact receipt obtains the witness's current signed head.
            checkpoint=call(['checkpoint',h/'witness/state',h/'witness/key.secret',h/'trust.json']) if (h/'paging.json').exists() else call(['witness',h/'witness/state',h/'witness/key.secret',h/'trust.json'],receipt)
        except Exception:
            return dict(base,status='committed_unwitnessed',verification_status='not_verified',
                        witness_status='confirmation_unavailable',error_code='witness_recovery_required')
        try:
            if not evidence_capacity(h):raise RuntimeError('evidence capacity')
            if (h/'paging.json').exists():
                from paged_workflow import finish_paged
                return finish_paged(h,identity,checkpoint,base)
            package=call(['export',h/'receiver/state',h/'trust.json'],checkpoint)
            # Pin comes directly from the configured witness; local custody is explicit.
            scratch=h/('checkpoint-'+uuid.uuid4().hex+'.json');save(scratch,checkpoint)
            try:result=call(['verify-trusted',h/'verifier',h/'trust-signed.json',scratch],package)
            finally:scratch.unlink(missing_ok=True)
            result['evidence_status']=result['status']
            if result['status']!='unknown_due_to_disclosed_gap':result['status']='local_consistency_check'
            result.update(base,verification_status='local_consistency_verified',witness_status='confirmed')
            eid=hashlib.sha256(json.dumps([identity,checkpoint,ref.read(h/'trust-signed.json')],sort_keys=True).encode()).hexdigest()
            run=h/'evidence'/eid
            if not run.exists():
                import shutil
                stage=h/'evidence'/('.pending-'+uuid.uuid4().hex);stage.mkdir(mode=0o700)
                try:
                    save(stage/'checkpoint.json',checkpoint);save(stage/'package.json',package)
                    save(stage/'assessment.json',result);stage.rename(run)
                finally:
                    if stage.exists():shutil.rmtree(stage)
            return dict(result,evidence_id=eid,evidence_directory=str(run))
        except Exception:
            return dict(base,status='witnessed_evidence_failed',witness_status='confirmed',
                        verification_status='not_verified',error_code='evidence_export_or_verification_failed')

def require_admission(home):
    if (Path(home)/'rotation-pending.json').exists():raise RuntimeError('planned key handover in progress; admission paused')


def evidence_capacity(home):
    # Reserve enough room for the next bounded package and its metadata.
    evidence=Path(home)/'evidence'
    entries=list(evidence.iterdir())
    if len(entries)>=1000:return False
    return sum(p.stat().st_size for p in evidence.rglob('*') if p.is_file())<=62*1024*1024

def install_trust(home,configuration):
    with home_lock(Path(home).resolve()):return _install_trust(home,configuration)

def _install_trust(home,configuration):
    """Owner-only staged update. If one store fails, retry the same retained configuration."""
    home=Path(home).resolve();new=ref.read(configuration);old=ref.read(home/'trust.json')
    if new['receiver']!=old['receiver'] or new['witness']!=old['witness']:raise ValueError('receiver/witness key rotation requires a future migration protocol')
    signed=call(['sign-trust',home/'root/key.secret',home/'root/signer'],new)
    root=ref.read(home/'root-public.json')['public_key']
    for role in ['receiver','witness']:call(['install-signed',home/role/'state',root],signed)
    call(['verifier-install',home/'verifier'],signed)
    signed_pending=home/('signed-trust-publish-'+uuid.uuid4().hex+'.json');save(signed_pending,signed);os.replace(signed_pending,home/'trust-signed.json')
    pending=home/('trust-publish-'+uuid.uuid4().hex+'.json');save(pending,new);os.replace(pending,home/'trust.json')
    return {'installed_epoch':new['epoch'],'expires_at':new['expires_at']}

def renew(home):
    home=Path(home).resolve()
    with home_lock(home):
        trust=authenticated_trust(home);trust['epoch']+=1;trust['expires_at']=int(time.time())+86400
        path=home/('trust-update-'+uuid.uuid4().hex+'.json');save(path,trust);return _install_trust(home,path)

def authenticated_trust(home):
    root=ref.read(Path(home)/'root-public.json')['public_key']
    return call(['trust-payload',root],ref.read(Path(home)/'trust-signed.json'))

def upgrade_trust(home):
    """Explicit owner migration; retain roles/state and a retryable candidate."""
    home=Path(home).resolve()
    with home_lock(home):
        (home/'root').mkdir(mode=0o700,exist_ok=True)
        secret=home/'root/key.secret'
        if not secret.exists() and ((home/'root-public.json').exists() or any(call(['role-status',home/role/'state'])['root'] is not None for role in ['receiver','witness'])):raise RuntimeError('restore the existing root key; refusing replacement')
        root=call(['key-public',secret] if secret.exists() else ['keygen',secret])['public_key']
        if (home/'root-public.json').exists():
            if ref.read(home/'root-public.json')['public_key']!=root:raise ValueError('root mismatch')
        else:save(home/'root-public.json',{'public_key':root})
        if not (home/'verifier').exists():call(['verifier-init',home/'verifier',root])
        if not (home/'root/signer').exists():call(['signer-init',home/'root/signer',root])
        for role in ['receiver','witness']:call(['role-pin',home/role/'state',root])
        candidate=home/'trust-upgrade.json'
        current=authenticated_trust(home) if (home/'trust-signed.json').exists() else ref.read(home/'trust.json')
        now=int(time.time())
        if (home/'trust-signed.json').exists() and current['expires_at']>=now and (not candidate.exists() or ref.read(candidate)['epoch']<=current['epoch']):
            snapshot=home/('upgrade-current-'+uuid.uuid4().hex+'.json');save(snapshot,current)
            try:result=_install_trust(home,snapshot)
            finally:snapshot.unlink(missing_ok=True)
            candidate.unlink(missing_ok=True);return result
        floors=[current['epoch'],call(['signer-floor',home/'root/signer'])['epoch']]
        floors.extend(call(['trust-floor',home/role/'state'])['epoch'] for role in ['receiver','witness'])
        floors.append(call(['trust-floor',home/'verifier'])['epoch'])
        if candidate.exists():
            pending=ref.read(candidate)
            if pending['expires_at']<now or pending['epoch']<max(floors) or (pending['epoch']==current['epoch'] and pending!=current):candidate.rename(home/('trust-upgrade-abandoned-'+uuid.uuid4().hex+'.json'))
        if not candidate.exists():
            current['epoch']=max(floors)+1;current['expires_at']=now+86400;save(candidate,current)
        result=_install_trust(home,candidate);candidate.unlink(missing_ok=True);return result

def timeline(package_path,trust_path,pin_path,out):
    import html
    package=ref.read(package_path);result=call(['verify',trust_path,pin_path],package)
    result['evidence_status']=result['status']
    if result['status']!='unknown_due_to_disclosed_gap':result['status']='stateless_consistency_check'
    result.update(verification_scope='stateless_inspection',verification_status='stateless_consistency_verified',independent_operators=False)
    e=lambda s:html.escape(str(s),quote=True)
    rows=''.join('<tr><td>'+str(r['payload']['sequence'])+'</td><td>'+e(r['payload']['kind'])+'</td><td>'+e(r['payload']['document'])+'</td><td>'+str(r['payload']['document_version'])+'</td><td>'+e(r['payload']['content_sha256'])+'</td></tr>' for r in package['receipts'])
    body='<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>OpenProof witnessed timeline</title><style>body{background:#0b1221;color:#e8eff8;font:16px/1.6 system-ui;margin:3rem;max-width:1100px}h1{font-size:3rem}table{width:100%;border-collapse:collapse}td,th{padding:12px;border-bottom:1px solid #35465b;text-align:left;overflow-wrap:anywhere}pre{white-space:pre-wrap}strong{color:#70ddc0}</style><h1>Authorization → receipt → witness</h1><strong>'+e(result['status'])+'</strong><p>Stateless inspection against caller-supplied trust and checkpoint. This view does not authenticate trust provisioning, establish independent operators, or persist freshness/rollback checks. Receiver assertions concern its document database; physical effects and model truth are not proven.</p><table><tr><th>Sequence</th><th>Event</th><th>Document</th><th>Version</th><th>Stored content digest</th></tr>'+rows+'</table><pre>'+e(json.dumps(result,indent=2))+'</pre>'
    with Path(out).open('x') as f:f.write(body)

def main():
    a=argparse.ArgumentParser(description=__doc__);s=a.add_subparsers(dest='cmd',required=True)
    for name in ['init','approve','commit','propose']:p=s.add_parser(name);p.add_argument('home');p.add_argument('id',nargs='?' if name=='init' else None)
    p=s.add_parser('renew');p.add_argument('home')
    p=s.add_parser('upgrade-trust');p.add_argument('home')
    p=s.add_parser('install-trust');p.add_argument('home');p.add_argument('configuration')
    p=s.add_parser('timeline');p.add_argument('package');p.add_argument('--trust',required=True);p.add_argument('--checkpoint',required=True);p.add_argument('--out',required=True)
    args=a.parse_args()
    if args.cmd=='init':result=initialize(args.home)
    elif args.cmd=='renew':result=renew(args.home)
    elif args.cmd=='upgrade-trust':result=upgrade_trust(args.home)
    elif args.cmd=='install-trust':result=install_trust(args.home,args.configuration)
    elif args.cmd=='timeline':timeline(args.package,args.trust,args.checkpoint,args.out);return
    elif args.cmd=='propose':result=Broker(args.home).propose(**ref.read(args.id))
    else:result=getattr(Broker(args.home),args.cmd)(args.id)
    print(json.dumps(result,indent=2))
if __name__=='__main__':
    try:main()
    except Exception as e:print('OpenProof: '+str(e),file=sys.stderr);sys.exit(1)
