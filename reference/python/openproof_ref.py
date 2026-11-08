#!/usr/bin/env python3
"""Separately implemented v1 verifier. Does not call or import the Rust implementation."""
import hashlib,json,re,struct,sys,unicodedata
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
MAX=1_048_576
P=2**255-19
D=(-121665*pow(121666,P-2,P))%P
L=2**252+27742317777372353535851937790883648493

def need(ok,message):
    if not ok:raise ValueError(message)
def pairs(items):
    out={}
    for k,v in items:
        need(k not in out,'duplicate JSON field');out[k]=v
    return out
def bad_number(_):raise ValueError('non-u64 number')
def load_bytes(data):
    need(len(data)<=MAX,'input exceeds 1 MiB')
    return json.loads(data.decode('utf-8'),object_pairs_hook=pairs,parse_float=bad_number,parse_constant=bad_number)
def read(path):
    with open(path,'rb') as f:return load_bytes(f.read(MAX+1))
def fields(value,required,optional=()):
    need(type(value) is dict,'object required')
    need(set(required)<=value.keys()<=set(required)|set(optional),'missing or unknown fields')
def text(s):
    need(type(s) is str and 0<len(s.encode('utf-8'))<=1024 and all(unicodedata.category(c)!='Cc' for c in s),'invalid text')
def hx(s,n):
    need(type(s) is str and re.fullmatch('[0-9a-f]{'+str(n*2)+'}',s) is not None,'noncanonical hex')
    return bytes.fromhex(s)
def integer(n):need(type(n) is int and 0<=n<2**64,'u64 required')
def frame(n):return struct.pack('>Q',n)
def encode(v):
    if v is None:return b'\x00'
    if v is False:return b'\x01'
    if v is True:return b'\x02'
    if type(v) is int:integer(v);return b'\x03'+frame(v)
    if type(v) is str:
        raw=v.encode('utf-8');return b'\x04'+frame(len(raw))+raw
    if type(v) is list:return b'\x05'+frame(len(v))+b''.join(encode(x) for x in v)
    if type(v) is dict:return b'\x06'+frame(len(v))+b''.join(encode(k)+encode(v[k]) for k in sorted(v,key=lambda x:x.encode('utf-8')))
    raise ValueError('unsupported canonical type')
def canonical(v):
    raw=b'OPEC\x01'+encode(v);need(len(raw)<=MAX,'canonical value too large');return raw
# Small-order checks supplement the OpenSSL-backed Ed25519 primitive. No signing primitive is reimplemented.
def point(raw):
    n=int.from_bytes(raw,'little');sign=n>>255;y=(n&((1<<255)-1))%P
    x2=((y*y-1)*pow((D*y*y+1)%P,P-2,P))%P
    x=pow(x2,(P+3)//8,P)
    if (x*x)%P!=x2:x=(x*pow(2,(P-1)//4,P))%P
    need(x*x%P==x2,'invalid Edwards point')
    if x%2!=sign:x=(-x)%P
    return x,y
def double(a):
    x,y=a;q=D*x*x*y*y%P
    return 2*x*y*pow((1+q)%P,P-2,P)%P,(y*y+x*x)*pow((1-q)%P,P-2,P)%P
def nonweak(raw):
    a=point(raw)
    for _ in range(3):a=double(a)
    need(a!=(0,1),'weak Edwards point')
def public(s):
    raw=hx(s,32);nonweak(raw);return Ed25519PublicKey.from_public_bytes(raw)
def spec(v):
    fields(v,['tool','resource','arguments_sha256']);text(v['tool']);text(v['resource']);hx(v['arguments_sha256'],32)
def validate(kind,v):
    if kind=='authorization':
        fields(v,['version','run_id','nonce','audience','actor_key','policy_sha256','action','not_before','expires_at'])
        for n in ['run_id','nonce','audience']:text(v[n])
        public(v['actor_key']);hx(v['policy_sha256'],32);spec(v['action']);integer(v['not_before']);integer(v['expires_at']);need(v['not_before']<=v['expires_at'],'invalid time window')
    elif kind=='action':
        fields(v,['version','authorization_sha256','action','claimed_at']);hx(v['authorization_sha256'],32);spec(v['action']);integer(v['claimed_at'])
    elif kind=='receipt':
        fields(v,['version','action_sha256','observed_at','outcome','output_sha256']);hx(v['action_sha256'],32);integer(v['observed_at']);hx(v['output_sha256'],32);need(v['outcome'] in ['succeeded','failed'],'invalid outcome')
    else:raise ValueError('unsupported kind')
    need(v['version']=='openproof/1','unsupported version')
def preimage(kind,v):validate(kind,v);return b'OpenProof/v1/'+kind.encode()+b'\0'+canonical(v)
def digest(kind,v):return hashlib.sha256(preimage(kind,v)).hexdigest()
def signature(kind,s,key):
    fields(s,['payload','signature']);raw=hx(s['signature'],64)
    need(int.from_bytes(raw[32:],'little')<L,'noncanonical scalar')
    nonweak(raw[:32]);need((int.from_bytes(raw[:32],'little')&((1<<255)-1))<P,'noncanonical R')
    public(key).verify(raw,preimage(kind,s['payload']))
def verify(b,c):
    fields(b,['authorization','action'],['receipt'])
    fields(c,['authority_key','actor_key','executor_key','run_id','nonce','audience','policy_sha256','expected_action','now'])
    for n in ['authority_key','actor_key','executor_key','run_id','nonce','audience','policy_sha256']:need(type(c[n]) is str,'context string required')
    integer(c['now']);spec(c['expected_action'])
    signature('authorization',b['authorization'],c['authority_key']);a=b['authorization']['payload']
    need(a['actor_key']==c['actor_key'],'actor mismatch');signature('action',b['action'],c['actor_key']);x=b['action']['payload']
    for n in ['run_id','nonce','audience','policy_sha256']:need(a[n]==c[n],'context mismatch')
    need(a['action']==c['expected_action']==x['action'],'action mismatch')
    need(x['authorization_sha256']==digest('authorization',a),'authorization binding mismatch')
    need(a['not_before']<=c['now']<=a['expires_at'],'authorization not valid at supplied time')
    need(a['not_before']<=x['claimed_at']<=c['now'],'invalid claim time')
    result='authorized_claim_only'
    if b.get('receipt') is not None:
        need(c['executor_key'] not in [c['actor_key'],c['authority_key']],'executor key must differ')
        signature('receipt',b['receipt'],c['executor_key']);r=b['receipt']['payload']
        need(r['action_sha256']==digest('action',x),'receipt binding mismatch')
        need(x['claimed_at']<=r['observed_at']<=c['now'],'invalid receipt time')
        result='executor_reported_success' if r['outcome']=='succeeded' else 'executor_reported_failure'
    return {'assurance':result,'external_effects_proven':False,'replay_protection_enforced':False}
if __name__=='__main__':
    try:
        if len(sys.argv)!=3:raise ValueError('usage: openproof_ref.py BUNDLE TRUSTED_CONTEXT')
        print(json.dumps(verify(read(sys.argv[1]),read(sys.argv[2])),indent=2))
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError,OverflowError) as e:
        print('openproof-ref: '+str(e),file=sys.stderr);sys.exit(1)
    except Exception as e:
        print('openproof-ref: '+type(e).__name__,file=sys.stderr);sys.exit(1)
