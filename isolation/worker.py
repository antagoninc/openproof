#!/usr/bin/env python3
"""Unprivileged proposal signer and synthetic boundary probes. No host mounts or API key."""
import base64,hashlib,json,os,socket,sys,time
sys.path.insert(0,"/app")
import openproof_ref as ref
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
status=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
if status.get('Seccomp','').strip()!='2' or status.get('NoNewPrivs','').strip()!='1':raise RuntimeError('required kernel restrictions absent')
job=ref.load_bytes(sys.stdin.buffer.read(32769))
if job['mode']=='receipt':
    import openproof_trust as trust
    report=trust.verify(job['bundle'],job['context'],job['snapshot'],job['anchor'],int(time.time()),'current')
    output=base64.b64decode(job['output'],validate=True)
    if hashlib.sha256(output).hexdigest()!=job['bundle']['receipt']['payload']['output_sha256']:raise ValueError('receipt artifact mismatch')
    print(json.dumps(dict(receipt_verified=True,assurance=report['assurance'],external_effects_proven=False)));sys.exit(0)
if job['mode']=='crash':os._exit(17)
if job['mode']=='hang':time.sleep(120)
if job['mode']=='flood':
    sys.stdout.write('x'*70000);sys.stdout.flush();sys.exit(0)
if job['mode']=='probe':
    checks={'seccomp_filter_active':status['Seccomp'].strip()=='2','no_new_privileges':status['NoNewPrivs'].strip()=='1','non_root':os.getuid()!=0,'no_api_key':'ANTHROPIC_API_KEY' not in os.environ}
    for name,path in [('host_canary',job['canary_path']),('executor_key',job['executor_path']),('replay_state',job['state_path']),('docker_socket','/var/run/docker.sock')]:
        try:
            with open(path,'rb') as f:f.read(1)
            checks[name+'_blocked']=False
        except OSError:checks[name+'_blocked']=True
    try:
        with open('/app/unauthorized-write','w') as f:f.write('probe')
        checks['rootfs_write_blocked']=False
    except OSError:checks['rootfs_write_blocked']=True
    try:os.setuid(0);checks['root_escalation_blocked']=False
    except OSError:checks['root_escalation_blocked']=True
    try:
        with socket.create_connection(('1.1.1.1',443),timeout=2):checks['network_blocked']=False
    except OSError:checks['network_blocked']=True
    print(json.dumps(checks));sys.exit(0)
args=base64.b64decode(job['arguments'],validate=True)
if len(args)>8192:raise ValueError('report too large')
scope=dict(job['authorization']['payload']['action'])
if job['mode']=='destination':scope['resource']='file:///unauthorized/report.txt'
if job['mode']=='altered':args+=b'\nunauthorized change'
action=dict(version='openproof/1',authorization_sha256=ref.digest('authorization',job['authorization']['payload']),action=scope,claimed_at=job['time'])
key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(job['actor_seed']))
print(json.dumps(dict(action=dict(payload=action,signature=key.sign(ref.preimage('action',action)).hex()),arguments=base64.b64encode(args).decode())))
