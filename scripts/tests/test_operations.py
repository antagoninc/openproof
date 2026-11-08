"""Operational boundaries: receipt-only recovery and staged TLS retirement."""
import datetime,http.client,json,os,ssl,sys,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from witness_workflow import initialize,call,ref
from owner_app import Owner
from paged_workflow import enable
from recovery_center import inventory,recover,rotation_status
from owner_rotation import prepare
from certificate_lifecycle import stage,activate,current,inspect_certificate,load_generation
from role_service import RoleServer
from tls_fixtures import certificates
class Operations(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT/'outputs');self.d=Path(self.tmp.name);self.h=self.d/'home';initialize(self.h);enable(self.h);self.o=Owner(self.h)
    def tearDown(self):self.tmp.cleanup()
    def approval(self):
        identity=self.o.broker.propose('report',0,'Operations fixture')['proposal_id'];r=self.o.review(identity);self.o.approve(identity,r['review_token']);return identity
    def test_receipt_only_recovery_never_dispatches_and_recovers_outage(self):
        identity=self.approval();real=call
        def no_receive(args,value=None):
            if args[0]=='receive':raise AssertionError('Recovery dispatched')
            return real(args,value)
        with patch('witness_workflow.call',side_effect=no_receive),self.assertRaises(ValueError):recover(self.o,identity)
        self.assertEqual(call(['head',self.h/'receiver/state'])['count'],0)
        self.assertFalse(inventory(self.o)['items'][0]['can_recover'])
        def outage(args,value=None):
            if args[0]=='witness':raise RuntimeError('Synthetic witness outage')
            return real(args,value)
        with patch('witness_workflow.call',side_effect=outage):self.assertEqual(self.o.broker.commit(identity)['status'],'committed_unwitnessed')
        report=inventory(self.o);self.assertEqual(report['heads'],{'receiver':1,'witness':0});self.assertTrue(report['items'][0]['can_recover'])
        with patch('witness_workflow.call',side_effect=no_receive):self.assertEqual(recover(self.o,identity)['verification_status'],'local_consistency_verified')
        self.assertEqual(call(['head',self.h/'receiver/state'])['count'],1)
    def test_expired_partial_rotation_inventory_stays_paused(self):
        p=self.approval();self.o.broker.commit(p);prepared=prepare(self.h)
        self.assertTrue(rotation_status(self.h)['can_resume'])
        with patch('recovery_center.time.time',return_value=prepared['expires_at']+1):
            r=rotation_status(self.h);self.assertEqual(r['status'],'expired_partial_handover');self.assertFalse(r['can_resume'])
        self.assertTrue((self.h/'rotation-pending.json').exists())
        self.assertFalse(inventory(self.o)['items'][0]['can_recover'])
    def test_certificate_inspection_bounds_and_failed_stage(self):
        pki=certificates(self.d);now=datetime.datetime.now(datetime.timezone.utc)
        self.assertEqual(inspect_certificate(self.d/'server.pem')['status'],'expiring')
        self.assertEqual(inspect_certificate(self.d/'server.pem',now=now+datetime.timedelta(hours=2))['status'],'expired')
        self.assertEqual(inspect_certificate(self.d/'server.pem',now=now-datetime.timedelta(hours=2))['status'],'not_yet_valid')
        directory=self.d/'tls'
        with self.assertRaises(ssl.SSLError):stage(directory,self.d/'server.pem',self.d/'client.key',self.d/'ca.pem',[pki['client']])
        self.assertIsNone(current(directory))
        (self.d/'server.key').chmod(0o644)
        with self.assertRaises(ValueError):stage(directory,self.d/'server.pem',self.d/'server.key',self.d/'ca.pem',[pki['client']])
    def test_live_tls_overlap_retirement_and_invalid_generation_fail_closed(self):
        pki=certificates(self.d);directory=self.d/'tls'
        first=stage(directory,self.d/'server.pem',self.d/'server.key',self.d/'ca.pem',[pki['client']]);activate(directory,first['generation'],None)
        server=RoleServer('receiver',self.h/'receiver/state',self.h/'receiver/key.secret',self.h/'trust.json',self.h/'trust-signed.json',None,None,None,None,tls_bundle=directory);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def request(who='client',hostname='127.0.0.1'):
            ctx=ssl.create_default_context(cafile=self.d/'ca.pem');ctx.load_cert_chain(self.d/(who+'.pem'),self.d/(who+'.key'))
            c=http.client.HTTPSConnection(hostname,server.server_port,context=ctx,timeout=3)
            try:c.request('POST','/v1/head','{}',{'Content-Type':'application/json'});r=c.getresponse();r.read();return r.status
            finally:c.close()
        try:
            self.assertEqual(request(),200);self.assertEqual(request('unlisted'),403)
            overlap=stage(directory,self.d/'server-renewed.pem',self.d/'server-renewed.key',self.d/'ca.pem',[pki['client'],pki['unlisted']]);activate(directory,overlap['generation'],first['generation'])
            self.assertEqual(request(),200);self.assertEqual(request('unlisted'),200)
            retired=stage(directory,self.d/'server.pem',self.d/'server.key',self.d/'ca.pem',[pki['unlisted']])
            with self.assertRaises(ValueError):activate(directory,retired['generation'],first['generation'])
            self.assertEqual(current(directory),overlap['generation'])
            # A connection admitted under the old generation must reconnect after activation.
            ctx=ssl.create_default_context(cafile=self.d/'ca.pem');ctx.load_cert_chain(self.d/'client.pem',self.d/'client.key')
            held=http.client.HTTPSConnection('127.0.0.1',server.server_port,context=ctx,timeout=3);held.connect()
            activate(directory,retired['generation'],overlap['generation'])
            held.request('POST','/v1/head','{}',{'Content-Type':'application/json'});reply=held.getresponse();self.assertEqual(reply.status,409);reply.read();held.close()
            self.assertEqual(request(),403);self.assertEqual(request('unlisted'),200)
            # Invalid staged data cannot replace the active pointer.
            broken=stage(directory,self.d/'server.pem',self.d/'server.key',self.d/'ca.pem',[pki['unlisted']]);(directory/'generations'/broken['generation']/'server.pem').write_text('invalid')
            with self.assertRaises(ValueError):activate(directory,broken['generation'],retired['generation'])
            self.assertEqual(current(directory),retired['generation']);self.assertEqual(request('unlisted'),200)
            # Corrupting the active generation does not fall back to old permissions.
            (directory/'generations'/retired['generation']/'server.pem').write_text('invalid')
            with self.assertRaises((ConnectionError,ssl.SSLError,http.client.HTTPException)):request('unlisted')
            self.assertTrue(thread.is_alive())
            repaired=stage(directory,self.d/'server-renewed.pem',self.d/'server-renewed.key',self.d/'ca.pem',[pki['unlisted']]);activate(directory,repaired['generation'],retired['generation'])
            self.assertEqual(request('unlisted'),200);self.assertEqual(request(),403)
        finally:server.shutdown();server.server_close();thread.join(timeout=5)
    def test_benchmark_and_seeded_crash_campaign_smoke(self):
        from operations_benchmark import run as benchmark
        from recovery_campaign import run as campaign
        go=os.environ.get('OPENPROOF_GO_VERIFY',str(ROOT/'outputs/tooling/openproof-go-verify'))
        result=benchmark(self.d/'measurements',go,2,128,(2,))
        self.assertEqual(result['rows'][0]['effects'],2);self.assertEqual(result['rows'][0]['commit']['samples'],2);self.assertEqual(result['rows'][0]['offline_verify']['samples'],5)
        results=campaign(self.d/'crashes',3,42);self.assertEqual({r['crash_after'] for r in results},{'receive','witness','verify-page'});self.assertTrue(all(r['recovered'] for r in results))
