import os
import hashlib,http.client,json,sys,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from owner_app import Owner,Server
from witness_workflow import initialize,call,ref
from paged_workflow import enable
from portable_history import export_history
class OwnerAppTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'outputs');self.h=Path(self.temp.name)/'home';initialize(self.h);enable(self.h);self.o=Owner(self.h)
    def tearDown(self):self.temp.cleanup()
    def proposed(self):return self.o.broker.propose('report',0,'<script>untrusted text</script>')['proposal_id']
    def test_review_binds_all_fields_and_is_one_use(self):
        identity=self.proposed();review=self.o.review(identity);p=self.o.broker.file('proposals',identity);data=ref.read(p);data['document']='other';p.write_text(json.dumps(data))
        with self.assertRaises(ValueError):self.o.approve(identity,review['review_token'])
        with self.assertRaises(ValueError):self.o.approve(identity,review['review_token'])
        self.assertEqual(call(['head',self.h/'receiver/state'])['count'],0)
    def test_paged_recovery_and_portable_history(self):
        identity=self.proposed();review=self.o.review(identity);self.o.approve(identity,review['review_token'])
        real=call
        def interrupted(args,value=None):
            if args[0]=='witness':raise RuntimeError('synthetic outage')
            return real(args,value)
        with patch('witness_workflow.call',side_effect=interrupted):first=self.o.broker.commit(identity)
        self.assertEqual(first['status'],'committed_unwitnessed')
        recovered=self.o.broker.commit(identity);self.assertEqual(recovered['verification_status'],'local_consistency_verified');self.assertEqual(self.o.broker.commit(identity)['document_version'],1)
        archive=Path(self.temp.name)/'archive';export_history(self.h,archive)
        import subprocess,time
        root=ref.read(self.h/'root-public.json')['public_key']
        cmd=[os.environ.get('OPENPROOF_GO_VERIFY',str(ROOT/'outputs/v0.9/openproof-go-verify')),'verify-archive',root,str(archive/'checkpoint-copy.json'),str(archive),str(int(time.time()))]
        r=subprocess.run(cmd,capture_output=True);self.assertEqual(r.returncode,0,r.stderr)
        manifest=ref.read(archive/'manifest.json');f=archive/manifest['entries'][0]['file'];raw=ref.read(f);raw['page']['requests'][0]['content']='changed';f.write_text(json.dumps(raw));manifest['entries'][0]['sha256']=hashlib.sha256(f.read_bytes()).hexdigest();(archive/'manifest.json').write_text(json.dumps(manifest))
        self.assertNotEqual(subprocess.run(cmd,capture_output=True).returncode,0)
    def test_http_rejects_foreign_origin_missing_cookie_csrf_and_bad_host(self):
        server=Server(self.o,0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            def post(path,body,headers=None):
                c=http.client.HTTPConnection('127.0.0.1',server.server_port);h={'Origin':self.o.origin,'Content-Type':'application/json'};h.update(headers or {});c.request('POST','/api/'+path,json.dumps(body),h);r=c.getresponse();code=r.status;data=r.read();c.close();return code,data
            self.assertEqual(post('session',{'token':self.o.token},{'Origin':'https://attacker.example'})[0],403)
            self.assertEqual(post('session',{'token':self.o.token},{'Host':'attacker.example'})[0],403)
            self.assertEqual(post('session',{'token':'wrong'})[0],403)
            self.assertEqual(post('session',{'token':self.o.token})[0],200)
            value={'document':'report','expected_version':0,'content':'hello'}
            self.assertEqual(post('propose',value)[0],403)
            self.assertEqual(post('propose',value,{'Cookie':'openproof_owner='+self.o.token})[0],403)
            self.assertEqual(post('propose',value,{'Cookie':'openproof_owner='+self.o.token,'X-OpenProof-CSRF':self.o.csrf})[0],200)
        finally:server.shutdown();thread.join();server.server_close()
if __name__=='__main__':unittest.main()

class RotationIntegration(unittest.TestCase):
    setUp=OwnerAppTests.setUp
    tearDown=OwnerAppTests.tearDown
    proposed=OwnerAppTests.proposed
    def test_interrupted_handover_resumes_and_archive_checks_both_epochs(self):
        import owner_rotation,subprocess,time
        identity=self.proposed();r=self.o.review(identity);self.o.approve(identity,r['review_token']);self.o.broker.commit(identity)
        original=ref.read(self.h/'genesis-root.json')['public_key'];owner_rotation.prepare(self.h)
        with self.assertRaises(RuntimeError):self.o.broker.propose('other',0,'paused')
        real=call
        def interrupt(args,value=None):
            if args[0]=='rotate-state' and 'witness/state' in str(args):raise RuntimeError('synthetic role outage')
            return real(args,value)
        with patch('owner_rotation.call',side_effect=interrupt),self.assertRaises(RuntimeError):owner_rotation.resume(self.h)
        self.assertTrue((self.h/'rotation-pending.json').exists());self.assertTrue(owner_rotation.resume(self.h)['completed'])
        self.assertEqual(self.o.broker.commit(identity)['document_version'],1)
        nextid=self.o.broker.propose('report',1,'After planned handover')['proposal_id'];r=self.o.review(nextid);self.o.approve(nextid,r['review_token']);self.assertEqual(self.o.broker.commit(nextid)['document_version'],2)
        archive=Path(self.temp.name)/'rotated-archive';export_history(self.h,archive)
        cmd=[os.environ.get('OPENPROOF_GO_VERIFY',str(ROOT/'outputs/v0.9/openproof-go-verify')),'verify-archive',original,str(archive/'checkpoint-copy.json'),str(archive),str(int(time.time()))]
        checked=subprocess.run(cmd,capture_output=True);self.assertEqual(checked.returncode,0,checked.stderr)
        wrong=list(cmd);wrong[2]=ref.read(self.h/'root-public.json')['public_key'];self.assertNotEqual(subprocess.run(wrong,capture_output=True).returncode,0)
        manifest=ref.read(archive/'manifest.json');rotation=next(x for x in manifest['entries'] if ref.read(archive/x['file'])['kind']=='handover');record=ref.read(archive/rotation['file']);record['handover']['new_witness']['signature']='00'*64;(archive/rotation['file']).write_text(json.dumps(record));rotation['sha256']=hashlib.sha256((archive/rotation['file']).read_bytes()).hexdigest();(archive/'manifest.json').write_text(json.dumps(manifest));self.assertNotEqual(subprocess.run(cmd,capture_output=True).returncode,0)
