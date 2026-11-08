"""Host adapter tests use fake responses, never credentials or paid network calls."""
import copy,io,json,os,sys,tempfile,unittest,urllib.error
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'reference/python'))
import claude_report as claude
import render_evidence as viewer
import openproof_ref as ref
import openproof_trust as trust
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
class Provider(unittest.TestCase):
    def call(self,value):
        class Opener:
            def open(inner,request,timeout):
                self.assertEqual(request.full_url,'https://api.anthropic.com/v1/messages')
                body=json.loads(request.data);self.assertLessEqual(body['max_tokens'],1024);self.assertNotIn('tools',body)
                self.assertEqual(body['messages'][0]['content'],claude.PROMPT)
                return io.BytesIO(value if isinstance(value,bytes) else json.dumps(value).encode())
        with patch.dict(os.environ,{'ANTHROPIC_API_KEY':'test-placeholder-not-a-secret'}),patch('urllib.request.build_opener',return_value=Opener()):return claude.generate()
    def test_text_only_and_no_key_in_metadata(self):
        text,metadata=self.call({'content':[{'type':'text','text':'A report'}],'stop_reason':'end_turn','model':'test-model','usage':{'input_tokens':1}})
        self.assertEqual(text,b'A report');self.assertNotIn('test-placeholder-not-a-secret',json.dumps(metadata))
    def test_truncated_empty_malformed_and_oversized_responses_fail(self):
        for value in [b'{',b' '*65537,{'content':[],'stop_reason':'end_turn'},{'content':[{'type':'text','text':'partial'}],'stop_reason':'max_tokens'}]:
            with self.subTest(value_type=type(value).__name__),self.assertRaises(RuntimeError):self.call(value)
    def test_redirect_is_not_followed(self):
        with self.assertRaises(RuntimeError):claude.NoRedirect().redirect_request(None,None,None,None,None,None)
    def test_missing_key_fails_before_network(self):
        with patch.dict(os.environ,{},clear=True),patch('urllib.request.build_opener') as opener,self.assertRaises(RuntimeError):claude.generate()
        opener.assert_not_called()
    def test_http_errors_do_not_log_response_or_key(self):
        with patch.dict(os.environ,{'ANTHROPIC_API_KEY':'test-placeholder-not-a-secret'}),patch('urllib.request.OpenerDirector.open',side_effect=urllib.error.HTTPError('https://api.anthropic.com',401,'private detail',{},None)):
            with self.assertRaisesRegex(RuntimeError,'^Claude request rejected: HTTP 401$'):claude.generate()
class BrokerCleanup(unittest.TestCase):
    def test_setup_failure_removes_executor_seed(self):
        import isolated_agent
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            base=Path(d);image=base/'image';image.write_text('sha256:'+'0'*64);out=base/'run'
            original=Path.write_text;observed=[]
            def fail_canary(path,*args,**kwargs):
                if path.name=='host-only-canary':
                    observed.append((out/'executor.secret').exists());raise OSError('synthetic setup failure')
                return original(path,*args,**kwargs)
            with patch.object(Path,'write_text',fail_canary),patch.object(sys,'argv',['pilot','--out',str(out),'--image-id-file',str(image),'--provider','fixture']),patch('isolated_agent.worker') as worker,self.assertRaisesRegex(OSError,'synthetic setup failure'):
                isolated_agent.main()
            worker.assert_not_called();self.assertEqual(observed,[True]);self.assertFalse((out/'executor.secret').exists())
class Viewer(unittest.TestCase):
    def fixture(self,root):
        job=root/'state/jobs/test';job.mkdir(parents=True)
        b=ref.read(ROOT/'fixtures/v1/bundle.json');c=ref.read(ROOT/'fixtures/v1/context.json');s=ref.read(ROOT/'fixtures/trust-v1/snapshot.json');a=ref.read(ROOT/'fixtures/trust-v1/anchor.json')
        text=b'<script>alert("test")</script>\nReport';b['receipt']['payload']['output_sha256']=__import__('hashlib').sha256(text).hexdigest()
        key=Ed25519PrivateKey.from_private_bytes(bytes([3])*32);b['receipt']['signature']=key.sign(ref.preimage('receipt',b['receipt']['payload'])).hex()
        for path,value in [(job/'bundle.json',b),(job/'context.json',c),(root/'execution.json',{'artifact_directory':str(job)}),(root/'trust.json',s),(root/'anchor.json',a),(root/'provider.json',{'provider':'fixture'}),(root/'isolation.json',{}),(root/'checks.json',{'claimed_pass':True})]:path.write_text(json.dumps(value))
        (job/'output.bin').write_bytes(text);return job
    def test_valid_evidence_is_escaped_and_has_no_scripts(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            root=Path(d);self.fixture(root)
            with patch('time.time',return_value=100):self.assertTrue(viewer.render(root,root/'view.html'))
            html=(root/'view.html').read_text();self.assertIn('&lt;script&gt;',html);self.assertNotIn('<script>',html);self.assertIn("default-src 'none'",html)
    def test_tamper_cannot_reuse_saved_pass_status(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            root=Path(d);job=self.fixture(root);(job/'output.bin').write_bytes(b'tampered')
            with patch('time.time',return_value=100):self.assertFalse(viewer.render(root,root/'view.html'))
            self.assertIn('Verification failed',(root/'view.html').read_text())
    def test_arbitrary_file_and_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            root=Path(d);job=self.fixture(root);(job/'output.bin').unlink();(job/'output.bin').symlink_to(ROOT/'README.md')
            with self.assertRaisesRegex(ValueError,'escapes'):viewer.render(root,root/'view.html')
            (root/'execution.json').write_text(json.dumps({'artifact_directory':str(ROOT)}))
            with self.assertRaisesRegex(ValueError,'escapes'):viewer.render(root,root/'view.html')
    def test_jobs_directory_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            root=Path(d);job=self.fixture(root);outside=root/'outside';job.parent.rename(outside)
            other=root/'other-run';other.mkdir();(other/'state').mkdir();(other/'state/jobs').symlink_to(outside)
            (other/'execution.json').write_text(json.dumps({'artifact_directory':str(outside/'test')}))
            with self.assertRaisesRegex(ValueError,'escapes'):viewer.render(other,other/'view.html')
    def test_untrusted_anchor_fails(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            root=Path(d);self.fixture(root);a=ref.read(root/'anchor.json');a['root_key']=ref.read(ROOT/'fixtures/v1/context.json')['actor_key'];(root/'anchor.json').write_text(json.dumps(a))
            with patch('time.time',return_value=100):self.assertFalse(viewer.render(root,root/'view.html'))
if __name__=='__main__':unittest.main()
