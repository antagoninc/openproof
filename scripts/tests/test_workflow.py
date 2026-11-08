"""Negative checks for approval, portability, cleanup and credential separation."""
import base64,copy,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'reference/python'))
import approval,portable,isolation_runner as runner,openproof_ref as ref
import test_agent

class Approval(unittest.TestCase):
    def test_decline_and_changed_digest_do_not_approve(self):
        for answer in ['','yes','APPROVE wrong']:
            with self.subTest(answer=answer),self.assertRaisesRegex(RuntimeError,'declined'):
                approval.approve(b'report',Path('/demo'),reader=lambda _:answer)
    def test_approval_binds_captured_bytes_and_escapes_controls(self):
        import hashlib,io
        report=b'Hello\x1b[2J';digest=hashlib.sha256(report).hexdigest()
        with patch('sys.stdout',new_callable=io.StringIO) as output:
            result=approval.approve(report,Path('/demo'),reader=lambda _:'APPROVE '+digest[:12])
        self.assertNotIn('\x1b',output.getvalue());self.assertEqual(result['report_sha256'],digest)
        self.assertNotEqual(result['report_sha256'],hashlib.sha256(report+b'changed').hexdigest())
    def test_noninteractive_input_rejected(self):
        with patch('sys.stdin.isatty',return_value=False),self.assertRaisesRegex(RuntimeError,'interactive'):
            approval.approve(b'report',Path('/demo'))
    def test_broker_decline_precedes_signing_and_execution(self):
        import isolated_agent
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            image=Path(d)/'image';image.write_text('sha256:'+'0'*64);out=Path(d)/'run'
            with patch.object(sys,'argv',['pilot','--out',str(out),'--image-id-file',str(image),'--provider','fixture','--approval','interactive']),patch('approval.approve',side_effect=RuntimeError('declined')),patch('isolated_agent.worker') as worker,self.assertRaisesRegex(RuntimeError,'declined'):
                isolated_agent.main()
            worker.assert_not_called();self.assertFalse((out/'authorization.json').exists());self.assertFalse((out/'executor.secret').exists())

class Portable(unittest.TestCase):
    def fixture(self,root):
        test_agent.Viewer().fixture(root);target=root/'portable.json';portable.export(root,target)
        return ref.read(target),ref.read(root/'anchor.json')
    def test_roundtrip_no_local_paths_or_anchor(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            package,anchor=self.fixture(Path(d));self.assertNotIn(d,json.dumps(package));self.assertNotIn('anchor',package)
            self.assertTrue(portable.verify(package,anchor,100)['artifact_bytes_match_receipt'])
    def test_modified_artifact_wrong_root_expired_snapshot_and_extra_fields(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            package,anchor=self.fixture(Path(d))
            bad=copy.deepcopy(package);bad['output_base64']=base64.b64encode(b'changed').decode()
            wrong=copy.deepcopy(anchor);wrong['root_key']=ref.read(ROOT/'fixtures/v1/context.json')['actor_key']
            extra=copy.deepcopy(package);extra['anchor']=anchor
            version=copy.deepcopy(package);version['version']='openproof-portable/2'
            for p,a,t in [(bad,anchor,100),(package,wrong,100),(package,anchor,100000),(extra,anchor,100),(version,anchor,100)]:
                with self.subTest(time=t),self.assertRaises(Exception):portable.verify(p,a,t)
    def test_export_new_only_and_rejects_escape(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            root=Path(d);test_agent.Viewer().fixture(root);target=root/'portable.json';portable.export(root,target)
            with self.assertRaises(FileExistsError):portable.export(root,target)
            (root/'trust.json').unlink();(root/'trust.json').symlink_to(ROOT/'fixtures/trust-v1/snapshot.json')
            with self.assertRaisesRegex(ValueError,'escapes'):portable.export(root,root/'bad.json')
    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate'):ref.load_bytes(b'{"version":"a","version":"b"}')

class IsolationFailure(unittest.TestCase):
    def test_missing_docker_fails_before_dispatch(self):
        with patch('isolation_runner.subprocess.run',side_effect=FileNotFoundError()),self.assertRaises(FileNotFoundError):runner.worker('sha256:'+'0'*64,{})
    def test_host_env_drops_credentials(self):
        self.assertNotIn('ANTHROPIC_API_KEY',runner.ENV)
        self.assertNotIn('AWS_SECRET_ACCESS_KEY',runner.ENV)
    def test_cleanup_failure_is_explicit(self):
        def docker(args):
            if args[0]=='context':return subprocess.CompletedProcess([],0,'"unix:///socket"')
            if args[0]=='create':return subprocess.CompletedProcess([],0,'id')
            raise RuntimeError('inspection failed')
        with patch('isolation_runner.docker',side_effect=docker),patch('isolation_runner.subprocess.run',return_value=subprocess.CompletedProcess([],1,b'',b'')),self.assertRaisesRegex(RuntimeError,'cleanup unconfirmed'):
            runner.worker('sha256:'+'0'*64,{})
    def test_interrupt_still_removes_created_container(self):
        calls=[]
        def docker(args):
            calls.append(args[0])
            if args[0]=='context':return subprocess.CompletedProcess([],0,'"unix:///socket"')
            if args[0]=='create':return subprocess.CompletedProcess([],0,'id')
            if args[0]=='inspect':raise KeyboardInterrupt()
            return subprocess.CompletedProcess([],0,'')
        with patch('isolation_runner.docker',side_effect=docker),patch('isolation_runner.subprocess.run',return_value=subprocess.CompletedProcess([],0,b'',b'')) as remove,self.assertRaises(KeyboardInterrupt):runner.worker('sha256:'+'0'*64,{})
        self.assertEqual(remove.call_args.args[0][1:3],['rm','-f']);self.assertIn('ps',calls)

if __name__=='__main__':unittest.main()
