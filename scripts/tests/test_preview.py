"""Preview regressions: real processes, durable effects, offline trust and hostile displays."""
import hashlib,json,os,shutil,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from witness_workflow import initialize,call,ref
from owner_app import Owner
from paged_workflow import enable
from portable_history import export_history
from history_viewer import render,verify
from assurance_lab import run
GO=os.environ.get('OPENPROOF_GO_VERIFY',str(ROOT/'outputs/v0.9/openproof-go-verify'))
class Preview(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT/'outputs');self.d=Path(self.tmp.name);self.h=self.d/'home';initialize(self.h);enable(self.h);self.o=Owner(self.h)
    def tearDown(self):self.tmp.cleanup()
    def approved(self):
        p=self.o.broker.propose('report',0,'<script>alert("fixture")</script>')['proposal_id'];r=self.o.review(p);self.o.approve(p,r['review_token']);return p
    def test_process_crash_after_durable_receive_then_concurrent_same_retry(self):
        p=self.approved()
        code='''import os,sys
sys.path.insert(0,sys.argv[1]);import witness_workflow
real=witness_workflow.call
def crash(args,value=None):
 result=real(args,value)
 if args[0]=='receive':os._exit(73)
 return result
witness_workflow.call=crash
witness_workflow.Broker(sys.argv[2]).commit(sys.argv[3])
'''
        child=subprocess.run([sys.executable,'-c',code,str(ROOT/'scripts'),str(self.h),p],capture_output=True,timeout=30)
        self.assertEqual(child.returncode,73,child.stderr);self.assertEqual(call(['head',self.h/'receiver/state'])['count'],1);self.assertEqual(call(['head',self.h/'witness/state'])['count'],0)
        children=[subprocess.Popen([sys.executable,str(ROOT/'scripts/witness_workflow.py'),'commit',str(self.h),p],stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(4)]
        for child in children:
            raw,err=child.communicate(timeout=60);self.assertEqual(child.returncode,0,err);r=json.loads(raw);self.assertEqual(r['document_version'],1);self.assertEqual(r['verification_status'],'local_consistency_verified')
        self.assertEqual(call(['head',self.h/'receiver/state'])['count'],1);self.assertEqual(call(['head',self.h/'witness/state'])['count'],1)
    def test_review_timeout_uses_monotonic_clock(self):
        p=self.o.broker.propose('report',0,'review timing')['proposal_id'];r=self.o.review(p)
        at=self.o.reviews[r['review_token']]['time']
        with patch('owner_app.time.monotonic',return_value=at+301),patch('owner_app.time.time',return_value=0):
            with self.assertRaises(ValueError):self.o.approve(p,r['review_token'])
        self.assertEqual(call(['head',self.h/'receiver/state'])['count'],0)
    def test_offline_display_and_independent_anchor_boundary(self):
        self.o.broker.commit(self.approved());archive=self.d/'archive';export_history(self.h,archive)
        page=(archive/'viewer.html').read_text();self.assertNotIn('<script>',page);self.assertIn('&lt;script&gt;',page)
        root=ref.read(self.h/'root-public.json')['public_key']
        with self.assertRaises(ValueError):verify(archive,root,archive/'checkpoint-copy.json',GO,self.d/'bad-pin-report')
        pin=self.d/'external-pin.json';shutil.copyfile(archive/'checkpoint-copy.json',pin)
        good=verify(archive,root,pin,GO,self.d/'good');self.assertEqual(good['status'],'portable_history_verified')
        with patch('history_viewer.time.time',return_value=time.time()+301):
            stale=verify(archive,root,pin,GO,self.d/'stale');self.assertEqual(stale['status'],'rejected')
        with patch('history_viewer.time.time',return_value=1):
            future=verify(archive,root,pin,GO,self.d/'clock-back');self.assertEqual(future['status'],'rejected')
        manifest=ref.read(archive/'manifest.json');manifest['entries'][0]['file']='../external-pin.json';(archive/'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):render(archive)
    def test_lab_exercises_real_tamper_cases(self):
        r=run(self.d/'lab',GO);self.assertEqual(len(r['cases']),8);self.assertTrue(all(x['expected']==x['observed'] for x in r['cases']));self.assertEqual(r['external_model_calls'],0)
