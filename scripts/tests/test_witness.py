"""Real local role processes and MCP transport; approvals below are explicitly simulated tests."""
import hashlib,json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from witness_workflow import Broker,initialize,call,timeline
from witness_client import Client
from witness_mcp import dispatch
class Workflow(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'outputs');self.home=Path(self.temp.name)/'roles';initialize(self.home);self.b=Broker(self.home)
    def tearDown(self):self.temp.cleanup()
    def test_no_approval_no_effect_and_no_approval_tool(self):
        with Client(self.home) as client:
            p=client.tool('document_propose',{'document':'test','expected_version':0,'content':'hello'})
            with self.assertRaises(RuntimeError):client.tool('document_commit',{'proposal_id':p['proposal_id']})
            with self.assertRaises(RuntimeError):client.tool('approve',{'proposal_id':p['proposal_id']})
            with self.assertRaises(RuntimeError):client.tool('document_commit',{'proposal_id':p['proposal_id'],'key':'attacker'})
        with self.assertRaises(RuntimeError):call(['document',self.home/'receiver/state','test'])
    def test_real_mcp_approval_commit_retry_and_timeline(self):
        with Client(self.home) as client:
            p=client.tool('document_propose',{'document':'test','expected_version':0,'content':'<script>untrusted</script>'});identity=p['proposal_id']
            self.b.approve(identity,reader=lambda _:'APPROVE '+p['content_sha256'][:12])
            result=client.tool('document_commit',{'proposal_id':identity});again=client.tool('document_commit',{'proposal_id':identity})
        self.assertEqual(result['document_version'],1);self.assertEqual(again['document_version'],1)
        self.assertEqual(call(['document',self.home/'receiver/state','test'])['content'],'<script>untrusted</script>')
        run=self.home/'evidence'/result['evidence_id'];timeline(run/'package.json',self.home/'trust.json',run/'checkpoint.json',run/'view.html');self.assertNotIn('<script>',(run/'view.html').read_text());self.assertIn('stateless_consistency_check',(run/'view.html').read_text());self.assertIn('stateless_inspection',(run/'view.html').read_text())
    def test_declined_approval(self):
        p=self.b.propose('test',0,'hello')
        with self.assertRaisesRegex(RuntimeError,'declined'):self.b.approve(p['proposal_id'],reader=lambda _:'no')
        with self.assertRaises(FileNotFoundError):self.b.commit(p['proposal_id'])
    def test_path_and_oversized_proposals_rejected(self):
        for d,v,c in [('../outside',0,'x'),('ok',True,'x'),('ok',0,'x'*8193)]:
            with self.assertRaises(ValueError):self.b.propose(d,v,c)
        with self.assertRaises(ValueError):self.b.commit('../authority/key.secret')
    def test_commit_resumes_after_missing_witness_response(self):
        p=self.b.propose('test',0,'hello');identity=p['proposal_id'];self.b.approve(identity,reader=lambda _:'APPROVE '+p['content_sha256'][:12])
        q=json.loads(self.b.file('approved',identity).read_text());call(['receive',self.home/'receiver/state',self.home/'receiver/key.secret',self.home/'trust.json'],q)
        self.assertEqual(self.b.commit(identity)['document_version'],1)
    def test_initialization_required_and_unknown_tool(self):
        with self.assertRaises(ValueError):dispatch(self.b,{'jsonrpc':'2.0','id':1,'method':'tools/list'},False)
        result=dispatch(self.b,{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'authority.sign','arguments':{}}},True);self.assertTrue(result['isError'])
if __name__=='__main__':unittest.main()
