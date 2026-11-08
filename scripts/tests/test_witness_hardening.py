import contextlib,io,json,shutil,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from witness_workflow import Broker,initialize,call,upgrade_trust,renew
from witness_mcp import dispatch
from witness_client import Client
class Hardening(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT/'outputs');self.h=Path(self.tmp.name)/'roles';initialize(self.h);self.b=Broker(self.h)
    def tearDown(self):self.tmp.cleanup()
    def approve(self,doc='test'):
        p=self.b.propose(doc,0,'synthetic')
        with contextlib.redirect_stdout(io.StringIO()):self.b.approve(p['proposal_id'],reader=lambda _:'APPROVE '+p['content_sha256'][:12])
        return p['proposal_id']
    def test_mcp_has_opaque_ids_local_labels_and_fixed_errors(self):
        identity=self.approve()
        with Client(self.h) as client:
            r=client.tool('document_commit',{'proposal_id':identity})
            self.assertNotIn('evidence_directory',r);self.assertEqual(len(r['evidence_id']),64)
            self.assertEqual(r['status'],'local_consistency_check');self.assertEqual(r['verification_status'],'local_consistency_verified')
            self.assertNotIn(str(self.h),json.dumps(r))
        request={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'document_commit','arguments':{'proposal_id':identity}}}
        with patch.object(self.b,'commit',side_effect=RuntimeError('/private/secret/path sensitive stderr')):r=dispatch(self.b,request,True)
        self.assertEqual(r['content'][0]['text'],'operation_failed')
    def test_legacy_home_requires_explicit_upgrade_before_effect(self):
        identity=self.approve();shutil.rmtree(self.h/'root');shutil.rmtree(self.h/'verifier');(self.h/'trust-signed.json').unlink();(self.h/'root-public.json').unlink()
        import sqlite3
        for role in ['receiver','witness']:
            db=sqlite3.connect(self.h/role/'state/state.db');db.execute('DROP TABLE role_anchor');db.commit();db.close()
        with self.assertRaisesRegex(RuntimeError,'upgrade-trust'):self.b.commit(identity)
        self.assertEqual(call(['head',self.h/'receiver/state'])['count'],0)
        self.assertEqual(upgrade_trust(self.h)['installed_epoch'],2)
        self.assertEqual(self.b.commit(identity)['document_version'],1)
        self.assertEqual(renew(self.h)['installed_epoch'],3)
        self.assertEqual(upgrade_trust(self.h)['installed_epoch'],3)
        self.assertEqual(self.b.commit(identity)['document_version'],1)
    def test_trust_tampering_is_not_verified(self):
        identity=self.approve();signed=json.loads((self.h/'trust-signed.json').read_text());signed['payload']['epoch']+=1;(self.h/'trust-signed.json').write_text(json.dumps(signed))
        r=self.b.commit(identity);self.assertEqual(r['verification_status'],'not_verified');self.assertEqual(r['status'],'witnessed_evidence_failed')
    def test_renewal_uses_authenticated_payload_and_missing_root_is_not_replaced(self):
        trusted=json.loads((self.h/'trust-signed.json').read_text())['payload']
        edited=dict(trusted);edited['authority']=edited['receiver'];(self.h/'trust.json').write_text(json.dumps(edited))
        self.assertEqual(renew(self.h)['installed_epoch'],2)
        self.assertEqual(json.loads((self.h/'trust.json').read_text())['authority'],trusted['authority'])
        (self.h/'root/key.secret').unlink()
        with self.assertRaisesRegex(RuntimeError,'refusing replacement'):upgrade_trust(self.h)
        self.assertFalse((self.h/'root/key.secret').exists())
    def test_expired_upgrade_candidate_is_retired(self):
        # Simulate an interrupted legacy upgrade whose candidate has expired.
        import sqlite3,time
        (self.h/'trust-signed.json').unlink()
        current=json.loads((self.h/'trust.json').read_text());pending=dict(current);pending['epoch']=2;pending['expires_at']=int(time.time())-1
        (self.h/'trust-upgrade.json').write_text(json.dumps(pending))
        result=upgrade_trust(self.h);self.assertGreaterEqual(result['installed_epoch'],2)
        self.assertFalse((self.h/'trust-upgrade.json').exists());self.assertEqual(len(list(self.h.glob('trust-upgrade-abandoned-*'))),1)
    def test_mutated_plain_trust_cannot_authorize_a_new_effect(self):
        identity=self.approve();t=json.loads((self.h/'trust.json').read_text());t['epoch']=2**63-1;(self.h/'trust.json').write_text(json.dumps(t))
        r=self.b.commit(identity);self.assertEqual(r['status'],'not_committed');self.assertEqual(call(['head',self.h/'receiver/state'])['count'],0)
    def test_evidence_capacity_stops_new_effect_and_does_not_delete_evidence(self):
        identity=self.approve()
        for i in range(1000):(self.h/'evidence'/str(i)).mkdir()
        r=self.b.commit(identity);self.assertEqual(r['status'],'not_committed');self.assertEqual(r['error_code'],'evidence_storage_capacity')
        self.assertEqual(call(['head',self.h/'receiver/state'])['count'],0);self.assertEqual(len(list((self.h/'evidence').iterdir())),1000)
    def test_repeated_same_second_commit_reuses_evidence(self):
        identity=self.approve();first=self.b.commit(identity)
        self.assertEqual(first['verification_status'],'local_consistency_verified')
        # Existing approved artifact remains immutable through every retry.
        raw=self.b.file('approved',identity).read_bytes()
        for _ in range(3):self.assertEqual(self.b.commit(identity)['document_version'],1)
        self.assertEqual(self.b.file('approved',identity).read_bytes(),raw)
if __name__=='__main__':unittest.main()
