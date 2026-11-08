import json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from witness_workflow import initialize,renew,install_trust,call
class Admin(unittest.TestCase):
    def test_renewal_persists_floor_and_rejects_rollback(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            home=Path(d)/'roles';initialize(home);old=Path(d)/'old.json';old.write_bytes((home/'trust.json').read_bytes())
            self.assertEqual(renew(home)['installed_epoch'],2)
            with self.assertRaises(RuntimeError):install_trust(home,old)
    def test_partial_install_can_retry_same_configuration(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            home=Path(d)/'roles';initialize(home);value=json.loads((home/'trust.json').read_text());value['epoch']=2
            new=Path(d)/'new.json';new.write_text(json.dumps(value));original=call
            def fail_witness(args,value=None):
                if 'witness/state' in str(args):raise RuntimeError('synthetic unavailable witness')
                return original(args,value)
            with patch('witness_workflow.call',side_effect=fail_witness),self.assertRaises(RuntimeError):install_trust(home,new)
            self.assertEqual(json.loads((home/'trust.json').read_text())['epoch'],1)
            self.assertEqual(install_trust(home,new)['installed_epoch'],2)
if __name__=='__main__':unittest.main()
