"""Reviewer export rejects changed source and runtime paths; archives are reproducible."""
import contextlib,hashlib,io,json,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
import package_external_review as pack
class ReviewPackage(unittest.TestCase):
    def test_reproducible_snapshot_and_rejected_source_changes(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'outputs') as d:
            d=Path(d);source=d/'source';source.mkdir();(source/'README.md').write_text('Public synthetic source\n');v=d/'validation';v.mkdir()
            m={'README.md':hashlib.sha256((source/'README.md').read_bytes()).hexdigest()};(v/'source-manifest.json').write_text(json.dumps(m));(v/'SUMMARY.md').write_text('Synthetic validation test\n')
            steps=[dict(name=n,exit_code=0) for n in ['format','clippy','tests','python-agent-tests','go-tests','witness-conformance','release','rustsec']];(v/'steps.json').write_text(json.dumps(steps))
            with patch.object(pack,'ROOT',source),contextlib.redirect_stdout(io.StringIO()):
                a=pack.package(d/'one',v);b=pack.package(d/'two',v);self.assertEqual(a['sha256'],b['sha256'])
                with tarfile.open(a['archive']) as tar:self.assertTrue(all('outputs' not in Path(n).parts for n in tar.getnames()))
                (source/'README.md').write_text('modified')
                with self.assertRaises(ValueError):pack.package(d/'changed',v)
                for name in ['../outside','/absolute','outputs/key.secret','key.pem','.env.prod']:
                    (v/'source-manifest.json').write_text(json.dumps({name:'00'*32}))
                    with self.assertRaises(ValueError):pack.package(d/'unsafe',v)
                (v/'source-manifest.json').write_text(json.dumps(m));(v/'steps.json').write_text(json.dumps(steps[:-1]))
                with self.assertRaises(ValueError):pack.package(d/'no-audit',v)
