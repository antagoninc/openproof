#!/usr/bin/env python3
"""Render inert evidence summaries; only the Go verifier establishes verification."""
import argparse, datetime, hashlib, html, json, os, re, subprocess, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
STYLE = '''body{background:#0b1322;color:#e5edf8;font:16px/1.65 system-ui;margin:auto;padding:48px 24px;max-width:1000px}h1{font-size:clamp(32px,6vw,56px);line-height:1.1}h2{color:#8ae3c6}article,details{background:#142238;padding:22px;border:1px solid #314760;border-radius:14px;margin:16px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}a{color:#8ae3c6}small{color:#bccadd}summary{cursor:pointer;font-weight:700}code{overflow-wrap:anywhere}strong{color:#8ae3c6}'''
def document(title, body):
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>'+html.escape(title)+'</title><style>'+STYLE+'</style><main><small>ANTAGON / OPENPROOF · EXPERIMENTAL</small><h1>'+html.escape(title)+'</h1>'+body+'</main></html>'
def bounded_json(path, limit=1048576):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>limit:raise ValueError('Expected bounded regular evidence file')
    with path.open('rb') as f:raw=f.read(limit+1)
    if len(raw)>limit:raise ValueError('Evidence file too large')
    return json.loads(raw)
def render(directory):
    directory=Path(directory);manifest=bounded_json(directory/'manifest.json')
    entries=manifest['entries']
    if not isinstance(entries,list) or len(entries)>4096:raise ValueError('Archive capacity')
    rows=[];total=0
    for e in entries:
        name=e['file']
        if not isinstance(name,str) or not re.fullmatch(r'entry-[0-9]{6}\.json',name):raise ValueError('Unsafe evidence path')
        value=bounded_json(directory/name);raw=json.dumps(value,indent=2,ensure_ascii=False);total+=len(raw.encode())
        if total>256*1024*1024:raise ValueError('Archive capacity')
        rows.append('<details><summary>'+html.escape(name+' · '+str(value.get('kind','unknown')))+'</summary><pre>'+html.escape(raw)+'</pre></details>')
    body='<article><h2>Evidence browser — not a verification result</h2><p>This page displays supplied records. It does not verify signatures or establish trust. Re-run the offline verifier with your separately trusted genesis root and current checkpoint.</p><p>A checkpoint copy inside this folder is convenience data, not an independently trusted pin. Complete history does not prove model truth or physical effects.</p></article><p>'+str(len(entries))+' record files. Expand any record to inspect the exact supplied fields.</p>'+''.join(rows)
    (directory/'viewer.html').write_text(document('Follow the evidence.',body))
    (directory/'VERIFY.txt').write_text('OpenProof portable history / 1\n\nviewer.html is an unverified display. Do not trust bundled HTML as a verifier.\nUse your separately obtained OpenProof source and Go verifier.\n\npython scripts/verify_history.py ARCHIVE_DIRECTORY --root TRUSTED_GENESIS_ROOT_HEX --checkpoint SEPARATELY_TRUSTED_CHECKPOINT.json --go-binary PATH_TO_YOUR_GO_VERIFIER --out NEW_REPORT_DIRECTORY\n\nCurrent verification requires a fresh checkpoint (300 seconds) matching the archive. Ask the operator for refreshed evidence and obtain the pin through your trusted channel. Do not backdate your clock to make old evidence pass.\nPrivate keys are not needed. Document contents are public to anyone receiving this archive; review disclosure before sharing.\n')

def verify(directory, root, checkpoint, binary, out):
    # Absolute local paths only: no extraction, networking, or executable from archive.
    directory=Path(directory).resolve();checkpoint=Path(checkpoint).resolve();binary=Path(binary).resolve();out=Path(out).resolve()
    if not re.fullmatch('[0-9a-f]{64}',root):raise ValueError('Root must be a separately trusted 32-byte public key')
    if binary.is_relative_to(directory):raise ValueError('Use a verifier obtained separately from the evidence archive')
    if checkpoint.is_relative_to(directory):raise ValueError('Supply the checkpoint from your separate trusted channel, outside the archive')
    out.mkdir(parents=True,exist_ok=False,mode=0o700)
    now=int(time.time())
    r=subprocess.run([str(binary),'verify-archive',root,str(checkpoint),str(directory),str(now)],capture_output=True,text=True,timeout=60)
    result={'status':'rejected','checked_at':datetime.datetime.fromtimestamp(now,datetime.timezone.utc).isoformat(),'trusted_genesis_root':root,'independent_operators_established':False,'physical_effects_proven':False}
    if r.returncode==0:
        checked=json.loads(r.stdout)
        if checked.get('status') not in ['portable_history_verified','unknown_due_to_disclosed_gap']:raise ValueError('Unexpected verifier response')
        result.update(checked)
    result['verifier_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    body='<article><h2>'+html.escape(result['status'])+'</h2><p>Recorded offline check at '+html.escape(result['checked_at'])+'. This report can be edited and is not a signed attestation. It is not a continuously fresh verification.</p><pre>'+html.escape(json.dumps(result,indent=2))+'</pre></article><p>Signatures authenticate statements under the supplied root and pin. They do not establish independent operators, model truth, or physical effects. A rejection may mean stale, malformed, incomplete or altered evidence; do not infer a specific attack from rejection alone.</p>'
    (out/'report.html').write_text(document('Your verification result.',body))
    return result
