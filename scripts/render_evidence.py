#!/usr/bin/env python3
"""Static, offline, script-free evidence viewer. Verifies inputs when rendered, never trusts saved status."""
import argparse,datetime,hashlib,html,json,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'reference/python'))
import openproof_ref as ref
import openproof_trust as trust
E=lambda v:html.escape(str(v),quote=True)
def inside(root,path):
    resolved=path.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve()):raise ValueError('artifact path escapes run directory')
    return resolved
def render(run,out):
    run=Path(run).resolve();out=Path(out)
    if out.exists():raise ValueError('viewer output must be new')
    def read_run(name):return ref.read(inside(run,run/name))
    execution=read_run('execution.json');jobs=inside(run,run/'state/jobs');job=inside(jobs,Path(execution['artifact_directory']))
    files={n:inside(job,job/n) for n in ['bundle.json','context.json','output.bin']}
    b=ref.read(files['bundle.json']);c=ref.read(files['context.json']);snapshot=read_run('trust.json');anchor=read_run('anchor.json')
    with files['output.bin'].open('rb') as f:output=f.read(ref.MAX+1)
    if len(output)>ref.MAX:raise ValueError('artifact too large')
    now=int(time.time());verified=False;detail=''
    try:
        report=trust.verify(b,c,snapshot,anchor,now,'historical')
        if not b.get('receipt') or hashlib.sha256(output).hexdigest()!=b['receipt']['payload']['output_sha256']:raise ValueError('artifact digest mismatch')
        verified=True;detail='Signatures, authorized scope, trust snapshot and exact saved bytes checked.'
    except Exception as e:detail='Verification failed: '+str(e)
    provider=read_run('provider.json');isolation=read_run('isolation.json');checks=read_run('checks.json')
    auth=b['authorization']['payload'];action=b['action']['payload'];receipt=b.get('receipt',{}).get('payload',{})
    status='Verified at render time' if verified else 'Verification failed'
    stamp=datetime.datetime.fromtimestamp(now,datetime.timezone.utc).isoformat()
    def panel(title,value):return '<details><summary>'+E(title)+'</summary><pre>'+E(json.dumps(value,indent=2))+'</pre></details>'
    content=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; img-src 'none'">
<title>OpenProof · Evidence inspection</title><style>
:root{{color-scheme:dark;--bg:#0b1221;--panel:#141f32;--line:#293b55;--ink:#e8eff8;--muted:#a9b9cd;--accent:#70ddc0}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.65 system-ui,sans-serif}}main{{max-width:1120px;margin:auto;padding:40px 24px 70px}}nav{{display:flex;justify-content:space-between;gap:20px;border-bottom:1px solid var(--line);padding-bottom:20px}}a{{color:var(--accent)}}small,.muted{{color:var(--muted)}}h1{{font-size:clamp(32px,5vw,56px);line-height:1.12;letter-spacing:-2px;margin:34px 0 18px}}h2{{font-size:23px}}h3{{margin-top:0}}.badge{{display:inline-block;border:1px solid var(--accent);color:var(--accent);border-radius:30px;padding:5px 13px}}.failed{{color:#ffb5b5;border-color:#ffb5b5}}.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:28px 0}}article,section,details{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;margin-top:16px}}.step{{color:var(--accent);font-size:13px;letter-spacing:2px}}.value{{word-break:break-word;font-family:ui-monospace,monospace;font-size:13px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font:14px/1.7 ui-monospace,monospace}}summary{{cursor:pointer;font-weight:600}}.notice{{border-left:3px solid #e8bb73;padding-left:18px;color:var(--muted)}}footer{{margin-top:30px;color:var(--muted);font-size:13px}}@media(max-width:700px){{.grid{{grid-template-columns:1fr}}nav{{flex-direction:column}}}}
</style></head><body><main><nav><strong>ANTAGON / OPENPROOF</strong><div><a href="#artifact">Report</a> · <a href="#evidence">Evidence</a></div></nav>
<h1>One action.<br>A traceable evidence chain.</h1><span class="badge {'failed' if not verified else ''}">{E(status)}</span><p>{E(detail)}</p>
<p class="notice">This view records verification at {E(stamp)}. It is a static local report, not continuous monitoring. Regenerate it to check changed files or newer trust data. The anchor in this demonstration is locally supplied; it is not an external identity certificate.</p>
<div class="grid"><article><div class="step">01 / AUTHORIZED</div><h3>{E(auth['action']['tool'])}</h3><p class="value">{E(auth['action']['resource'])}</p><small>Exact report bytes and policy are bound to the authorization.</small></article><article><div class="step">02 / EXECUTOR REPORTED</div><h3>{E(receipt.get('outcome','No receipt'))}</h3><p>Actor claim → executor receipt</p><small>A signature authenticates the executor's statement, not independent observation.</small></article><article><div class="step">03 / ARTIFACT</div><h3>{'Matches receipt' if verified else 'Check failed'}</h3><p>{len(output):,} bytes</p><small>Verification includes the saved output digest.</small></article></div>
<section id="artifact"><h2>Generated report</h2><p class="muted">Provider label: {E(provider.get('provider'))}. Provider metadata is recorded by the broker, not cryptographically attested by the model service.</p><pre>{E(output.decode('utf-8',errors='replace'))}</pre><p class="value">SHA-256 · {hashlib.sha256(output).hexdigest()}</p></section>
<section id="evidence"><h2>Inspect the records</h2><p class="muted">Raw records stay local. Report text is displayed as text, never executed as HTML.</p>
{panel('Authorization',b['authorization'])}{panel('Actor action claim',b['action'])}{panel('Executor receipt',b.get('receipt'))}{panel('Trusted context and root anchor',dict(context=c,anchor=anchor))}{panel('Broker-recorded worker configuration and probes',isolation)}{panel('Recorded adversarial checks',checks)}{panel('Provider metadata',provider)}</section>
<footer>Experimental · Offline inspection · No external resources or scripts · No production-security certification</footer></main></body></html>'''
    out.write_text(content)
    return verified
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('run');a.add_argument('--out',required=True);args=a.parse_args();sys.exit(0 if render(Path(args.run),Path(args.out)) else 1)
