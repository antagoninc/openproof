#!/usr/bin/env python3
"""Read-only owner snapshot. Saved outcomes are observations, not fresh verification."""
import argparse,datetime,html,json
from pathlib import Path
from witness_workflow import call,ref

def render(home,out):
    home=Path(home).resolve();e=lambda x:html.escape(str(x),quote=True)
    rows=[];counts={k:0 for k in ['Approved','Committed','Witnessed','Fresh check','Needs attention']}
    for file in sorted((home/'approved').glob('*.json')):
        receipt=None;status='Approved';detail='No receipt observed';fresh='Not checked'
        try:
            request=ref.read(file);receipt=call(['recover',home/'receiver/state'],request)
            if receipt:status='Committed';detail='Receiver database version '+str(receipt['payload']['document_version'])
        except Exception:status='Needs attention';detail='Could not inspect durable receipt'
        evidence=[]
        for record in (home/'evidence').glob('*/assessment.json'):
            try:
                if ref.read(record).get('proposal_id')==file.stem:evidence.append(record.parent)
            except Exception:pass
        if evidence:
            latest=max(evidence,key=lambda p:p.stat().st_mtime_ns)
            try:
                result=call(['verify',home/'trust.json',latest/'checkpoint.json'],ref.read(latest/'package.json'))
                if result['complete_history']:
                    status='Fresh check';fresh='Stateless signatures and history pass now'
                else:status='Needs attention';fresh='Disclosed gap: completeness unknown'
            except Exception:status='Needs attention';fresh='Stale, changed, or unavailable evidence; refresh required'
        if receipt:
            try:
                if call(['head',home/'witness/state'])['count']>=receipt['payload']['sequence']:
                    counts['Witnessed']+=1
            except Exception:pass
        counts[status]+=1
        rows.append('<tr><td><code>'+e(file.stem[:16])+'</code></td><td>'+e(status)+'</td><td>'+e(detail)+'</td><td>'+e(fresh)+'</td></tr>')
    cards=''.join('<article><span>'+e(k)+'</span><strong>'+str(v)+'</strong></article>' for k,v in counts.items())
    text='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>OpenProof · Owner overview</title><style>body{margin:0;background:#091321;color:#e3eaf3;font:16px/1.6 system-ui}main{max-width:1180px;margin:auto;padding:56px 30px}.brand{color:#70ddc0;letter-spacing:.18em;font-size:13px}h1{font-size:clamp(32px,5vw,58px);line-height:1.1;letter-spacing:-.04em}.muted{color:#a7b7ca}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:16px;margin:36px 0}article{background:#132338;border:1px solid #29435a;padding:22px;border-radius:16px}article strong{display:block;font-size:38px;color:#70ddc0}table{width:100%;border-collapse:collapse}td,th{padding:16px;text-align:left;border-bottom:1px solid #29435a;overflow-wrap:anywhere}.table{overflow:auto}.note{padding:22px;border-left:3px solid #70ddc0;background:#102238;margin:30px 0}footer{margin-top:36px;color:#a7b7ca}</style><main><div class="brand">ANTAGON / OPENPROOF</div><h1>Every action.<br>A clearer account.</h1><p class="muted">Read-only owner snapshot · '''+e(datetime.datetime.now(datetime.timezone.utc).isoformat())+'''</p><div class="cards">'''+cards+'''</div><div class="note">A fresh check verifies signatures against this home's configured trust and checkpoint. This snapshot does not authenticate independent operators, persist rollback checks, prove physical effects, or judge whether a model's report is true. Counts are observations, and witnessed counts may overlap other stages.</div><div class="table"><table><tr><th>Proposal</th><th>Current observation</th><th>Execution</th><th>Evidence</th></tr>'''+''.join(rows)+'''</table></div><footer>Recovery: use the owner CLI to retry the same approved proposal. Do not create a replacement authorization to resolve an unknown outcome. Refresh expired trust through the owner workflow, then regenerate this snapshot. This page cannot approve or execute actions.</footer></main></html>'''
    with Path(out).open('x') as f:f.write(text)
    return counts
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('home');p.add_argument('--out',required=True);a=p.parse_args();print(json.dumps(render(a.home,a.out)))
