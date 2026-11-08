#!/usr/bin/env python3
"""One bounded Claude request. No filesystem discovery, tools, redirects, retries, or key logging."""
import hashlib,json,os,ssl,urllib.request,urllib.error
import certifi
MODEL='claude-haiku-5-5'
PROMPT='''Write a short plain-text project status report (under 500 words) using only these supplied public facts. Do not invent tests, findings or capabilities. OpenProof is an experimental independently authored Rust-first execution assurance project, unpublished. Its v0.4 macOS and Linux builds each passed 80 Rust tests, 224 evidence differential cases and 94 trust differential cases. A scoped independent AI review of 12 Rust crate files found no reportable vulnerabilities under documented assumptions; this is not an external human audit or certification. Receipts are executor assertions, not proof of external effects. Root rotation preserves replay history in intact local state. Backup rollback and compromised-root recovery remain limitations. The next demonstration isolates a proposal-signing worker from executor keys and state. End with two practical limitations. Output report text only.'''
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise RuntimeError('Claude redirect refused')
def generate(model=MODEL):
    key=os.environ.get('ANTHROPIC_API_KEY')
    if not key:raise RuntimeError('Set ANTHROPIC_API_KEY locally; never paste it into chat or project files')
    body=json.dumps({'model':model,'max_tokens':1024,'messages':[{'role':'user','content':PROMPT}]}).encode()
    req=urllib.request.Request('https://api.anthropic.com/v1/messages',data=body,headers={'Content-Type':'application/json','x-api-key':key,'anthropic-version':'2026-10-21'},method='POST')
    # Disable ambient proxy routing so the API credential goes only to the fixed TLS endpoint.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=certifi.where())),NoRedirect())
    try:
        with opener.open(req,timeout=60) as response:
            raw=response.read(65537)
            if len(raw)>65536:raise RuntimeError('Claude response exceeds limit')
    except urllib.error.HTTPError as e:raise RuntimeError('Claude request rejected: HTTP '+str(e.code)) from None
    except (urllib.error.URLError,TimeoutError):raise RuntimeError('Claude connection failed; no automatic retry') from None
    try:
        value=json.loads(raw);text='\n'.join(b['text'] for b in value['content'] if b.get('type')=='text')
        if value.get('stop_reason')!='end_turn' or not text.strip() or len(text.encode())>8192:raise ValueError()
        metadata={'provider':'Anthropic Claude','requested_model':model,'returned_model':value.get('model'),'request_id':value.get('id'),'usage':value.get('usage'),'prompt_sha256':hashlib.sha256(PROMPT.encode()).hexdigest(),'report_sha256':hashlib.sha256(text.encode()).hexdigest(),'external_call':True}
        return text.encode(),metadata
    except (ValueError,KeyError,TypeError):raise RuntimeError('Claude response malformed, truncated or too large') from None
