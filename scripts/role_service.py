#!/usr/bin/env python3
"""Experimental bounded mTLS role transport. Administrative commands stay offline."""
import argparse,hashlib,hmac,json,ssl,subprocess,tempfile
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
from witness_workflow import call,ref

class RoleServer(HTTPServer):
    request_queue_size=8
    def __init__(self,role,state,key,trust,signed_trust,cert,tls_key,ca,clients,host='127.0.0.1',port=0):
        if role not in ['receiver','witness']:raise ValueError('role')
        self.role=role;self.state=Path(state);self.key=Path(key);self.trust=Path(trust)
        root=call(['role-status',self.state])['root']
        if not root:raise ValueError('Provision a pinned role root before serving')
        expected=call(['trust-payload',root],ref.read(signed_trust))
        if ref.read(self.trust)!=expected:raise ValueError('Plain trust differs from authenticated trust')
        self.clients=set(clients)
        if not self.clients or any(len(x)!=64 or any(c not in '0123456789abcdef' for c in x) for x in self.clients):raise ValueError('Client certificate fingerprints required')
        self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);self.context.minimum_version=ssl.TLSVersion.TLSv1_3;self.context.verify_mode=ssl.CERT_REQUIRED;self.context.load_cert_chain(cert,tls_key);self.context.load_verify_locations(cafile=ca)
        super().__init__((host,port),RoleHandler)
    def get_request(self):
        sock,addr=super().get_request();sock.settimeout(5)
        try:return self.context.wrap_socket(sock,server_side=True),addr
        except Exception:sock.close();raise
    def dispatch(self,path,value):
        if path=='/v1/head':ref.fields(value,[]);return call(['head',self.state])
        if path=='/v1/status':ref.fields(value,[]);return call(['role-status',self.state])
        if self.role=='receiver':
            if path=='/v1/document':ref.fields(value,['document']);return call(['document',self.state,value['document']])
            if path=='/v1/export':ref.fields(value,['checkpoint']);return call(['export',self.state,self.trust],value['checkpoint'])
            if path=='/v1/page-historical':
                ref.fields(value,['start','checkpoint','trust']);ref.integer(value['start'])
                # An allowlisted client has read access to this role's history.
                # Caller-supplied historical trust is used only for this read-only
                # export and is never installed or used to authorize an effect.
                with tempfile.NamedTemporaryFile(mode='w+',dir=self.state,prefix='history-',suffix='.json') as f:
                    json.dump(value['trust'],f);f.flush()
                    return call(['export-page-historical',self.state,f.name,value['start']],value['checkpoint'])
            if path=='/v1/receive':ref.fields(value,['request']);return call(['receive',self.state,self.key,self.trust],value['request'])
            if path=='/v1/recover':ref.fields(value,['request']);return call(['recover',self.state],value['request'])
            if path=='/v1/receipt':
                ref.fields(value,['sequence']);ref.integer(value['sequence']);return call(['receipt',self.state,value['sequence']])
            if path=='/v1/page':
                ref.fields(value,['start','checkpoint']);ref.integer(value['start']);return call(['export-page',self.state,self.trust,value['start']],value['checkpoint'])
        if self.role=='witness':
            if path=='/v1/witness':ref.fields(value,['receipt']);return call(['witness',self.state,self.key,self.trust],value['receipt'])
            if path=='/v1/checkpoint':ref.fields(value,[]);return call(['checkpoint',self.state,self.key,self.trust])
        raise ValueError('Unknown operation')
class RoleHandler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def reply(self,code,value):
        raw=json.dumps(value).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(raw)
    def do_POST(self):
        certificate=self.connection.getpeercert(binary_form=True)
        fingerprint=hashlib.sha256(certificate).hexdigest()
        if fingerprint not in self.server.clients:return self.reply(403,{'error':'client_not_authorized'})
        try:
            if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type')!='application/json':raise ValueError('encoding')
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=1048576:raise ValueError('size')
            value=ref.load_bytes(self.rfile.read(size));result=self.server.dispatch(self.path,value);self.reply(200,result)
        except (ValueError,KeyError,TypeError):self.reply(400,{'error':'invalid_operation'})
        except Exception:self.reply(409,{'error':'operation_unconfirmed','recovery':'Read the durable receipt for this exact request before retrying or reporting failure.'})
    def do_GET(self):self.reply(405,{'error':'post_required'})
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['role','state','key','trust','signed-trust','cert','tls-key','ca']:p.add_argument('--'+name,required=True)
    p.add_argument('--client-fingerprint',action='append',required=True);p.add_argument('--bind',default='127.0.0.1');p.add_argument('--port',type=int,default=8443);a=p.parse_args()
    server=RoleServer(a.role,a.state,a.key,a.trust,a.signed_trust,a.cert,a.tls_key,a.ca,a.client_fingerprint,a.bind,a.port)
    print('Authenticated '+a.role+' service listening on '+a.bind+':'+str(server.server_port),flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
if __name__=='__main__':main()
