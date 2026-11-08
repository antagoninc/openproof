"""Small synchronous Python SDK for the local MCP broker; no approval/signing API."""
import json,subprocess,sys
from pathlib import Path
from isolation_runner import ENV
class Client:
    def __init__(self,home):
        self.process=subprocess.Popen([sys.executable,str(Path(__file__).with_name('witness_mcp.py')),'--home',str(home)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,env=ENV)
        self.counter=0;self.rpc('initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'openproof-python-client','version':'0.7.2'}})
        self.process.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n');self.process.stdin.flush()
    def rpc(self,method,params):
        self.counter+=1;self.process.stdin.write(json.dumps({'jsonrpc':'2.0','id':self.counter,'method':method,'params':params})+'\n');self.process.stdin.flush()
        response=json.loads(self.process.stdout.readline(1_048_577))
        if response.get('id')!=self.counter or 'error' in response:raise RuntimeError('broker protocol error')
        return response['result']
    def tool(self,name,arguments):
        result=self.rpc('tools/call',{'name':name,'arguments':arguments})
        if result.get('isError'):raise RuntimeError(result['content'][0]['text'])
        return json.loads(result['content'][0]['text'])
    def close(self):
        self.process.stdin.close()
        try:self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:self.process.kill();self.process.wait()
        self.process.stdout.close()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
