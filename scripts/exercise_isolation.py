#!/usr/bin/env python3
"""Opt-in real Docker failure tests; fixture jobs only, no model calls."""
import argparse,json,subprocess,sys,time,signal
from pathlib import Path
from isolation_runner import worker,docker,ENV
p=argparse.ArgumentParser();p.add_argument('--image-id-file',required=True);a=p.parse_args();image=Path(a.image_id_file).read_text().strip()
def containers():return set(docker(['ps','-aq','--filter','name=^/openproof-worker-']).stdout.split())
before=containers();results={}
for mode,expected,limit in [('crash','isolated worker failed',5),('hang','worker deadline exceeded',1),('flood','worker output exceeds limit',5)]:
    try:worker(image,{'mode':mode},timeout=limit)
    except RuntimeError as e:
        if expected not in str(e):raise
        results[mode]={'rejected':True,'reason':str(e)}
    else:raise AssertionError(mode+' accepted')
    assert containers()==before,'worker leaked after '+mode
# Interrupt the host while a real worker is running; finally must remove it.
code='import sys;from isolation_runner import worker;worker(sys.argv[1],{"mode":"hang"})'
child=subprocess.Popen([sys.executable,'-c',code,image],cwd=Path(__file__).parent,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
    deadline=time.monotonic()+10
    while containers()==before:
        if child.poll() is not None or time.monotonic()>deadline:raise RuntimeError('interrupt test worker did not start')
        time.sleep(.1)
    child.send_signal(signal.SIGINT);child.communicate(timeout=15)
    assert child.returncode!=0 and containers()==before,'interrupted worker not cleaned'
    results['host_interrupt']={'rejected':True,'cleanup_confirmed':True}
finally:
    if child.poll() is None:child.kill();child.communicate(timeout=5)
print(json.dumps({'results':results,'new_containers_remaining':sorted(containers()-before),'external_model_calls':0},indent=2))
