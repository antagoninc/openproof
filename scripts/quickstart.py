#!/usr/bin/env python3
"""One-command local demo setup. No Docker or external model account required."""
import argparse,os,shutil,subprocess,sys,uuid,webbrowser
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--no-open',action='store_true');p.add_argument('--check',action='store_true',help='Build and run the lab, then exit instead of starting the owner app');a=p.parse_args()
    if sys.version_info<(3,11):raise SystemExit('Use Python 3.11 or newer.')
    missing=[x for x in ['cargo','go'] if not shutil.which(x)]
    if missing:raise SystemExit('Install these prerequisites first: '+', '.join(missing)+'. See README.md.')
    os.chdir(ROOT);(ROOT/'outputs').mkdir(exist_ok=True)
    python=ROOT/'outputs/local-venv/bin/python'
    def run(cmd,cwd=ROOT,env=None):subprocess.run(list(map(str,cmd)),cwd=cwd,env=env,check=True)
    if not python.exists():run([sys.executable,'-m','venv',python.parent.parent])
    run([python,'-m','pip','install','-r',ROOT/'scripts/requirements.txt','jsonschema==4.25.1'])
    run(['cargo','build','--workspace','--locked'])
    tools=ROOT/'outputs/tooling';tools.mkdir(exist_ok=True);go=tools/'openproof-go-verify'
    run(['go','build','-o',go,'.'],ROOT/'reference/go-witness',dict(os.environ,GOMODCACHE=str(tools/'go-mod'),GOCACHE=str(tools/'go-cache'),GOTOOLCHAIN='local'))
    out=ROOT/'outputs'/('welcome-'+uuid.uuid4().hex[:12])
    run([python,ROOT/'scripts/assurance_lab.py','--out',out,'--go-binary',go])
    print('Recorded experiment explorer: '+str(out/'lab.html'),flush=True)
    if not a.no_open:webbrowser.open((out/'lab.html').as_uri())
    if not a.check:
        cmd=[python,ROOT/'scripts/owner_app.py','--home',out/'owner-workspace','--demo','--session-file',out/'owner-session.json']
        if not a.no_open:cmd+=['--open']
        else:print('Private session link will be in '+str(out/'owner-session.json')+'; keep it secret.',flush=True)
        run(cmd)
if __name__=='__main__':
    try:main()
    except (subprocess.CalledProcessError,KeyboardInterrupt):sys.exit(1)
