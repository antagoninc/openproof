#!/usr/bin/env python3
"""Consume bounded pages into an already root-pinned durable verifier."""
import argparse,json
from pathlib import Path
from witness_workflow import call,save,ref

def consume(receiver,verifier,signed_trust,checkpoint,out):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700)
    signed=ref.read(signed_trust);cp=ref.read(checkpoint)
    save(out/'trust.json',signed['payload']);save(out/'signed-trust.json',signed);save(out/'checkpoint.json',cp)
    start=call(['page-progress',verifier])['count']+1;initial=start-1;pages=[]
    while True:
        if start>cp['payload']['count']:
            page=dict(version='openproof-history-page/1',start=start,receipts=[],requests=[],checkpoint=cp)
        else:page=call(['export-page',receiver,out/'trust.json',start],cp)
        name=f'page-{start:08}.json';save(out/name,page) # Retain before durable progress advances.
        result=call(['verify-page',verifier,signed_trust,checkpoint],page);pages.append(name)
        if result['checkpoint_complete']:break
        if result['processed']<start:raise RuntimeError('page made no progress')
        start=result['processed']+1
    save(out/'result.json',dict(assessment=result,base_count=initial,pages=pages,standalone_history=initial==0,trust_anchor='preinstalled verifier root; not supplied by bundle'))
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['receiver','verifier','signed-trust','checkpoint','out']:p.add_argument('--'+name,required=True)
    a=p.parse_args();print(json.dumps(consume(a.receiver,a.verifier,a.signed_trust,a.checkpoint,a.out),indent=2))
if __name__=='__main__':main()
