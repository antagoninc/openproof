#!/usr/bin/env python3
"""Verify an extracted archive offline with independently supplied trust."""
import argparse,json,sys
from history_viewer import verify

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive')
    for name in ['root','checkpoint','go-binary','out']:p.add_argument('--'+name,required=True)
    a=p.parse_args();result=verify(a.archive,a.root,a.checkpoint,a.go_binary,a.out);print(json.dumps(result,indent=2))
    return 0 if result['status']=='portable_history_verified' else 1
if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,OSError,TimeoutError) as e:print('Verification unavailable: '+str(e),file=sys.stderr);sys.exit(1)
