#!/usr/bin/env python3
"""Export only signed public evidence (calls the Rust broker). The trust anchor
and a current checkpoint are provisioned separately."""

import argparse, json
from pathlib import Path
from witness_workflow import call


def export_history(home, out):
    return call(["export-history", Path(home).resolve(), Path(out).resolve()])


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("home")
    p.add_argument("--out", required=True)
    a = p.parse_args()
    print(json.dumps(export_history(a.home, a.out), indent=2))
