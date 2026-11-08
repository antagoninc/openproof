#!/bin/zsh
set -eu
cd -- "${0:A:h}"
exec outputs/local-venv/bin/python scripts/owner_app.py --open
