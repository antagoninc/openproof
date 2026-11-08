#!/bin/zsh
set -eu
cd -- "${0:A:h}"
exec target/debug/openproof-witness owner-app --home outputs/owner-home --open
