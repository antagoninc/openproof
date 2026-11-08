#!/usr/bin/env python3
"""Enable incremental evidence pages for an owner home (calls the Rust broker)."""

import os, uuid
from pathlib import Path
from witness_workflow import call, save


def replace_json(path, value):
    path = Path(path)
    tmp = path.with_name("." + path.name + "-" + uuid.uuid4().hex)
    save(tmp, value)
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def enable(home):
    return call(["enable-paging", Path(home).resolve()])
