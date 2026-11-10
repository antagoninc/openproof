#!/usr/bin/env python3
"""Count OpenProof's trusted code (docs/TCB.md) and check it.

    python3 scripts/tcb_count.py            # table and totals
    python3 scripts/tcb_count.py --check    # also fail on any check below

Counts are non-blank lines. Rust test modules (`#[cfg(test)]` or
`#[cfg(all(test, ...))]` followed by `mod`) and Go `_test.go` files are not
counted. In a file listed with `regions`, only the lines between
`// TCB:begin` and `// TCB:end` are counted.

`--check` fails when:
- the trusted code total is over BUDGET;
- a source file of the receiver or role crates is not listed;
- the role binary or the receiver crate depends on another workspace crate
  than `openproof-core` and `openproof-receiver`;
- the review origin serves a file that is not listed, or a listed page or
  module loads one (HTML `src`/`href`, ES module imports).
"""

import argparse, json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The trusted code total may not grow past this without a TCB.md change.
# The aim stated in docs/TCB.md is under 4,000.
BUDGET = 4750
G1, G2, G3 = "G1", "G2", "G3"
# path: (guarantees, what it is trusted for, counting)
TRUSTED = {
    "crates/openproof-core/src/lib.rs": ((G1, G2), "canonical bytes and signatures"),
    "crates/openproof-receiver/src/lib.rs": ((G1, G2), "receiver and witness"),
    "crates/openproof-receiver/src/passkey.rs": ((G1,), "owner passkey checks"),
    "crates/openproof-receiver/src/roles.rs": ((G1, G2), "trust install, export"),
    "crates/openproof-receiver/src/pages.rs": ((G1, G2), "history pages, store bound"),
    "crates/openproof-receiver/src/tlog.rs": ((G2,), "C2SP checkpoints"),
    "crates/openproof-receiver/src/clock.rs": ((G1, G2), "signing clock floor"),
    "crates/openproof-receiver/src/http.rs": ((G1, G2), "request parsing"),
    "crates/openproof-receiver/src/keys.rs": ((G1, G2), "key and file reads"),
    "crates/openproof-receiver/src/files.rs": ((G1, G2), "atomic file writes"),
    "crates/openproof-role/src/main.rs": ((G1, G2), "role service"),
    "scripts/local_roles.py": ((G1,), "account installer, status"),
    "app/review.html": ((G1,), "review page"),
    "app/review.js": ((G1,), "review page"),
    "app/approval.js": ((G1,), "approval check, challenge"),
    "app/common.js": ((G1,), "review page requests"),
    "app/setup.html": ((G1,), "passkey set-up page"),
    "app/setup.js": ((G1,), "passkey set-up page"),
    "crates/openproof-witness/src/owner_app.rs": (
        (G1,),
        "origins, page table",
        "regions",
    ),
    "reference/go-witness/main.go": ((G3,), "Go verifier"),
    "reference/go-witness/archive.go": ((G3,), "Go verifier"),
    "reference/go-witness/passkey.go": ((G3,), "Go verifier"),
    "reference/go-witness/tlog.go": ((G3,), "Go verifier"),
    "scripts/verify_history.py": ((G3,), "verifier wrapper"),
}
# Trusted for what the owner sees, listed apart as before: a style sheet.
STYLE = {"app/base.css": ((G1,), "review page style")}
TEST_MOD = re.compile(r"^#\[cfg\((all\()?test\b")


def count(path, regions=False):
    lines = (ROOT / path).read_text().splitlines()
    if regions:
        kept, inside = [], False
        for line in lines:
            mark = line.strip()
            if mark == "// TCB:begin":
                if inside:
                    raise ValueError(f"{path}: nested TCB:begin")
                inside = True
            elif mark == "// TCB:end":
                if not inside:
                    raise ValueError(f"{path}: TCB:end without begin")
                inside = False
            elif inside:
                kept.append(line)
        if inside or not kept:
            raise ValueError(f"{path}: unbalanced or empty TCB regions")
        lines = kept
    elif path.endswith(".rs"):
        for i, line in enumerate(lines):
            if (
                TEST_MOD.match(line)
                and lines[i + 1 : i + 2]
                and lines[i + 1].startswith("mod ")
            ):
                lines = lines[:i]
                break
    return sum(1 for line in lines if line.strip())


def report():
    rows, totals, total = [], {G1: 0, G2: 0, G3: 0}, 0
    for path, spec in TRUSTED.items():
        n = count(path, len(spec) > 2)
        rows.append((path, n, spec[0], spec[1]))
        total += n
        for g in spec[0]:
            totals[g] += n
    style = {p: count(p) for p in STYLE}
    return dict(files=rows, by_guarantee=totals, total=total, style=style)


def problems(r, budget):
    found = []
    if r["total"] > budget:
        found.append(f"trusted code is {r['total']} lines, over the budget of {budget}")
    for crate in ["openproof-receiver", "openproof-role"]:
        for f in sorted((ROOT / "crates" / crate / "src").rglob("*.rs")):
            rel = str(f.relative_to(ROOT))
            if rel not in TRUSTED:
                found.append(f"{rel} is in a trusted crate but not listed")
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    workspace = {p["name"] for p in meta["packages"]}
    allowed = {
        "openproof-receiver": {"openproof-core"},
        "openproof-role": {"openproof-core", "openproof-receiver"},
    }
    for p in meta["packages"]:
        if p["name"] in allowed:
            inner = {
                d["name"]
                for d in p["dependencies"]
                if d["name"] in workspace and d["kind"] is None
            }
            if inner - allowed[p["name"]]:
                found.append(f"{p['name']} depends on {sorted(inner)}")
    listed = {Path(p).name for p in list(TRUSTED) + list(STYLE) if p.startswith("app/")}
    # Everything the review origin serves (REVIEW_FILES in owner_app.rs).
    source = (ROOT / "crates/openproof-witness/src/owner_app.rs").read_text()
    table = re.search(r"const REVIEW_FILES: \[&str; \d+\] = \[(.*?)\];", source, re.S)
    served = re.findall(r'"/([^"]*)"', table.group(1)) if table else []
    if not served:
        found.append("REVIEW_FILES not found in owner_app.rs")
    pages = {"review": "review.html", "setup": "setup.html"}
    names = [pages.get(n, n) for n in served]
    seen = set()
    while names:
        name = names.pop()
        if name in seen:
            continue
        seen.add(name)
        if name not in listed:
            found.append(
                f"the review origin serves or loads app/{name}, which is not listed"
            )
            continue
        text = (ROOT / "app" / name).read_text()
        if name.endswith(".html"):
            names += re.findall(r'(?:src|href)="/([^"/]+)"', text)
        elif name.endswith(".js"):
            names += re.findall(
                r"""(?:from|import)\s*\(?\s*["'](?:\./|/)([^"']+)["']""", text
            )
    return found


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--check", action="store_true")
    a.add_argument("--budget", type=int, default=BUDGET)
    a.add_argument("--json", action="store_true")
    x = a.parse_args()
    r = report()
    if x.json:
        print(json.dumps(r, indent=2))
    else:
        for path, n, gs, what in r["files"]:
            print(f"{n:6d}  {'/'.join(gs):8s}  {path}  ({what})")
        for g, n in r["by_guarantee"].items():
            print(f"{n:6d}  {g} (files shared between guarantees count in each)")
        print(f"{r['total']:6d}  total trusted code (budget {x.budget})")
        for path, n in r["style"].items():
            print(f"{n:6d}  style sheet, listed apart: {path}")
    if x.check:
        found = problems(r, x.budget)
        for p in found:
            print("FAIL: " + p, file=sys.stderr)
        if found:
            sys.exit(1)
        print("PASS: trusted code within budget; trusted crates fully listed")


if __name__ == "__main__":
    main()
