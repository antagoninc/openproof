#!/usr/bin/env python3
"""Local daily workflow: setup, readiness, approved runs, history, portable verification."""

import argparse, json, os, shutil, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IMAGE = ROOT / "outputs/local-worker/image-id"


def setup():
    from isolation_runner import ENV

    venv = ROOT / "outputs/local-venv"
    python = venv / "bin/python"
    if not python.exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, env=ENV)
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "-r",
            str(ROOT / "scripts/requirements.txt"),
            "jsonschema==4.25.1",
        ],
        check=True,
        env=ENV,
    )
    subprocess.run(["cargo", "build", "--locked"], cwd=ROOT, check=True, env=ENV)
    if not DEFAULT_IMAGE.exists():
        subprocess.run(
            [
                str(python),
                str(ROOT / "scripts/build_isolation.py"),
                "--out",
                str(DEFAULT_IMAGE.parent),
            ],
            check=True,
            env=ENV,
        )
    print(
        "Ready. Run: outputs/local-venv/bin/python scripts/openproof.py run --provider fixture"
    )


def doctor(image_file):
    import importlib.util

    checks = {
        "python_dependencies": all(
            importlib.util.find_spec(n) is not None for n in ["cryptography", "certifi"]
        ),
        "rust_executor": (ROOT / "target/debug/openproof").is_file(),
        "docker_cli": shutil.which("docker") is not None,
        "image_file": Path(image_file).is_file(),
    }
    try:
        from isolation_runner import docker

        endpoint = json.loads(
            docker(
                ["context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"]
            ).stdout
        )
        checks["local_engine"] = endpoint.startswith("unix://") and os.environ.get(
            "DOCKER_HOST", "unix://"
        ).startswith("unix://")
        checks["seccomp_supported"] = any(
            "name=seccomp" in x
            for x in json.loads(
                docker(["info", "--format", "{{json .SecurityOptions}}"]).stdout
            )
        )
        if checks["image_file"]:
            image = Path(image_file).read_text().strip()
            checks["image_present"] = (
                json.loads(docker(["image", "inspect", image]).stdout)[0]["Id"] == image
            )
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        checks["engine_available"] = False
    print(
        json.dumps(
            {
                "ready": all(checks.values()),
                "checks": checks,
                "api_key_configured": bool(os.environ.get("ANTHROPIC_API_KEY")),
            },
            indent=2,
        )
    )
    return all(checks.values())


def history(root):
    import portable, openproof_ref as ref

    rows = []
    if not root.exists():
        return rows
    for run in sorted(root.iterdir())[-200:]:
        if not run.is_dir() or run.is_symlink():
            continue
        row = {
            "run": run.name,
            "status": "incomplete; inspect state before retry",
            "viewer": (
                str(run / "viewer.html") if (run / "viewer.html").is_file() else None
            ),
        }
        try:
            from render_evidence import inside

            execution = ref.read(inside(run, run / "execution.json"))
            jobs = inside(run, run / "state/jobs")
            job = inside(jobs, Path(execution["artifact_directory"]))
            b = ref.read(inside(job, job / "bundle.json"))
            c = ref.read(inside(job, job / "context.json"))
            import openproof_trust as trust, hashlib

            trust.verify(
                b,
                c,
                ref.read(inside(run, run / "trust.json")),
                ref.read(inside(run, run / "anchor.json")),
                int(time.time()),
                "historical",
            )
            with inside(job, job / "output.bin").open("rb") as f:
                data = f.read(ref.MAX + 1)
            ref.need(
                len(data) <= ref.MAX
                and hashlib.sha256(data).hexdigest()
                == b["receipt"]["payload"]["output_sha256"],
                "artifact mismatch",
            )
            row["status"] = "verified now against run-local anchor"
            row["outcome"] = b["receipt"]["payload"]["outcome"]
        except Exception:
            if (run / "execution.json").exists():
                row["status"] = (
                    "unverified now: expired, altered or incomplete evidence"
                )
        rows.append(row)
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("setup")
    d = sub.add_parser("doctor")
    d.add_argument("--image-id-file", default=DEFAULT_IMAGE)
    r = sub.add_parser("run")
    r.add_argument("--provider", choices=["fixture", "claude"], default="fixture")
    r.add_argument("--image-id-file", default=DEFAULT_IMAGE)
    r.add_argument("--out")
    r.add_argument("--model")
    h = sub.add_parser("history")
    h.add_argument("--runs", type=Path, default=ROOT / "outputs/runs")
    e = sub.add_parser("export")
    e.add_argument("run")
    e.add_argument("--out", required=True)
    v = sub.add_parser("verify")
    v.add_argument("package")
    v.add_argument("--anchor", required=True)
    a = p.parse_args()
    if a.command == "setup":
        setup()
        return 0
    if a.command == "doctor":
        return 0 if doctor(a.image_id_file) else 1
    if a.command == "history":
        print(json.dumps(history(a.runs), indent=2))
        return 0
    if a.command == "run":
        if not doctor(a.image_id_file):
            return 1
        out = (
            Path(a.out)
            if a.out
            else ROOT
            / "outputs/runs"
            / ("run-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
        )
        cmd = [
            sys.executable,
            str(ROOT / "scripts/isolated_agent.py"),
            "--provider",
            a.provider,
            "--image-id-file",
            str(a.image_id_file),
            "--out",
            str(out),
            "--approval",
            "interactive",
        ]
        if a.model:
            cmd += ["--model", a.model]
        print("Run folder: " + str(out), flush=True)
        return subprocess.run(cmd).returncode
    import portable, openproof_ref as ref

    result = (
        portable.export(a.run, a.out)
        if a.command == "export"
        else portable.verify(ref.read(a.package), ref.read(a.anchor))
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as e:
        print(
            "OpenProof: "
            + (
                "Interrupted. Inspect existing run state; never automatically retry."
                if isinstance(e, KeyboardInterrupt)
                else str(e)
            ),
            file=sys.stderr,
        )
        sys.exit(1)
