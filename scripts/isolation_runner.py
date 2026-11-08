"""Run a fixed worker image with no host mounts, network, privileges or inherited secrets."""

import json, os, re, selectors, subprocess, time, uuid

ENV = {
    k: v
    for k, v in os.environ.items()
    if k
    in {
        "PATH",
        "HOME",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    }
}
FLAGS = [
    "--network",
    "none",
    "--read-only",
    "--user",
    "65532:65532",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--security-opt",
    "seccomp=builtin",
    "--pids-limit",
    "32",
    "--memory",
    "128m",
    "--memory-swap",
    "128m",
    "--cpus",
    "1",
    "--ipc",
    "none",
    "--log-driver",
    "none",
]


def docker(args):
    r = subprocess.run(
        ["docker", *args], env=ENV, text=True, capture_output=True, timeout=40
    )
    if r.returncode:
        raise RuntimeError("Docker operation failed: " + r.stderr[:1000])
    return r


def worker(image, job, *, timeout=30):
    if not 0 < timeout <= 30:
        raise ValueError("worker timeout must be in (0,30]")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("immutable local image ID required")
    endpoint = json.loads(
        docker(
            ["context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"]
        ).stdout
    )
    if not endpoint.startswith("unix://") or (
        ENV.get("DOCKER_HOST") and not ENV["DOCKER_HOST"].startswith("unix://")
    ):
        raise RuntimeError("local Unix-socket Docker engine required")
    data = json.dumps(job).encode()
    if len(data) > 32768:
        raise ValueError("worker input too large")
    name = "openproof-worker-" + uuid.uuid4().hex
    proc = None
    created = False
    try:
        created = True  # Creation may succeed even if the client loses its reply.
        docker(["create", "--name", name, *FLAGS, "-i", image])
        info = json.loads(docker(["inspect", name]).stdout)[0]
        h = info["HostConfig"]
        config = {
            "network": h["NetworkMode"],
            "readonly": h["ReadonlyRootfs"],
            "user": info["Config"]["User"],
            "mounts": info["Mounts"],
            "cap_drop": h["CapDrop"],
            "security_opt": h["SecurityOpt"],
            "pids_limit": h["PidsLimit"],
            "memory": h["Memory"],
            "memory_swap": h["MemorySwap"],
            "nano_cpus": h["NanoCpus"],
            "ipc": h["IpcMode"],
            "image": info["Image"],
        }
        if (
            config["network"] != "none"
            or not config["readonly"]
            or config["mounts"]
            or config["user"] != "65532:65532"
            or "ALL" not in config["cap_drop"]
            or not any(
                x
                in [
                    "no-new-privileges",
                    "no-new-privileges=true",
                    "no-new-privileges:true",
                ]
                for x in config["security_opt"]
            )
            or "seccomp=builtin" not in config["security_opt"]
            or config["image"] != image
        ):
            raise RuntimeError("unexpected isolation configuration")
        if (
            config["pids_limit"] != 32
            or config["memory"] != 134217728
            or config["memory_swap"] != 134217728
            or config["nano_cpus"] != 1000000000
            or config["ipc"] != "none"
        ):
            raise RuntimeError("worker resource limits not enforced")
        proc = subprocess.Popen(
            ["docker", "start", "-ai", name],
            env=ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        selector = selectors.DefaultSelector()
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        offset = 0
        deadline = time.monotonic() + timeout
        for pipe, label, event in [
            (proc.stdin, "stdin", selectors.EVENT_WRITE),
            (proc.stdout, "stdout", selectors.EVENT_READ),
            (proc.stderr, "stderr", selectors.EVENT_READ),
        ]:
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, event, label)
        try:
            while selector.get_map():
                if time.monotonic() > deadline:
                    raise RuntimeError("worker deadline exceeded")
                for key, _ in selector.select(0.2):
                    if key.data == "stdin":
                        try:
                            offset += os.write(key.fd, data[offset:])
                        except BrokenPipeError:
                            offset = len(data)
                        if offset == len(data):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        buffers[key.data].extend(chunk)
                        if len(buffers[key.data]) > 65536:
                            raise RuntimeError("worker output exceeds limit")
        finally:
            selector.close()
        if proc.wait(timeout=5) != 0:
            raise RuntimeError("isolated worker failed; no request dispatched")
        return json.loads(buffers["stdout"]), config
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        if proc:
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                if pipe and not pipe.closed:
                    pipe.close()
        if created:
            try:
                removed = subprocess.run(
                    ["docker", "rm", "-f", name],
                    env=ENV,
                    capture_output=True,
                    timeout=30,
                )
                remaining = docker(
                    ["ps", "-aq", "--filter", "name=^/" + name + "$"]
                ).stdout.strip()
                if remaining:
                    raise RuntimeError("container remains")
            except Exception as error:
                raise RuntimeError(
                    "Worker cleanup unconfirmed: "
                    + name
                    + "; inspect Docker before continuing"
                ) from error
