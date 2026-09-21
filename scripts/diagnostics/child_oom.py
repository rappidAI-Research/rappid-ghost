"""CI-only diagnosis: finite allocations inside hardened 64-MiB containers.

A uniquely named, persistent parent slice retains hierarchical kernel counters
after Docker deletes a child's cgroup. This is diagnostic infrastructure, not a
new Ghost runtime path or a requirement on user machines.
"""
import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid


def run(*args, check=True, timeout=30):
    return subprocess.run(args, check=check, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=timeout).stdout.strip()


def counters(path):
    return {k: int(v) for k, v in (line.split() for line in path.read_text().splitlines())}


image = "alpine:3.22.5@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
token = "ghostoomdiag" + uuid.uuid4().hex
slice_name = token + ".slice"
unit = token + ".service"
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
container = None
print(run("docker", "info"), flush=True)
print(run("uname", "-a"), flush=True)
for binary in ("containerd", "containerd-shim-runc-v2", "runc"):
    print(run(binary, "--version", check=False), flush=True)
run("docker", "pull", image, timeout=120)
run("sudo", "systemd-run", "--unit=" + unit, "--slice=" + slice_name,
    "--property=MemoryAccounting=yes", "/usr/bin/sleep", "420")
try:
    group = run("systemctl", "show", slice_name, "--property=ControlGroup", "--value")
    assert group.startswith("/") and token in group
    memory_events = Path("/sys/fs/cgroup" + group) / "memory.events"
    with tempfile.TemporaryDirectory(prefix=token) as workspace:
        os.chmod(workspace, 0o777)
        run("cc", "-static", "-O0", "-o", workspace + "/resource-fixture",
            "internal/runtime/testdata/resource_fixture.c")
        for attempt in range(60):
            before = counters(memory_events)
            container = run("docker", "create", "--init", "--interactive", "--name", token + "-" + str(attempt),
                "--label", "ghost.diagnostic=" + token, "--cgroup-parent", slice_name,
                "--network", "none", "--user", "1000:1000", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--read-only", "--pids-limit", "32",
                "--memory", "64m", "--memory-swap", "64m", "--cpu-period", "100000", "--cpu-quota", "100000",
                "--log-driver", "none", "--mount", "type=bind,src=" + workspace + ",dst=/workspace",
                image, "sh", "-c", '/workspace/resource-fixture memory & child=$!; wait "$child"; printf "%s" "$?" > /workspace/child-exit; exit 0')
            assert len(container) == 64 and all(c in "0123456789abcdef" for c in container)
            run("docker", "start", "--attach", container)
            state = json.loads(run("docker", "inspect", "--format", "{{json .State}}", container))
            after = counters(memory_events)
            until = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1)).isoformat()
            history = run("docker", "events", "--since", started, "--until", until,
                          "--filter", "container=" + container, "--format", "{{json .}}")
            events = [json.loads(line) for line in history.splitlines()]
            oom = state["OOMKilled"] or any(e["Action"] == "oom" for e in events)
            killed = after["oom_kill"] - before["oom_kill"]
            print(json.dumps({"attempt": attempt, "container": container,
                "kernel_oom_kills": killed, "docker_oom": oom, "state": state,
                "actions": [e["Action"] for e in events],
                "child_exit": Path(workspace + "/child-exit").read_text()}), flush=True)
            if killed != 1 or not oom:
                journal = run("sudo", "journalctl", "-u", "docker.service", "-u", "containerd.service",
                              "--since", started, "--no-pager", "-n", "3000", check=False)
                print("\n".join(line for line in journal.splitlines()
                      if container in line or "oom" in line.lower()), flush=True)
                raise SystemExit("Kernel/daemon OOM mismatch; retain strict failure")
            run("docker", "rm", container)
            container = None
finally:
    if container:
        run("docker", "rm", "--force", container, check=False)
    run("sudo", "systemctl", "stop", unit, slice_name, check=False)
