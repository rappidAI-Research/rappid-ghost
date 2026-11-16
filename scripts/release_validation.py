#!/usr/bin/env python3
"""Build a minimal release receipt from actual completed integration results."""
import json
import math
import os
from pathlib import Path
import subprocess
import sys

REQUIRED = {
    "TestDockerRealCodexExecThroughBroker", "TestDockerRealNativeOllamaInference",
    "TestDockerReleasedV05UpgradeAndMatchedMeasurements", "TestDockerOfficialMCPClientCannotBypassScope",
    "TestDockerBrokerConcurrentSessionScopesStaySeparate", "TestDockerClosedLangGraphRunsRealToolModelGraph",
}


def validate(lines, benchmark):
    counts = {"passed": 0, "failed": 0, "skipped": 0}
    passed = set()
    performance = []
    for line in lines:
        event = json.loads(line)
        action = event.get("Action")
        if action in ("fail", "skip"):
            raise ValueError("release validation contains a failed/skipped Docker test or package")
        if event.get("Test") and action == "pass":
            counts["passed"] += 1
            passed.add(event["Test"])
        output = event.get("Output", "")
        if event.get("Test") == "TestDockerReleasedV05UpgradeAndMatchedMeasurements" and "VERSION_PERF {" in output:
            sample = json.loads(output.split("VERSION_PERF ", 1)[1])
            allowed = {"version", "sample", "phase", "wall_ms", "controller_cpu_ms", "controller_peak_rss_kib",
                       "roundtrip_ms", "guest_process_rss_kib", "guest_cgroup_peak_bytes", "guest_cgroup_cpu_usec"}
            if set(sample) != allowed or sample["version"] not in ("v0.5.0", "v0.6.0-candidate"):
                raise ValueError("unexpected performance receipt shape")
            if type(sample["sample"]) is not int or sample["sample"] not in range(4) or sample["phase"] != ("first-session-prepared-images" if sample["sample"] == 0 else "warm"):
                raise ValueError("unexpected performance phase")
            for key in allowed - {"version", "sample", "phase"}:
                if type(sample[key]) not in (int, float) or not math.isfinite(sample[key]) or sample[key] < 0:
                    raise ValueError("invalid numeric measurement")
            performance.append(sample)
    if not REQUIRED.issubset(passed):
        raise ValueError("mandatory real integration result absent")
    results = benchmark["results"]
    if len(results) != 27 or len({r["scenario"] for r in results}) != 27 or any(r["status"] != "PASS" for r in results):
        raise ValueError("all 27 distinct GhostBench properties must pass")
    if benchmark["summary"] != {"passed": 27, "failed": 0, "skipped": 0}:
        raise ValueError("inconsistent GhostBench summary")
    if len(performance) != 8 or len({(p["version"], p["sample"]) for p in performance}) != 8:
        raise ValueError("missing matched version performance samples")
    return {"docker_test_results": counts, "required_integrations": sorted(REQUIRED),
            "ghostbench": benchmark["summary"], "version_performance": performance}


def main():
    with Path("docker-integration.jsonl").open() as source:
        result = validate(source, json.loads(Path("ghostbench-release.json").read_text()))
    result.update({"schema_version": 1,
                   "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                   "tag": os.environ["RELEASE_TAG"], "qualified_platform": "native Linux amd64 / Docker Engine",
                   "baseline_commit": "970631de9872e2eedcc3523318103d100a4b70fc",
                   "go_toolchain": subprocess.check_output(["go", "version"], text=True).strip(),
                   "main_ci": "https://github.com/rappidAI-Research/rappid-ghost/actions/runs/" + os.environ["MAIN_CI_RUN"],
                   "release_gate": "https://github.com/rappidAI-Research/rappid-ghost/actions/runs/" + os.environ["GITHUB_RUN_ID"]})
    Path("dist/validation.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
