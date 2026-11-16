import copy
import json
import unittest
import release_validation


class ValidationReceiptTests(unittest.TestCase):
    def fixture(self):
        lines = [json.dumps({"Action": "pass", "Test": name}) for name in release_validation.REQUIRED]
        for version in ("v0.5.0", "v0.6.0-candidate"):
            for index in range(4):
                sample = {"version": version, "sample": index, "phase": "warm" if index else "first-session-prepared-images",
                          "wall_ms": 1000, "controller_cpu_ms": 300, "controller_peak_rss_kib": 50000,
                          "roundtrip_ms": 30, "guest_process_rss_kib": 20000, "guest_cgroup_peak_bytes": 20000000,
                          "guest_cgroup_cpu_usec": 400000}
                lines.append(json.dumps({"Action": "output", "Test": "TestDockerReleasedV05UpgradeAndMatchedMeasurements", "Output": "VERSION_PERF " + json.dumps(sample)}))
        benchmark = {"results": [{"scenario": "property-" + str(i), "status": "PASS"} for i in range(27)], "summary": {"passed": 27, "failed": 0, "skipped": 0}}
        return lines, benchmark

    def test_receipt_requires_complete_distinct_evidence(self):
        lines, benchmark = self.fixture()
        report = release_validation.validate(lines, benchmark)
        self.assertEqual(report["ghostbench"]["passed"], 27)
        for action in ("skip", "fail"):
            with self.assertRaises(ValueError):
                release_validation.validate(lines + [json.dumps({"Action": action, "Test": "required"})], benchmark)
        for invalid in (lines[1:], lines[:-1], lines[:-1] + [lines[-2]]):
            with self.assertRaises(ValueError):
                release_validation.validate(invalid, benchmark)
        bad = copy.deepcopy(benchmark)
        bad["results"][0]["status"] = "SKIP"
        with self.assertRaises(ValueError):
            release_validation.validate(lines, bad)
        bad = copy.deepcopy(benchmark)
        bad["results"][0] = bad["results"][1]
        with self.assertRaises(ValueError):
            release_validation.validate(lines, bad)


if __name__ == "__main__":
    unittest.main()
