"""Pure-function tests for score-stability-test.py (stdlib unittest, no network)."""

import importlib.util
import pathlib
import unittest

_path = pathlib.Path(__file__).with_name("score-stability-test.py")
_spec = importlib.util.spec_from_file_location("score_stability_test", _path)
sst = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sst)


def run(score, cats, statuses=None, latency=100, findings=0, grade="B"):
    meta = {"checkStatuses": statuses if statuses is not None else sst.ABSENT,
            "inconclusiveCategories": sst.ABSENT, "evidenceInsufficient": sst.ABSENT,
            "latencyMs": latency}
    return (score, grade, cats, findings, None, meta)


class ScoreStabilityTests(unittest.TestCase):
    def test_dedupe_preserves_order(self):
        self.assertEqual(sst.dedupe_domains(["a.com", "b.com", "a.com", "c.com", "b.com"]), ["a.com", "b.com", "c.com"])

    def test_load_domains_never_cycles(self):
        got = sst.load_domains(None, 100)
        self.assertEqual(got, sst.dedupe_domains(sst.DEFAULT_DOMAINS))
        self.assertEqual(len(got), len(set(got)))
        self.assertEqual(sst.load_domains(None, 3), sst.DEFAULT_DOMAINS[:3])

    def test_identical_runs_are_stable(self):
        self.assertIsNone(sst.classify_drift([run(80, {"spf": 90}), run(80, {"spf": 90})]))

    def test_null_differs_from_absent(self):
        drift = sst.classify_drift([run(80, {"spf": None}), run(80, {})])
        self.assertEqual(drift["cat_diffs"]["spf"]["values"], [None, sst.ABSENT])

    def test_null_vs_null_is_stable(self):
        self.assertIsNone(sst.classify_drift([run(80, {"spf": None}), run(80, {"spf": None})]))

    def test_moved_category_reports_check_statuses(self):
        a = run(80, {"dkim": 90}, {"dkim": "completed"})
        b = run(80, {"dkim": None}, {"dkim": "timeout"})
        drift = sst.classify_drift([a, b])
        self.assertEqual(drift["cat_diffs"]["dkim"]["statuses"], ["completed", "timeout"])

    def test_missing_status_reads_absent(self):
        drift = sst.classify_drift([run(80, {"dkim": 90}), run(80, {"dkim": 70}, {"other": "ok"})])
        self.assertEqual(drift["cat_diffs"]["dkim"]["statuses"], [sst.ABSENT, sst.ABSENT])

    def test_slow_scans_flagged_over_threshold_only(self):
        rounds = [{"a.com": run(80, {}, latency=25000), "b.com": run(80, {}, latency=20000)},
                  {"a.com": run(80, {}, latency=500), "b.com": run(80, {}, latency=30000)}]
        self.assertEqual(sst.find_slow_scans(rounds, ["a.com", "b.com"], 20000), [(1, "a.com", 25000), (2, "b.com", 30000)])

    def test_extract_meta_marks_missing_keys_absent(self):
        meta = sst.extract_meta({"checkStatuses": {"spf": "ok"}, "evidenceInsufficient": None})
        self.assertEqual(meta["checkStatuses"], {"spf": "ok"})
        self.assertIsNone(meta["evidenceInsufficient"])
        self.assertEqual(meta["inconclusiveCategories"], sst.ABSENT)


if __name__ == "__main__":
    unittest.main()
