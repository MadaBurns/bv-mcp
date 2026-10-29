"""Pure-function tests for score-stability-test.py (no network)."""

import importlib.util
import pathlib

_path = pathlib.Path(__file__).with_name("score-stability-test.py")
_spec = importlib.util.spec_from_file_location("score_stability_test", _path)
sst = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sst)


def run(score, cats, statuses=None, latency=100, findings=0, grade="B"):
    meta = {"checkStatuses": statuses if statuses is not None else sst.ABSENT,
            "inconclusiveCategories": sst.ABSENT, "evidenceInsufficient": sst.ABSENT,
            "latencyMs": latency}
    return (score, grade, cats, findings, None, meta)


def test_dedupe_preserves_order():
    assert sst.dedupe_domains(["a.com", "b.com", "a.com", "c.com", "b.com"]) == ["a.com", "b.com", "c.com"]


def test_load_domains_never_cycles():
    got = sst.load_domains(None, 100)
    assert got == sst.dedupe_domains(sst.DEFAULT_DOMAINS)
    assert len(got) == len(set(got))
    assert sst.load_domains(None, 3) == sst.DEFAULT_DOMAINS[:3]


def test_identical_runs_are_stable():
    assert sst.classify_drift([run(80, {"spf": 90}), run(80, {"spf": 90})]) is None


def test_null_differs_from_absent():
    drift = sst.classify_drift([run(80, {"spf": None}), run(80, {})])
    assert drift["cat_diffs"]["spf"]["values"] == [None, sst.ABSENT]


def test_null_vs_null_is_stable():
    assert sst.classify_drift([run(80, {"spf": None}), run(80, {"spf": None})]) is None


def test_moved_category_reports_check_statuses():
    a = run(80, {"dkim": 90}, {"dkim": "completed"})
    b = run(80, {"dkim": None}, {"dkim": "timeout"})
    drift = sst.classify_drift([a, b])
    assert drift["cat_diffs"]["dkim"]["statuses"] == ["completed", "timeout"]


def test_missing_status_reads_absent():
    drift = sst.classify_drift([run(80, {"dkim": 90}), run(80, {"dkim": 70}, {"other": "ok"})])
    assert drift["cat_diffs"]["dkim"]["statuses"] == [sst.ABSENT, sst.ABSENT]


def test_slow_scans_flagged_over_threshold_only():
    rounds = [{"a.com": run(80, {}, latency=25000), "b.com": run(80, {}, latency=20000)},
              {"a.com": run(80, {}, latency=500), "b.com": run(80, {}, latency=30000)}]
    assert sst.find_slow_scans(rounds, ["a.com", "b.com"], 20000) == [(1, "a.com", 25000), (2, "b.com", 30000)]


def test_extract_meta_marks_missing_keys_absent():
    meta = sst.extract_meta({"checkStatuses": {"spf": "ok"}, "evidenceInsufficient": None})
    assert meta["checkStatuses"] == {"spf": "ok"}
    assert meta["evidenceInsufficient"] is None
    assert meta["inconclusiveCategories"] == sst.ABSENT
