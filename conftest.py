"""Pytest configuration: the list of STATED, MEASURED limits — and why rewriting the probe is not the answer.

Two of the partner-written probes are DELIBERATELY red. `ClampLiedFields` measures that the round entry's
`pending`/`next_id` field is the accused's SELF-REPORT, and the notary log ON ITS OWN does not refute it. This is true, and
the probe pins exactly this boundary — it is not a bug but evidence.

Why we do not rewrite the probe: the partner's files ship VERBATIM, because that is what makes them evidence —
we did not write them. A "fix" in the file would destroy their evidentiary value. So the limit is stated here, on the runner's
side, without touching a single byte of the file.

Why not `skip`: a skipped test measures nothing, and would stay silent even if the limit went away meanwhile.
A `strict` xfail is the OPPOSITE of that: while the limit stands, the probe's red is EXPECTED; but if it ever
passed, the suite turns RED and asks what changed. So a stated limit does not fall asleep.

The CLOSURE of the limit exists one layer up and is measured: `test_clamp_lied_with_audit_20260916.py`
runs the same scenario with the bus's own hash-chained `cursor_audit` export, and both
lies get the `audit_skipped_contradicts_log` (hard) verdict. So the clamp CANNOT be defeated with a single
lying number if the comparison runs — it just cannot be refuted with the log alone.
"""
import pytest

# node-id -> why its red is expected, and where it is closed
EXPECTED_LIMITS = {
    "test_joint_delivery_outcome.py::ClampLiedFields::test_lied_next_id_must_not_defeat_the_clamp":
        "the round entry's next_id is a self-report; it cannot be refuted with the log alone "
        "(closed by: test_clamp_lied_with_audit_20260916.py, with bus_audit)",
    "test_joint_delivery_outcome.py::ClampLiedFields::test_lied_pending_must_not_defeat_the_clamp":
        "the round entry's pending is a self-report; it cannot be refuted with the log alone "
        "(closed by: test_clamp_lied_with_audit_20260916.py, with bus_audit)",
}


def _is_full_run(config):
    """True if the run is the FULL suite — only then does the fact "not collected" say anything.

    The first version always checked, and failed a run narrowed to a single file: there the probes are
    legitimately not collected. A guard that treats narrowing as a defect teaches the developer to
    bypass it — and from then on the real case goes unnoticed too."""
    if getattr(config.option, "keyword", None) or getattr(config.option, "markexpr", None):
        return False
    args = [a for a in (config.args or []) if not a.startswith("-")]
    root = str(config.rootpath)
    return all(a in ("", ".", root) for a in args)


def pytest_collection_modifyitems(config, items):
    seen = set()
    for item in items:
        for nodeid, why in EXPECTED_LIMITS.items():
            if item.nodeid.endswith(nodeid):
                item.add_marker(pytest.mark.xfail(reason=why, strict=True))
                seen.add(nodeid)
    missing = sorted(set(EXPECTED_LIMITS) - seen)
    if missing and _is_full_run(config):
        # A node id that no longer exists would live on as a silent exception: the probe was renamed or deleted,
        # and from then on the "expected red" covers nothing. This is a loud error, not a forgivable typo — but only on a full
        # run, because on a narrowed run the absence is a consequence of the narrowing, not a finding.
        raise pytest.UsageError("conftest: a stated limit that was not collected: %s" % ", ".join(missing))
