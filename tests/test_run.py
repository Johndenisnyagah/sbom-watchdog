"""Specification for the orchestrator.

These cover the behaviours that were previously only demonstrated by hand, and
the one that would fail silently: run.py must build the state document from the
diff result, not from the parsed scan.

Every test writes through tmp_path. Nothing here touches .sbom-watchdog/.
"""
import json
import pathlib

from src.diff import diff, select_for_issues
from src.model import parse_grype
from src.run import main
from src.state import state_documents_equal

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
REAL = FIXTURES / "grype" / "real_0117.json"


def run(scan: pathlib.Path, state: pathlib.Path, out: pathlib.Path) -> None:
    assert main(["--scan", str(scan), "--state", str(state), "--out", str(out)]) == 0


def document(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# --- bootstrap -----------------------------------------------------------

def test_bootstrap_records_the_baseline_and_files_nothing(tmp_path, capsys):
    """First run against a real scan: every finding is recorded, none is new,
    and nothing is filed. Without this the first run on a real project opens
    several hundred issues at once."""
    state = tmp_path / "findings.json"
    out = tmp_path / "next.json"
    assert not state.exists()

    run(REAL, state, out)
    printed = capsys.readouterr().out

    assert "bootstrap" in printed
    assert len(document(out)["findings"]) == 22

    result = diff(None, parse_grype(document(REAL)))
    assert result.bootstrap is True
    assert result.new == {}
    assert select_for_issues(result) == []


def test_bootstrap_does_not_write_to_the_state_path(tmp_path):
    """--out is the only thing written without --write-state."""
    state = tmp_path / "findings.json"
    run(REAL, state, tmp_path / "next.json")
    assert not state.exists()


# --- idempotency ---------------------------------------------------------

def test_second_run_over_the_same_scan_changes_nothing(tmp_path, capsys):
    """The round trip through state.py must preserve every field exactly. If it
    coerced a type or reordered a list, the second run would report 22 changed
    findings instead of 22 unchanged ones."""
    first = tmp_path / "findings.json"
    run(REAL, first, first)
    capsys.readouterr()

    second = tmp_path / "second.json"
    run(REAL, first, second)
    printed = capsys.readouterr().out

    assert "unchanged:  22" in printed
    assert "changed:    0" in printed
    assert "new:        0" in printed

    before, after = document(first), document(second)
    assert state_documents_equal(before, after)

    differing = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
    assert differing <= {"generated_at"}


# --- provenance ----------------------------------------------------------

def test_provenance_carries_forward_and_last_seen_advances(tmp_path):
    """first_seen and issue_number belong to the record, not to the scan. If a
    run reset them, every finding would look new to phase 4 and be refiled."""
    state = tmp_path / "findings.json"
    run(REAL, state, state)

    key = "CVE-2020-14343::python::pyyaml"
    neighbour = "CVE-2018-18074::python::requests"

    tampered = document(state)
    tampered["findings"][key]["first_seen"] = "2026-01-15"
    tampered["findings"][key]["last_seen"] = "2026-01-15"
    tampered["findings"][key]["issue_number"] = 99
    neighbour_first_seen = tampered["findings"][neighbour]["first_seen"]
    state.write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")

    out = tmp_path / "next.json"
    run(REAL, state, out)
    findings = document(out)["findings"]

    assert findings[key]["first_seen"] == "2026-01-15"
    assert findings[key]["issue_number"] == 99
    assert findings[key]["last_seen"] > "2026-01-15"

    assert findings[neighbour]["first_seen"] == neighbour_first_seen
    assert findings[neighbour]["issue_number"] is None


# --- the state document comes from the diff, not the scan ----------------

def test_reconciled_finding_keeps_its_key_and_provenance(tmp_path):
    """Yesterday the advisory had no CVE and was keyed by its GHSA, with issue
    44 already filed. Today it carries a CVE, so the parsed scan keys it under
    the CVE. Writing the scan straight to state would move the record, orphan
    issue 44 and reset first_seen. The record must stay where it was."""
    state = tmp_path / "findings.json"
    state.write_text((FIXTURES / "state" / "ghsa_only.json").read_text(encoding="utf-8"),
                     encoding="utf-8")

    out = tmp_path / "next.json"
    run(FIXTURES / "grype" / "06_alias_flip.json", state, out)
    findings = document(out)["findings"]

    original = "GHSA-aaaa-bbbb-cccc::python::jinja2"
    assert original in findings
    assert "CVE-2026-11111::python::jinja2" not in findings

    record = findings[original]
    assert record["first_seen"] == "2026-08-19"
    assert record["issue_number"] == 44
    assert record["id"] == "CVE-2026-11111"
    assert "CVE-2026-11111" in record["aliases"]
    assert "GHSA-aaaa-bbbb-cccc" in record["aliases"]


# --- the comparison the commit-back depends on ---------------------------

def test_state_documents_equal_ignores_only_generated_at(tmp_path):
    a = document(FIXTURES / "state" / "baseline.json")
    b = json.loads(json.dumps(a))
    b["generated_at"] = "2099-01-01T00:00:00Z"
    assert state_documents_equal(a, b)

    b["findings"]["CVE-2020-14343::python::pyyaml"]["severity"] = "Low"
    assert not state_documents_equal(a, b)


def test_state_documents_equal_treats_a_missing_document_as_different(tmp_path):
    """None means no state file, which must always write. Conflating it with an
    empty document would skip the baseline commit on a first run."""
    a = document(FIXTURES / "state" / "baseline.json")
    assert not state_documents_equal(None, a)
    assert state_documents_equal(None, None)
