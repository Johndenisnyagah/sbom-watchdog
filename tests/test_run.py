"""Specification for the orchestrator.

These cover the behaviours that were previously only demonstrated by hand, and
the one that would fail silently: run.py must build the state document from the
diff result, not from the parsed scan.

Every test writes through tmp_path. Nothing here touches .sbom-watchdog/.
"""
import json
import pathlib
import re

from src.diff import diff, select_for_issues
from src.model import parse_grype
from src.run import commit_message, main
from src.state import (
    SCHEMA_VERSION,
    findings_from_state,
    migrate,
    resolved_from_state,
    state_documents_equal,
    state_from_findings,
    utc_now,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
# Captured Grype output, shipped with the action rather than under tests/ so
# the packaged self-check and this suite read the same bytes.
REAL = pathlib.Path(__file__).parents[1] / "packaging" / "real_0117.json"


def run(scan: pathlib.Path, state: pathlib.Path, out: pathlib.Path) -> None:
    assert main(["--scan", str(scan), "--state", str(state), "--out", str(out)]) == 0


def document(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def step_outputs(path: pathlib.Path) -> dict[str, str]:
    """Parse the key=value lines run.py appends to $GITHUB_OUTPUT."""
    pairs = (line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if line)
    return {key: value for key, value in pairs}


# --- bootstrap -----------------------------------------------------------

def test_bootstrap_records_the_baseline_and_files_nothing(tmp_path, capsys, monkeypatch):
    """First run against a real scan: every finding is recorded, none is new,
    and nothing is filed. Without this the first run on a real project opens
    several hundred issues at once.

    The bootstrap output matters as much as the behaviour: a first run reports
    zero new by design, so without it the workflow would announce a baseline of
    several hundred findings as "no change" in a commit that is permanent.
    """
    state = tmp_path / "findings.json"
    out = tmp_path / "next.json"
    outputs = tmp_path / "step_outputs.txt"
    outputs.touch()
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    assert not state.exists()

    run(REAL, state, out)
    printed = capsys.readouterr().out

    assert "bootstrap" in printed
    assert len(document(out)["findings"]) == 22

    emitted = step_outputs(outputs)
    assert emitted["bootstrap"] == "true"
    assert emitted["recorded"] == "22"
    assert emitted["new"] == "0"

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


# --- the commit message ---------------------------------------------------
#
# This text is permanent in somebody's history. A real baseline once shipped as
# "no change (scan of )" - wrong branch, empty date - because it was assembled
# from step outputs in workflow shell. These are the tests that stop that twice.

DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def build(previous_state, scan):
    """(DiffResult, state document) for a scan against an optional prior state.

    `scan` is a fixture filename, or a path for the captured document that
    lives outside tests/."""
    path = scan if isinstance(scan, pathlib.Path) else FIXTURES / "grype" / scan
    report = json.loads(path.read_text(encoding="utf-8"))
    current = parse_grype(report)
    previous = None if previous_state is None else findings_from_state(previous_state)
    result = diff(previous, current)
    from src.run import findings_to_record
    state = state_from_findings(
        findings_to_record(result), provenance={}, generated_at=utc_now(), tooling={}
    )
    return result, state


def test_commit_message_bootstrap_names_the_baseline():
    result, state = build(None, REAL)
    assert commit_message(result, state) == (
        "Vulnerability state: baseline, 22 findings recorded [skip ci]"
    )


def test_commit_message_reports_new_and_resolved_counts():
    previous = document(FIXTURES / "state" / "baseline.json")
    result, state = build(previous, "02_new_finding.json")
    assert commit_message(result, state) == (
        "Vulnerability state: 1 new, 0 resolved [skip ci]"
    )


def test_commit_message_no_change_carries_a_real_date():
    """The empty date is what shipped. A message may never say "scan of )"."""
    previous = document(FIXTURES / "state" / "baseline.json")
    result, state = build(previous, "01_baseline.json")
    message = commit_message(result, state)

    assert message.startswith("Vulnerability state: no change (scan of ")
    assert "scan of )" not in message

    scanned = re.search(r"scan of (\S+)\)", message)
    assert scanned, message
    assert DATE.match(scanned.group(1)), f"not a YYYY-MM-DD date: {scanned.group(1)!r}"


def test_commit_message_after_a_recompute_is_still_correct(tmp_path):
    """The race path recomputes against whatever origin holds and rewrites the
    message. A stale or empty message there would mislabel the commit that
    actually lands."""
    state_path = tmp_path / "findings.json"
    message_path = tmp_path / "commit-message.txt"

    assert main(["--scan", str(REAL), "--state", str(state_path),
                 "--write-state", "--message-file", str(message_path)]) == 0
    assert message_path.read_text(encoding="utf-8").strip() == (
        "Vulnerability state: baseline, 22 findings recorded [skip ci]"
    )

    # Recompute against the state just written, as the retry loop does.
    assert main(["--scan", str(REAL), "--state", str(state_path),
                 "--write-state", "--message-file", str(message_path)]) == 0
    message = message_path.read_text(encoding="utf-8").strip()

    assert message.startswith("Vulnerability state: no change (scan of ")
    assert "scan of )" not in message
    scanned = re.search(r"scan of (\S+)\)", message)
    assert scanned and DATE.match(scanned.group(1))


# --- a dry run is a preview -----------------------------------------------
#
# The state write is as irreversible as the issue. Recording a baseline during
# a preview permanently consumes the one bootstrap a repository gets: every
# finding is "already known" from then on, so the first real run files nothing.

def test_dry_run_does_not_create_a_state_file(tmp_path, capsys):
    state = tmp_path / "findings.json"
    assert not state.exists()

    assert main(["--scan", str(REAL), "--state", str(state),
                 "--write-state", "--dry-run-issues"]) == 0

    assert not state.exists(), "a preview wrote the state file"
    assert "the state file was not written" in capsys.readouterr().out


def test_dry_run_leaves_an_existing_state_file_untouched(tmp_path, capsys):
    state = tmp_path / "findings.json"
    main(["--scan", str(FIXTURES / "grype" / "01_baseline.json"),
          "--state", str(state), "--out", str(state)])
    capsys.readouterr()
    before = state.read_bytes()

    assert main(["--scan", str(REAL), "--state", str(state),
                 "--write-state", "--dry-run-issues"]) == 0

    assert state.read_bytes() == before, "a preview rewrote the state file"


def test_dry_run_reports_no_state_change_to_the_workflow(tmp_path, monkeypatch):
    """The commit step keys off this. A preview must not present as something
    to commit, whatever the diff found."""
    outputs = tmp_path / "outputs.txt"
    outputs.touch()
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))

    main(["--scan", str(REAL), "--state", str(tmp_path / "findings.json"),
          "--write-state", "--dry-run-issues"])

    emitted = step_outputs(outputs)
    assert emitted["state_changed"] == "false"
    # The counts are still reported, so the preview is still informative.
    assert emitted["recorded"] == "22"


def test_a_real_run_still_writes_state(tmp_path):
    """The guard must not have disabled the thing it is guarding."""
    state = tmp_path / "findings.json"
    assert main(["--scan", str(REAL), "--state", str(state),
                 "--write-state"]) == 0
    assert state.exists()
    assert len(document(state)["findings"]) == 22


# --- schema 2: resolved findings stay ------------------------------------
#
# v1 deleted a resolved finding, which discarded the only link between it and
# the issue it was filed under. Nothing could then close that issue, or
# reference it if the vulnerability came back.

def test_v1_documents_migrate_and_are_all_unresolved():
    v1 = {
        "schema_version": 1,
        "generated_at": "2026-08-20T03:00:00Z",
        "tooling": {},
        "findings": {
            "CVE-1::python::x": {
                "id": "CVE-1", "aliases": ["CVE-1"],
                "package": {"name": "x", "type": "python", "versions": ["1.0"]},
                "severity": "High", "fixed_in": ["2.0"], "fix_state": "fixed",
                "first_seen": "2026-08-01", "last_seen": "2026-08-20",
                "issue_number": 7,
            }
        },
    }
    upgraded = migrate(v1)

    assert upgraded["schema_version"] == SCHEMA_VERSION
    assert findings_from_state(v1).keys() == {"CVE-1::python::x"}
    assert resolved_from_state(v1) == {}
    assert v1["schema_version"] == 1, "migrate mutated its argument"


def test_resolved_records_are_not_returned_as_current():
    state = document(FIXTURES / "state" / "with_resolved.json")
    key = "CVE-2023-45803::python::urllib3"

    assert key not in findings_from_state(state)
    assert key in resolved_from_state(state)


def test_resolved_records_survive_a_write(tmp_path):
    """The record, and with it the issue number, must still be there next run."""
    state = document(FIXTURES / "state" / "with_resolved.json")
    key = "CVE-2023-45803::python::urllib3"

    rebuilt = state_from_findings(
        findings_from_state(state),
        provenance=provenance_of(state),
        generated_at=utc_now(),
        tooling={},
        resolved=resolved_from_state(state),
    )

    assert key in rebuilt["findings"]
    assert rebuilt["findings"][key]["resolved_on"] == "2026-08-20"
    assert rebuilt["findings"][key]["issue_number"] == 45
    assert rebuilt["findings"][key]["last_seen"] == "2026-08-19", (
        "a resolved finding must not keep being marked as seen")


def provenance_of(state: dict) -> dict:
    from src.state import provenance_from_state
    return provenance_from_state(state)


# --- the regression cycle -------------------------------------------------

def test_a_returning_finding_is_new_and_keeps_its_history(tmp_path, capsys):
    """File, resolve, then reintroduce. The finding must come back as NEW - a
    regression is the one direction this tool must not miss - while carrying
    the issue number and first_seen of the original."""
    state = tmp_path / "findings.json"
    key = "CVE-2023-45803::python::urllib3"

    # It was filed as #45 and later resolved.
    state.write_text(
        (FIXTURES / "state" / "with_resolved.json").read_text(encoding="utf-8"),
        encoding="utf-8")

    # 02_new_finding.json contains urllib3 again.
    out = tmp_path / "next.json"
    run(FIXTURES / "grype" / "02_new_finding.json", state, out)
    printed = capsys.readouterr().out

    assert "new:        1" in printed

    record = document(out)["findings"][key]
    assert record["resolved_on"] is None, "a returning finding is not resolved"
    assert record["issue_number"] == 45, "lost the link to the original issue"
    assert record["first_seen"] == "2026-08-01", "history restarted"


def test_the_regression_body_references_the_original_issue():
    from src.issues import render_issue
    from src.model import parse_grype

    scan = parse_grype(document(FIXTURES / "grype" / "02_new_finding.json"))
    key = "CVE-2023-45803::python::urllib3"
    previous = {"issue_number": 45, "resolved_on": "2026-08-20"}

    _, body, _ = render_issue(scan[key], scan, previous)

    assert "previously reported in #45" in body
    assert "resolved on 2026-08-20" in body
    assert "It has returned." in body


def test_a_first_time_finding_has_no_regression_notice():
    from src.issues import render_issue
    from src.model import parse_grype

    scan = parse_grype(document(FIXTURES / "grype" / "02_new_finding.json"))
    key = "CVE-2023-45803::python::urllib3"

    _, body, _ = render_issue(scan[key], scan, {"issue_number": None,
                                                "resolved_on": None})
    assert "has returned" not in body
    assert "previously reported" not in body


def test_findings_that_resolve_are_recorded_not_deleted(tmp_path, capsys):
    """The change this whole schema bump exists for."""
    state = tmp_path / "findings.json"
    state.write_text(
        (FIXTURES / "state" / "baseline.json").read_text(encoding="utf-8"),
        encoding="utf-8")

    out = tmp_path / "next.json"
    run(FIXTURES / "grype" / "04_resolved.json", state, out)
    assert "resolved:   1" in capsys.readouterr().out

    record = document(out)["findings"]["CVE-2018-18074::python::requests"]
    assert record["resolved_on"], "resolved finding was deleted, not recorded"


# --- the clean repository -------------------------------------------------
#
# A repository with no findings never moves its vulnerability state: findings
# stays empty, so once the tooling settles the document is identical every day.
# Gating the commit on state_changed therefore left its audit trail empty -
# and a clean project is precisely the readership a compliance trail is for.
#
# It also inverted the write-every-day decision. A missing dated SBOM was
# supposed to mean exactly one thing, "no scan ran that day". Uncommitted daily
# files made it mean "or the project was clean" as well.

CLEAN = FIXTURES / "grype" / "09_empty.json"


def compliance_run(tmp_path, outputs, *, day=None):
    """One run with both compliance outputs on, returning the step outputs."""
    sbom = tmp_path / "sbom.json"
    if not sbom.exists():
        sbom.write_text('{"components": []}', encoding="utf-8")
    outputs.write_text("", encoding="utf-8")

    argv = ["--scan", str(CLEAN), "--state", str(tmp_path / "findings.json"),
            "--write-state", "--sbom", str(sbom),
            "--sbom-history", str(tmp_path / "sboms"),
            "--inventory", str(tmp_path / "SECURITY-INVENTORY.md")]
    assert main(argv) == 0
    return step_outputs(outputs)


def test_a_clean_repository_still_commits_its_daily_sbom(tmp_path, monkeypatch, capsys):
    outputs = tmp_path / "outputs.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))

    first = compliance_run(tmp_path, outputs)
    capsys.readouterr()

    assert first["recorded"] == "0", "this fixture must have no findings"
    assert first["should_commit"] == "true"

    # Same day, same scan, same tooling: the document is identical, so the
    # vulnerability state has not moved. There is still a file to commit.
    second = compliance_run(tmp_path, outputs)
    capsys.readouterr()

    assert second["state_changed"] == "false", (
        "a clean repository's state never moves - that is the whole problem")
    assert second["should_commit"] == "true", (
        "the daily SBOM was written and would never have been committed")


def test_a_later_day_produces_a_new_dated_sbom_to_commit(tmp_path, monkeypatch, capsys):
    outputs = tmp_path / "outputs.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))

    compliance_run(tmp_path, outputs)
    capsys.readouterr()

    monkeypatch.setattr("src.run.utc_now", lambda: "2099-01-02T03:17:00Z")
    later = compliance_run(tmp_path, outputs)
    capsys.readouterr()

    assert later["state_changed"] == "false", "no finding moved"
    assert later["should_commit"] == "true"

    written = sorted(p.name for p in (tmp_path / "sboms").iterdir())
    assert "2099-01-02.json" in written
    assert len(written) == 2, "one file per day the scan ran"


def test_state_changed_still_means_only_that_the_state_moved(tmp_path, monkeypatch, capsys):
    """The two outputs must not collapse into each other. state_changed stays
    a narrower and separately useful fact."""
    outputs = tmp_path / "outputs.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    state = tmp_path / "findings.json"

    assert main(["--scan", str(REAL), "--state", str(state), "--write-state"]) == 0
    capsys.readouterr()
    outputs.write_text("", encoding="utf-8")

    assert main(["--scan", str(REAL), "--state", str(state), "--write-state"]) == 0
    capsys.readouterr()
    emitted = step_outputs(outputs)

    # No compliance outputs requested, nothing moved: both are false.
    assert emitted["state_changed"] == "false"
    assert emitted["should_commit"] == "false"


def test_a_dry_run_never_asks_to_commit(tmp_path, monkeypatch, capsys):
    outputs = tmp_path / "outputs.txt"
    outputs.touch()
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")

    assert main(["--scan", str(CLEAN), "--state", str(tmp_path / "findings.json"),
                 "--write-state", "--dry-run-issues", "--sbom", str(sbom),
                 "--sbom-history", str(tmp_path / "sboms"),
                 "--inventory", str(tmp_path / "SECURITY-INVENTORY.md")]) == 0
    capsys.readouterr()

    emitted = step_outputs(outputs)
    assert emitted["should_commit"] == "false"
    assert emitted["state_changed"] == "false"
    assert not (tmp_path / "sboms").exists(), "a preview wrote a file"
    assert not (tmp_path / "SECURITY-INVENTORY.md").exists()
