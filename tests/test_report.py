"""Specification for the compliance outputs.

SECURITY-INVENTORY.md is read by someone who is not a developer, so most of
these assert about words rather than structure. The scanner's vocabulary
leaking into it is a defect, in the same way it was a defect in the issue body.
"""
import json
import pathlib

import pytest

from src.report import (
    inventory_markdown,
    sbom_history_path,
    write_inventory,
    write_sbom_history,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def state(**overrides) -> dict:
    document = {
        "schema_version": 2,
        "generated_at": "2026-08-24T03:17:00Z",
        "tooling": {
            "syft": "1.51.0",
            "grype": "0.117.0",
            "grype_db_built": "2026-08-23T06:22:13Z",
        },
        "findings": {},
    }
    document.update(overrides)
    return document


def record(name="urllib3", severity="High", identifier="CVE-1",
           fixed_in=("2.0",), resolved_on=None, versions=("1.0",)) -> dict:
    return {
        "id": identifier,
        "aliases": [identifier],
        "package": {"name": name, "type": "python", "versions": list(versions)},
        "severity": severity,
        "fixed_in": list(fixed_in),
        "fix_state": "fixed" if fixed_in else "not-fixed",
        "first_seen": "2026-08-01",
        "last_seen": "2026-08-24",
        "issue_number": None,
        "resolved_on": resolved_on,
    }


# --- the dated SBOM history -----------------------------------------------

def test_history_is_named_for_the_day_it_covers():
    assert sbom_history_path("sboms", "2026-03-14T03:17:00Z").name == "2026-03-14.json"


def test_history_is_written_even_when_nothing_changed(tmp_path):
    """One file per day the scan ran, never skipped for being unchanged.

    A missing file has to mean "no scan ran that day" and nothing else. If it
    could also mean "the dependencies had not changed", the trail cannot tell a
    stable project from an abandoned one - and GitHub disables scheduled
    workflows after 60 days of inactivity, so going quiet is a real ending.
    """
    sbom = tmp_path / "sbom.json"
    sbom.write_text('{"components": []}', encoding="utf-8")
    history = tmp_path / "sboms"

    first = write_sbom_history(sbom, history, "2026-03-14T03:17:00Z")
    second = write_sbom_history(sbom, history, "2026-03-15T03:17:00Z")

    assert first.name == "2026-03-14.json"
    assert second.name == "2026-03-15.json"
    assert sorted(p.name for p in history.iterdir()) == [
        "2026-03-14.json", "2026-03-15.json"]


def test_history_creates_the_directory(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")
    written = write_sbom_history(sbom, tmp_path / "nested" / "sboms",
                                 "2026-03-14T00:00:00Z")
    assert written.exists()


def test_a_second_run_on_the_same_day_leaves_the_day_alone(tmp_path):
    """The first scan of a day writes that day's record; later scans do not
    touch it. Syft stamps a new serialNumber every run, so rewriting would
    produce a commit whose entire content is a changed UUID - and would quietly
    turn the day's record into the last scan of that day, with nothing saying
    which."""
    sbom = tmp_path / "sbom.json"
    history = tmp_path / "sboms"

    sbom.write_text('{"run": 1}', encoding="utf-8")
    first = write_sbom_history(sbom, history, "2026-03-14T03:17:00Z")

    sbom.write_text('{"run": 2}', encoding="utf-8")
    second = write_sbom_history(sbom, history, "2026-03-14T15:00:00Z")

    assert first is not None
    assert second is None, "a later scan the same day rewrote the record"
    assert len(list(history.iterdir())) == 1
    assert json.loads(first.read_text())["run"] == 1


def test_a_new_day_is_recorded_even_though_yesterday_exists(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")
    history = tmp_path / "sboms"

    write_sbom_history(sbom, history, "2026-03-14T03:17:00Z")
    written = write_sbom_history(sbom, history, "2026-03-15T03:17:00Z")

    assert written is not None
    assert written.name == "2026-03-15.json"


def test_the_inventory_is_rewritten_when_it_would_differ(tmp_path):
    """It describes the current state rather than a dated snapshot, so the
    latest scan is always the right content - including undoing a hand edit."""
    destination = tmp_path / "SECURITY-INVENTORY.md"
    document = state(findings={"a": record()})

    assert write_inventory(destination, document) is not None
    destination.write_text("someone edited this by hand", encoding="utf-8")
    assert write_inventory(destination, document) is not None
    assert destination.read_text(encoding="utf-8").startswith("# Security inventory")


def test_the_inventory_is_left_alone_when_already_correct(tmp_path):
    """Writing identical content is a no-op, not a rewrite. Reporting it as one
    would tell the caller there is something to commit when there is not."""
    destination = tmp_path / "SECURITY-INVENTORY.md"
    document = state(findings={"a": record()})

    write_inventory(destination, document)
    assert write_inventory(destination, document) is None


# --- the inventory, as a document a non-developer reads -------------------

def test_counts_are_split_by_severity():
    document = state(findings={
        "a": record(severity="Critical"),
        "b": record(severity="High", identifier="CVE-2"),
        "c": record(severity="High", identifier="CVE-3"),
        "d": record(severity="Low", identifier="CVE-4"),
    })
    rendered = inventory_markdown(document)

    assert "| Critical | 1 |" in rendered
    assert "| High | 2 |" in rendered
    assert "| Low | 1 |" in rendered
    assert "| **Total** | **4** |" in rendered
    assert "**Vulnerabilities currently open:** 4" in rendered


def test_open_and_resolved_are_separate_sections():
    """The schema 2 resolved records are what make this more than a snapshot."""
    document = state(findings={
        "a": record(),
        "b": record(identifier="CVE-2", resolved_on="2026-08-20"),
    })
    rendered = inventory_markdown(document)

    assert "**Vulnerabilities currently open:** 1" in rendered
    assert "**Vulnerabilities resolved since tracking began:** 1" in rendered
    assert "| **Total** | **1** |" in rendered, "a resolved finding is not open"
    assert "| urllib3 | High | CVE-2 | 20 August 2026 |" in rendered


def test_no_fix_findings_get_their_own_line():
    """A package with no available fix is a different compliance posture from
    one awaiting an upgrade, and that distinction is what an auditor wants."""
    document = state(findings={
        "a": record(identifier="CVE-1", fixed_in=("2.0",)),
        "b": record(name="pycrypto", identifier="CVE-2", fixed_in=()),
    })
    rendered = inventory_markdown(document)

    assert "### Can be fixed by updating (1)" in rendered
    assert "### No fix available (1)" in rendered
    assert "no published fix" in rendered
    assert "replaced with a maintained alternative" in rendered
    assert "| pycrypto | 1.0 | High | CVE-2 | none published |" in rendered


def test_it_says_so_when_every_finding_has_a_fix():
    document = state(findings={"a": record()})
    rendered = inventory_markdown(document)
    assert "### No fix available (0)" in rendered
    assert "Every open vulnerability has a published fix available." in rendered


def test_a_clean_project_reads_as_checked_not_as_empty():
    """An empty inventory must say the check ran and found nothing, not just
    show zeroes. "We looked" and "we did not look" cannot look alike."""
    rendered = inventory_markdown(state())

    assert "**Vulnerabilities currently open:** 0" in rendered
    assert "No known vulnerabilities are open." in rendered
    assert "was checked against the vulnerability databases" in rendered


def test_provenance_answers_when_did_you_last_check():
    rendered = inventory_markdown(state())

    assert "| Date of this check | 24 August 2026 |" in rendered
    assert "| Software inventory produced by | Syft 1.51.0 |" in rendered
    assert "| Vulnerabilities identified by | Grype 0.117.0 |" in rendered
    assert "| Vulnerability data published on | 23 August 2026 |" in rendered


def test_dates_are_written_for_a_person():
    rendered = inventory_markdown(state())
    assert "24 August 2026" in rendered
    assert "2026-08-24T03:17:00Z" not in rendered


def test_no_scanner_vocabulary_reaches_the_reader():
    """The same discipline that fixed the no-fix issue body. A procurement
    reviewer should not have to look up what a purl is."""
    document = state(findings={
        "a": record(),
        "b": record(name="pycrypto", identifier="CVE-2", fixed_in=()),
        "c": record(identifier="CVE-3", resolved_on="2026-08-20"),
    })
    rendered = inventory_markdown(document).lower()

    for jargon in ("purl", "fix_state", "not-fixed", "wont-fix", "cyclonedx",
                   "schema_version", "first_seen", "issue_number", "bootstrap",
                   "package_type", "grype_db_built"):
        assert jargon not in rendered, f"scanner vocabulary leaked: {jargon}"


def test_severity_is_not_presented_as_a_risk_assessment():
    """Overstating what a severity rating means is the easiest way for a
    compliance document to mislead the person relying on it."""
    rendered = inventory_markdown(state(findings={"a": record()}))
    assert "not an assessment of how this project uses the software" in rendered


def test_the_history_directory_is_explained():
    """A reader has to know that an absent file means no scan, not no change."""
    rendered = inventory_markdown(state())
    assert "one file per day the check ran" in rendered
    assert "absence of a file for a given date means no check ran that day" in rendered


# --- writing it out --------------------------------------------------------

def test_write_inventory_creates_the_file(tmp_path):
    destination = write_inventory(tmp_path / "nested" / "SECURITY-INVENTORY.md",
                                  state(findings={"a": record()}))
    assert destination.exists()
    assert destination.read_text(encoding="utf-8").startswith("# Security inventory")


def test_write_inventory_uses_lf_endings(tmp_path):
    """It is committed to the adopter's repository, like the state file."""
    destination = write_inventory(tmp_path / "SECURITY-INVENTORY.md", state())
    assert b"\r\n" not in destination.read_bytes()


@pytest.mark.parametrize("fixture", ["baseline.json", "with_resolved.json"])
def test_renders_from_the_state_fixtures(fixture):
    """Whatever the fixtures hold, the document renders without raising."""
    document = json.loads((FIXTURES / "state" / fixture).read_text(encoding="utf-8"))
    rendered = inventory_markdown(document)
    assert rendered.startswith("# Security inventory")
    assert "## How this was checked" in rendered
