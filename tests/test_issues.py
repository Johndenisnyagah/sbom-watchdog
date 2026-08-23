"""Specification for issue rendering.

Rendering is pure, so these build Findings directly rather than going through
fixtures. Two of the three fix branches - wont-fix and no-published-fix - do not
appear in any fixture, and real Grype output reported `fixed` for all 22
findings. That makes them the branches most likely to be wrong and the ones
least likely to be noticed, which is exactly why they are covered here.
"""
import re

from src.diff import SEVERITY_ORDER
from src.issues import (
    KEY_MARKER,
    LABEL,
    advisory_url,
    dry_run,
    fixed_in_phrase,
    render_issue,
)
from src.model import Finding


def finding(**overrides) -> Finding:
    """A Finding with sensible defaults, overridable field by field."""
    fields = {
        "key": "CVE-2023-45803::python::urllib3",
        "id": "CVE-2023-45803",
        "aliases": frozenset({"CVE-2023-45803", "GHSA-v845-jxx5-vc9f"}),
        "package_name": "urllib3",
        "package_type": "python",
        "versions": ("1.26.17",),
        "severity": "High",
        "fixed_in": ("1.26.18", "2.0.7"),
        "fix_state": "fixed",
    }
    fields.update(overrides)
    return Finding(**fields)


# --- the key in the title -------------------------------------------------

def test_title_carries_the_finding_key():
    """The key in the title is the deduplication net: one search for it tells a
    later run whether this was already filed, even if state was never
    committed."""
    title, _, _ = render_issue(finding())
    assert "CVE-2023-45803::python::urllib3" in title


def test_key_round_trips_out_of_the_title():
    """Whatever parses the key back out must recover it exactly. The key
    contains colons, which is the character most likely to break a naive
    parser."""
    subject = finding()
    title, _, _ = render_issue(subject)

    recovered = re.search(r"\[([^\]]+)\]$", title)
    assert recovered, title
    assert recovered.group(1) == subject.key


def test_machine_readable_key_comment_is_present_and_parseable():
    subject = finding()
    _, body, _ = render_issue(subject)

    assert "<!-- Do not edit the line below" in body
    recovered = re.search(rf"{re.escape(KEY_MARKER)} `([^`]+)`", body)
    assert recovered, body
    assert recovered.group(1) == subject.key


# --- labels ---------------------------------------------------------------

def test_labels_are_exactly_the_marker_and_the_severity():
    for severity in SEVERITY_ORDER:
        _, _, labels = render_issue(finding(severity=severity))
        assert labels == [LABEL, f"severity:{severity.lower()}"], severity


def test_severity_label_is_lowercased():
    _, _, labels = render_issue(finding(severity="Critical"))
    assert "severity:critical" in labels
    assert "severity:Critical" not in labels


# --- the three fix branches ----------------------------------------------

def test_fixed_branch_frames_the_choice_without_making_it():
    """Two fixed versions are usually two release lines. The tool does not know
    which one the reader can adopt, and string sort would eventually pick
    wrong, so it must not pick at all."""
    _, body, _ = render_issue(finding(fixed_in=("1.26.18", "2.0.7")))
    assert "1.26.18 or 2.0.7" in body
    assert "separate release lines" in body
    assert "pick the one matching your major version" in body


def test_single_fixed_version_is_stated_plainly():
    _, body, _ = render_issue(finding(fixed_in=("2.20.0",)))
    assert "**Fixed in:** 2.20.0" in body
    assert "separate release lines" not in body


def test_wont_fix_says_no_upgrade_will_help():
    """Unexercised by every fixture and by real Grype output, which reported
    `fixed` for all 22 findings."""
    _, body, _ = render_issue(finding(fixed_in=(), fix_state="wont-fix"))
    assert "wont-fix" in body
    assert "no upgrade will resolve it" in body
    assert "no fixed version has been published" not in body


def test_no_published_fix_says_so():
    _, body, _ = render_issue(finding(fixed_in=(), fix_state="not-fixed"))
    assert "no fixed version has been published yet" in body
    assert "wont-fix" not in body


def test_fixed_in_phrase_handles_all_three_shapes():
    assert fixed_in_phrase(()) == "none published"
    assert fixed_in_phrase(("2.20.0",)) == "2.20.0"
    assert fixed_in_phrase(("1.26.18", "2.0.7")).startswith("1.26.18 or 2.0.7 (")


# --- advisory links -------------------------------------------------------

def test_advisory_url_maps_cve_and_ghsa():
    assert advisory_url("CVE-2023-45803") == (
        "https://nvd.nist.gov/vuln/detail/CVE-2023-45803"
    )
    assert advisory_url("GHSA-v845-jxx5-vc9f") == (
        "https://github.com/advisories/GHSA-v845-jxx5-vc9f"
    )


def test_advisory_url_returns_none_for_anything_else():
    """A wrong link in a security issue costs more than a missing one."""
    for identifier in ("PYSEC-2018-28", "OSV-2021-1", "", "https://evil.test"):
        assert advisory_url(identifier) is None, identifier


def test_body_omits_unmappable_identifiers_rather_than_linking_them():
    subject = finding(aliases=frozenset({"CVE-2023-45803", "PYSEC-2018-28"}))
    _, body, _ = render_issue(subject)

    assert "[CVE-2023-45803](https://nvd.nist.gov/vuln/detail/CVE-2023-45803)" in body
    assert "PYSEC-2018-28" not in body


def test_body_says_so_when_no_identifier_is_linkable():
    subject = finding(aliases=frozenset({"PYSEC-2018-28"}))
    _, body, _ = render_issue(subject)
    assert "- none published" in body


# --- the body a person actually reads ------------------------------------

def test_body_carries_the_facts_a_reader_needs():
    _, body, _ = render_issue(finding(versions=("1.26.15", "1.26.17")))
    assert "CVE-2023-45803" in body
    assert "urllib3" in body
    assert "1.26.15, 1.26.17" in body
    assert "| Severity | High |" in body
    assert "| Fix state | fixed |" in body


def test_dry_run_reports_nothing_when_there_is_nothing():
    assert dry_run([]) == "no issues would be filed"


def test_dry_run_renders_every_selected_finding():
    findings = [finding(), finding(key="CVE-2020-14343::python::pyyaml",
                                   id="CVE-2020-14343", package_name="pyyaml",
                                   severity="Critical")]
    rendered = dry_run(findings)
    assert "2 issue(s) would be filed" in rendered
    assert "Nothing was posted" in rendered
    assert "CVE-2023-45803::python::urllib3" in rendered
    assert "CVE-2020-14343::python::pyyaml" in rendered
