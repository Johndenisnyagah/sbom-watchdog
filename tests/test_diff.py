"""Specification for the diff engine.

These tests are written before src/ exists. Each one names the failure mode it
guards against. If a test fails, the implementation is wrong until an argument
is made in CLAUDE.md that the test is.
"""
import json
import pathlib

import pytest

from src.diff import diff, select_for_issues
from src.model import parse_grype
from src.state import findings_from_state

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def grype(name: str) -> dict:
    return parse_grype(json.loads((FIXTURES / "grype" / name).read_text()))


def state(name: str) -> dict:
    return findings_from_state(json.loads((FIXTURES / "state" / name).read_text()))


# --- parsing and identity ------------------------------------------------

def test_key_uses_cve_not_ghsa():
    """Grype reports GHSA in vulnerability.id and the CVE in relatedVulnerabilities.
    Keying on the raw id lets a finding change identity when the advisory DB
    updates, which files a duplicate issue."""
    findings = grype("01_baseline.json")
    assert "CVE-2020-14343::python::pyyaml" in findings
    assert not any(k.startswith("GHSA-") for k in findings)


def test_ghsa_id_kept_as_alias():
    f = grype("01_baseline.json")["CVE-2020-14343::python::pyyaml"]
    assert "GHSA-8q59-q68h-6hv4" in f.aliases


def test_package_name_lowercased_in_key():
    """The fixture spells it PyYAML. Casing varies between Grype versions."""
    assert "CVE-2020-14343::python::pyyaml" in grype("01_baseline.json")


def test_falls_back_to_primary_id_when_no_cve_exists():
    """Advisories published before a CVE is assigned have no relatedVulnerabilities."""
    assert "GHSA-aaaa-bbbb-cccc::python::jinja2" in grype("05_ghsa_only.json")


def test_same_package_two_versions_collapses_to_one_finding():
    """A dependency tree can ship two copies of a package. Both are vulnerable to
    the same CVE, but that is one finding, not two issues."""
    findings = grype("08_duplicate_versions.json")
    assert len(findings) == 1
    f = findings["CVE-2023-45803::python::urllib3"]
    assert f.versions == ("1.26.15", "1.26.17")


def test_versions_are_sorted():
    """Unsorted versions make the committed state file churn on every run."""
    f = grype("08_duplicate_versions.json")["CVE-2023-45803::python::urllib3"]
    assert list(f.versions) == sorted(f.versions)


def test_same_name_different_ecosystem_does_not_collide():
    """`requests` on PyPI and `requests` on npm are unrelated packages."""
    findings = grype("10_cross_ecosystem.json")
    assert len(findings) == 2
    assert {f.package_type for f in findings.values()} == {"python", "npm"}


# --- bootstrap -----------------------------------------------------------

def test_first_run_reports_nothing_as_new():
    """Without this, the first run against a real project opens several hundred
    issues at once."""
    result = diff(None, grype("01_baseline.json"))
    assert result.bootstrap is True
    assert result.new == {}
    assert len(result.unchanged) == 3


def test_first_run_files_no_issues():
    assert select_for_issues(diff(None, grype("01_baseline.json"))) == []


def test_empty_previous_state_is_not_bootstrap():
    """A repo that was clean yesterday and has a finding today is a real alert.
    An empty dict is different from a missing file."""
    result = diff({}, grype("01_baseline.json"))
    assert result.bootstrap is False
    assert len(result.new) == 3


# --- the diff itself -----------------------------------------------------

def test_unchanged_findings_are_not_new():
    result = diff(state("baseline.json"), grype("01_baseline.json"))
    assert result.new == {}
    assert len(result.unchanged) == 3


def test_new_finding_detected():
    result = diff(state("baseline.json"), grype("02_new_finding.json"))
    assert list(result.new) == ["CVE-2023-45803::python::urllib3"]


def test_version_bump_still_vulnerable_is_not_new():
    """requests 2.19.1 -> 2.19.2, still below the 2.20.0 fix. Same CVE.
    Firing a second issue here is the single most annoying possible bug."""
    result = diff(state("baseline.json"), grype("03_version_bump.json"))
    assert result.new == {}
    assert "CVE-2018-18074::python::requests" in result.changed


def test_version_bump_records_the_new_version():
    result = diff(state("baseline.json"), grype("03_version_bump.json"))
    _, current = result.changed["CVE-2018-18074::python::requests"]
    assert current.versions == ("2.19.2",)


def test_resolved_finding_detected():
    result = diff(state("baseline.json"), grype("04_resolved.json"))
    assert list(result.resolved) == ["CVE-2018-18074::python::requests"]
    assert result.new == {}


def test_clean_scan_resolves_everything():
    result = diff(state("baseline.json"), grype("09_empty.json"))
    assert len(result.resolved) == 3
    assert result.new == {}


def test_resolved_finding_never_files_an_issue():
    result = diff(state("baseline.json"), grype("04_resolved.json"))
    assert select_for_issues(result) == []


# --- alias reconciliation ------------------------------------------------

def test_ghsa_gaining_a_cve_is_not_a_new_finding():
    """Yesterday the advisory had no CVE, so it was keyed GHSA-aaaa-bbbb-cccc.
    Today NVD assigned CVE-2026-11111 and the key changes. Same flaw, same
    package: reconcile via the alias sets instead of filing again."""
    result = diff(state("ghsa_only.json"), grype("06_alias_flip.json"))
    assert result.new == {}


def test_reconciled_finding_keeps_its_original_key():
    """The key must be stable so issue_number and first_seen survive."""
    result = diff(state("ghsa_only.json"), grype("06_alias_flip.json"))
    assert "GHSA-aaaa-bbbb-cccc::python::jinja2" in result.changed


def test_reconciled_finding_merges_aliases():
    result = diff(state("ghsa_only.json"), grype("06_alias_flip.json"))
    _, current = result.changed["GHSA-aaaa-bbbb-cccc::python::jinja2"]
    assert {"GHSA-aaaa-bbbb-cccc", "CVE-2026-11111"} <= set(current.aliases)


def test_alias_overlap_alone_does_not_match_across_packages():
    """Reconciliation requires matching package name and type as well as an
    alias overlap. Two packages vulnerable to the same CVE are two findings."""
    previous = state("baseline.json")
    result = diff(previous, grype("10_cross_ecosystem.json"))
    assert "CVE-2026-22222::npm::requests" in result.new


def test_reconciliation_will_not_cross_ecosystems():
    """The python `requests` finding is gone and an npm package of the same name
    carries the same CVE. Package name matches, aliases overlap, the old key is
    absent from the current scan: every condition except package_type says
    reconcile. Dropping that one check makes the tool silently report a brand-new
    npm vulnerability as an old python one it already filed."""
    result = diff(state("baseline.json"), grype("11_same_cve_other_ecosystem.json"))
    assert "CVE-2018-18074::npm::requests" in result.new
    assert "CVE-2018-18074::python::requests" in result.resolved


# --- severity threshold --------------------------------------------------

def test_below_threshold_finding_is_recorded_but_not_filed():
    """setuptools is Medium. It stays in state so its history is intact; the
    default High threshold keeps it out of the issue tracker."""
    result = diff({}, grype("01_baseline.json"))
    assert "CVE-2022-40897::python::setuptools" in result.new
    filed = {f.key for f in select_for_issues(result)}
    assert "CVE-2022-40897::python::setuptools" not in filed
    assert len(filed) == 2


def test_threshold_is_configurable():
    result = diff({}, grype("01_baseline.json"))
    assert len(select_for_issues(result, threshold="Medium")) == 3


def test_upward_rerating_across_the_threshold_files_an_issue():
    """NVD re-rated setuptools Medium -> Critical. It is not a new finding, but
    it was never filed and now clears the threshold, so it should be."""
    result = diff(state("baseline.json"), grype("07_severity_rerated.json"))
    assert result.new == {}
    assert [f.key for f in select_for_issues(result)] == [
        "CVE-2022-40897::python::setuptools"
    ]


def test_unchanged_finding_above_threshold_is_not_refiled():
    """pyyaml is Critical and has been there since 1 August. Nothing changed,
    so nothing is filed, regardless of how severe it is."""
    result = diff(state("baseline.json"), grype("01_baseline.json"))
    assert select_for_issues(result, threshold="Critical") == []


@pytest.mark.parametrize("severity", ["Unknown", "Negligible"])
def test_unfiled_severities_sort_below_low(severity):
    """Comparing severity as a string puts 'Unknown' above 'Low' alphabetically.
    Compare by index in the ordered list instead."""
    from src.diff import SEVERITY_ORDER
    assert SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index("Low")


# --- purity --------------------------------------------------------------

def test_diff_does_not_mutate_its_arguments():
    previous = state("baseline.json")
    before = json.dumps({k: repr(v) for k, v in sorted(previous.items())})
    diff(previous, grype("02_new_finding.json"))
    after = json.dumps({k: repr(v) for k, v in sorted(previous.items())})
    assert before == after


def test_diff_module_imports_nothing_it_should_not():
    """diff.py must stay pure: no filesystem, no network, no clock, no environ.
    This is the constraint most likely to be violated while wiring up phase 4."""
    import ast
    src = pathlib.Path(__file__).parents[1] / "src" / "diff.py"
    tree = ast.parse(src.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    banned = {"os", "sys", "pathlib", "requests", "urllib", "datetime",
              "time", "subprocess", "json", "github"}
    assert not (imported & banned), f"diff.py imports {imported & banned}"
