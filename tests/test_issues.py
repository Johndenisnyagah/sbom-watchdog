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
    highest_version,
    package_findings,
    package_line,
    render_issue,
    version_key,
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
    # With something to install, the scanner's own fix vocabulary still earns
    # its place next to the version.
    assert "| Fix state | fixed |" in body
    assert "no longer reported as" in body


def test_wont_fix_leads_with_the_situation_not_a_missing_version():
    """"Fixed in: nothing" reads as a template that failed to fill itself in.
    The bold label has to state the situation, and the sentence after it has to
    name the decision the reader faces, because there is nothing to install."""
    _, body, _ = render_issue(finding(fixed_in=(), fix_state="wont-fix"))

    assert "**No fix is planned.**" in body
    assert "no upgrade will resolve it" in body
    assert "replace the dependency" in body
    assert "accept the risk and record why" in body

    assert "**Fixed in:**" not in body
    assert "| Fix state |" not in body, "raw scanner vocabulary restating the prose"
    assert "removed or replaced" in body
    assert "no longer reported as" not in body


def test_no_available_fix_leads_with_the_situation():
    _, body, _ = render_issue(finding(fixed_in=(), fix_state="not-fixed"))

    assert "**No fix is available.**" in body
    assert "nothing to upgrade to" in body
    assert "replace the dependency" in body
    assert "accept the risk and record why" in body

    assert "**Fixed in:**" not in body
    assert "wont-fix" not in body
    assert "| Fix state |" not in body


def test_the_footer_does_not_imply_waiting_works_when_nothing_is_coming():
    """pycrypto's last release was 2013. "Until it is no longer reported as
    vulnerable" is accurate for something fixable and quietly wrong here: it
    never stops being reported, so the sentence implies waiting is a strategy."""
    _, body, _ = render_issue(finding(fixed_in=(), fix_state="not-fixed"))
    assert "until the dependency is removed or replaced" in body
    assert "no longer reported as" not in body


# --- the no-fix label -----------------------------------------------------

def test_no_fix_label_is_applied_when_there_is_nothing_to_install():
    """A dependency-replacement decision is a different kind of work item from
    a version bump, and worth filtering for."""
    for state in ("not-fixed", "wont-fix", "unknown"):
        _, _, labels = render_issue(finding(fixed_in=(), fix_state=state))
        assert "no-fix" in labels, state


def test_no_fix_label_is_absent_when_a_fix_exists():
    _, _, labels = render_issue(finding(fixed_in=("2.20.0",)))
    assert "no-fix" not in labels
    assert labels == ["sbom-watchdog", "severity:high"]


def test_no_fix_label_sits_alongside_the_usual_two():
    _, _, labels = render_issue(finding(fixed_in=(), fix_state="not-fixed",
                                        severity="Critical"))
    assert labels == ["sbom-watchdog", "severity:critical", "no-fix"]


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


# --- version ordering -----------------------------------------------------
#
# CLAUDE.md deferred a natural sort key until something compared versions
# semantically. Picking the highest fix across a package's findings does.

def test_natural_sort_orders_1_26_9_below_1_26_10():
    """The case plain string sort gets wrong, and the reason this exists."""
    assert version_key("1.26.9") < version_key("1.26.10")
    assert sorted(["1.26.9", "1.26.10"]) == ["1.26.10", "1.26.9"]
    assert sorted(["1.26.9", "1.26.10"], key=version_key) == ["1.26.9", "1.26.10"]


def test_natural_sort_handles_the_shapes_grype_emits():
    assert version_key("2.0") < version_key("2.0.1")
    assert version_key("2.0rc1") < version_key("2.0")
    assert version_key("1.26.18") < version_key("2.0.7")


def test_highest_version_picks_the_real_maximum():
    assert highest_version(["1.26.18", "2.0.7", "2.7.0", "2.6.3"]) == "2.7.0"
    assert highest_version(["2.6.3", "2.6.0", "2.6.0", "2.7.0"]) == "2.7.0"
    assert highest_version([]) is None
    assert highest_version(["1.26.9", "1.26.10"]) == "1.26.10"


# --- per-package guidance -------------------------------------------------

def urllib3_scan() -> dict:
    """Four urllib3 findings with different fix versions, as the testbed
    produced. Only 2.7.0 resolves all of them."""
    fixes = {
        "CVE-2025-66418": ("2.6.3",),
        "CVE-2025-66471": ("2.6.0",),
        "CVE-2026-21441": ("2.6.0",),
        "CVE-2026-44431": ("2.7.0",),
    }
    return {
        f"{cve}::python::urllib3": finding(
            key=f"{cve}::python::urllib3", id=cve, aliases=frozenset({cve}),
            package_name="urllib3", versions=("1.26.17",), fixed_in=fixed_in,
        )
        for cve, fixed_in in fixes.items()
    }


def test_package_findings_groups_by_name_and_ecosystem():
    scan = urllib3_scan()
    scan["CVE-1::npm::urllib3"] = finding(
        key="CVE-1::npm::urllib3", id="CVE-1", package_name="urllib3",
        package_type="npm")
    subject = scan["CVE-2025-66418::python::urllib3"]

    grouped = package_findings(subject, scan)
    assert len(grouped) == 4
    assert all(f.package_type == "python" for f in grouped)


def test_sibling_guidance_names_the_highest_fix_across_the_package():
    """Each issue used to give a different answer to "what do I install", and
    only one of them was right. A reader closing this one by upgrading to
    2.6.3 would still have three findings open."""
    scan = urllib3_scan()
    _, body, _ = render_issue(scan["CVE-2025-66418::python::urllib3"], scan)

    assert "This package has 4 findings in this scan" in body
    assert "highest fix version among them is 2.7.0" in body
    assert "leaves the others open" in body


def test_every_issue_for_a_package_names_the_same_version():
    scan = urllib3_scan()
    for subject in scan.values():
        _, body, _ = render_issue(subject, scan)
        assert "highest fix version among them is 2.7.0" in body


def test_no_sibling_line_when_the_package_has_one_finding():
    subject = finding()
    _, body, _ = render_issue(subject, {subject.key: subject})
    assert "findings in this scan" not in body


def test_rendering_without_a_scan_still_works():
    """The signature stays usable with the finding alone; it just cannot say
    anything about siblings it was not shown."""
    _, body, _ = render_issue(finding())
    assert "findings in this scan" not in body
    assert "**Fixed in:**" in body


# --- major version jumps --------------------------------------------------

def test_major_version_jump_is_flagged():
    """1.26.17 to 2.7.0 is a breaking change presented as a version bump."""
    scan = urllib3_scan()
    _, body, _ = render_issue(scan["CVE-2026-44431::python::urllib3"], scan)
    assert "crosses a major version and may require code changes" in body


def test_same_major_upgrade_is_not_flagged():
    subject = finding(versions=("2.19.1",), fixed_in=("2.20.0",))
    _, body, _ = render_issue(subject, {subject.key: subject})
    assert "crosses a major version" not in body


def test_no_major_warning_when_there_is_no_fix():
    subject = finding(versions=("1.26.17",), fixed_in=(), fix_state="not-fixed")
    _, body, _ = render_issue(subject, {subject.key: subject})
    assert "crosses a major version" not in body


# --- the footer -----------------------------------------------------------

def test_footer_does_not_claim_a_closed_issue_is_refiled():
    """Nothing refiles a closed issue: issue_number persists in state. The old
    wording said the opposite and would have taught adopters to distrust it."""
    _, body, _ = render_issue(finding())

    assert "Closing it will not suppress it" not in body
    assert "Closing this issue does not resolve the finding" in body
    assert "nothing" in body and "refiles it" in body
    assert ".sbom-watchdog/findings.json" in body


def test_dry_run_threads_the_scan_into_every_rendered_issue():
    scan = urllib3_scan()
    rendered = dry_run(list(scan.values()), scan)
    assert rendered.count("highest fix version among them is 2.7.0") == 4


# --- what upgrading does to the rest of the package -----------------------
#
# Three shapes, three actions. Two pycrypto issues against the same abandoned
# package read as two separate decisions, each carrying the same "replace it or
# accept the risk" paragraph and neither acknowledging the other, when one
# decision closes both.

def package(name: str, entries) -> dict:
    """A scan of one package: (cve, fixed_in) per finding."""
    return {
        f"{cve}::python::{name}": finding(
            key=f"{cve}::python::{name}", id=cve, aliases=frozenset({cve}),
            package_name=name, versions=("1.0",), fixed_in=fixed_in,
            fix_state="fixed" if fixed_in else "not-fixed",
        )
        for cve, fixed_in in entries
    }


def test_all_no_fix_says_one_decision_closes_everything():
    """The pycrypto shape. Nothing to upgrade to, so the only useful fact is
    that replacing the package resolves every one of them at once."""
    scan = package("pycrypto", [("CVE-2013-7459", ()), ("CVE-2018-6594", ())])
    _, body, _ = render_issue(scan["CVE-2013-7459::python::pycrypto"], scan)

    assert "This package has 2 findings in this scan, none with an available fix." in body
    assert "Replacing or removing it resolves all of them." in body
    assert "Upgrading to" not in body


def test_all_fixable_still_answers_which_version():
    """Unchanged. "Which version" is a different question from "how many does
    this close", and where every finding has a fix the version is the answer."""
    scan = package("urllib3", [("CVE-1", ("2.6.3",)), ("CVE-2", ("2.7.0",))])
    _, body, _ = render_issue(scan["CVE-1::python::urllib3"], scan)

    assert "the highest fix version among them is 2.7.0" in body
    assert "Upgrading to anything below that leaves the others open." in body
    assert "none with an available fix" not in body


def test_mixed_states_both_halves_because_upgrading_is_not_enough():
    """The dangerous shape, and the one that was silently wrong: it took the
    fixable wording, which implies an upgrade covers everything. It does not.
    A reader could upgrade and reasonably believe they were done."""
    scan = package("paramiko", [("CVE-1", ("2.4.2",)), ("CVE-2", ())])
    _, body, _ = render_issue(scan["CVE-1::python::paramiko"], scan)

    assert "This package has 2 findings in this scan." in body
    assert "Upgrading to 2.4.2 closes 1 of them" in body
    assert "the remaining 1 has no available fix" in body
    assert "resolved only by replacing or removing the package" in body

    # It must not claim the upgrade is sufficient.
    assert "leaves the others open" not in body
    assert "resolves all of them" not in body


def test_the_no_fix_issue_in_a_mixed_package_says_the_same_thing():
    """Both issues for a package have to agree about what the work is,
    whichever one the reader opens first."""
    scan = package("paramiko", [("CVE-1", ("2.4.2",)), ("CVE-2", ())])
    _, body, _ = render_issue(scan["CVE-2::python::paramiko"], scan)

    assert "Upgrading to 2.4.2 closes 1 of them" in body
    assert "the remaining 1 has no available fix" in body


def test_counts_include_findings_below_the_threshold():
    """A below-threshold finding is still resolved by replacing the package, so
    the count has to be honest about the work rather than about the noise."""
    scan = package("pycrypto", [("CVE-1", ()), ("CVE-2", ()), ("CVE-3", ())])
    scan["CVE-3::python::pycrypto"] = finding(
        key="CVE-3::python::pycrypto", id="CVE-3", aliases=frozenset({"CVE-3"}),
        package_name="pycrypto", versions=("1.0",), fixed_in=(),
        fix_state="not-fixed", severity="Low")

    _, body, _ = render_issue(scan["CVE-1::python::pycrypto"], scan)
    assert "This package has 3 findings in this scan" in body


def test_package_line_pluralises_the_remainder():
    """Rendered for a person; "the remaining 1 have" is the kind of detail that
    makes a security tool look unattended."""
    one = package_line(total=3, fixable=2, recommended="2.0")
    many = package_line(total=4, fixable=2, recommended="2.0")

    assert "the remaining 1 has no available fix and is resolved" in one
    assert "the remaining 2 have no available fix and are resolved" in many


def test_no_package_line_for_a_lone_finding():
    scan = package("pycrypto", [("CVE-1", ())])
    _, body, _ = render_issue(scan["CVE-1::python::pycrypto"], scan)
    assert "findings in this scan" not in body
