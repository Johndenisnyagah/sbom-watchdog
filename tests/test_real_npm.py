"""The npm ecosystem, against genuine Grype output.

`tests/fixtures/grype/real_python_npm_0117.json` is Grype 0.117.0 output from
the public testbed (github.com/Johndenisnyagah/watchdog-testbed) on
2026-10-26, after four deliberately vulnerable npm packages were added beside
the existing Python ones. It is captured, not generated: one absolute runner
path was scrubbed to `/src/` and nothing else altered.

Before this file, npm was covered only by reconstructed fixtures (10 and 11),
which carry Python matcher details under an npm package type. These tests are
what lets the README say npm has been run in anger, so each one asserts
something a real npm scan could break: a scoped name, a vulnerability that
arrives through a dependency nobody listed, two findings on one package, and
a mixed Python/npm inventory.
"""
import json
import pathlib

from src.diff import diff, select_for_issues
from src.issues import render_issue
from src.model import parse_grype
from src.report import inventory_markdown
from src.run import main
from src.state import findings_from_state, save_state, state_from_findings

CAPTURE = (pathlib.Path(__file__).parent / "fixtures" / "grype"
           / "real_python_npm_0117.json")

NPM_KEYS = {
    "CVE-2020-15168::npm::node-fetch",
    "CVE-2020-7598::npm::minimist",
    "CVE-2021-44906::npm::minimist",
    "CVE-2022-0235::npm::node-fetch",
    "CVE-2022-25883::npm::semver",
    "CVE-2023-45133::npm::@babel/traverse",
}

FILED_AT_HIGH = {
    "CVE-2021-44906::npm::minimist",
    "CVE-2022-0235::npm::node-fetch",
    "CVE-2022-25883::npm::semver",
    "CVE-2023-45133::npm::@babel/traverse",
}


def scan() -> dict:
    return parse_grype(json.loads(CAPTURE.read_text(encoding="utf-8")))


def python_only(findings: dict) -> dict:
    return {k: f for k, f in findings.items() if f.package_type == "python"}


def state_of(findings: dict) -> dict:
    return state_from_findings(findings, provenance={},
                               generated_at="2026-10-25T08:30:00Z", tooling={})


# --- parsing ---------------------------------------------------------------

def test_the_capture_parses_to_both_ecosystems():
    findings = scan()
    assert len(findings) == 25
    assert len(python_only(findings)) == 19
    assert {k for k, f in findings.items() if f.package_type == "npm"} == NPM_KEYS


def test_npm_findings_are_keyed_on_the_cve_and_keep_the_ghsa():
    """Grype reports these under their GHSA id; the CVE wins, as for Python."""
    traverse = scan()["CVE-2023-45133::npm::@babel/traverse"]
    assert traverse.id == "CVE-2023-45133"
    assert "GHSA-67hx-6x53-jw92" in traverse.aliases


def test_a_scoped_name_survives_intact():
    traverse = scan()["CVE-2023-45133::npm::@babel/traverse"]
    assert traverse.package_name == "@babel/traverse"
    assert traverse.versions == ("7.23.0",)


def test_a_transitive_dependency_is_reported_like_a_direct_one():
    """minimist is not in package.json; mkdirp pulls it in."""
    minimist = [f for f in scan().values() if f.package_name == "minimist"]
    assert {f.severity for f in minimist} == {"Critical", "Medium"}


# --- state and diff --------------------------------------------------------

def test_npm_findings_round_trip_through_the_state_file(tmp_path):
    findings = scan()
    path = tmp_path / "findings.json"
    save_state(path, state_of(findings))
    reloaded = findings_from_state(json.loads(path.read_text(encoding="utf-8")))
    assert reloaded == findings
    assert diff(reloaded, findings).new == {}


def test_adding_npm_to_a_python_project_is_six_new_and_four_issues():
    """What the testbed's first scan after npm was added actually reported."""
    findings = scan()
    result = diff(python_only(findings), findings)
    assert set(result.new) == NPM_KEYS
    assert len(result.unchanged) == 19
    assert {f.key for f in select_for_issues(result, "High")} == FILED_AT_HIGH


def test_the_dry_run_names_the_four_issues(tmp_path, capsys):
    state = tmp_path / "findings.json"
    save_state(state, state_of(python_only(scan())))
    before = state.read_bytes()

    # The flags the action passes on a dry run: --write-state is declined.
    assert main(["--scan", str(CAPTURE), "--state", str(state),
                 "--write-state", "--dry-run-issues"]) == 0

    out = capsys.readouterr().out
    assert "4 issue(s) would be filed" in out
    for key in FILED_AT_HIGH:
        assert f"[{key}]" in out
    assert state.read_bytes() == before


# --- what the reader sees --------------------------------------------------

def test_the_scoped_issue_reads_correctly():
    findings = scan()
    key = "CVE-2023-45133::npm::@babel/traverse"
    title, body, labels = render_issue(findings[key], findings)
    assert title == f"Critical: CVE-2023-45133 in @babel/traverse [{key}]"
    assert "`@babel/traverse` (npm)" in body
    assert "**Fixed in:** 7.23.2" in body
    assert "https://github.com/advisories/GHSA-67hx-6x53-jw92" in body
    assert "severity:critical" in labels


def test_two_findings_on_one_package_point_at_one_version():
    findings = scan()
    _, body, _ = render_issue(findings["CVE-2022-0235::npm::node-fetch"], findings)
    assert "2 findings in this scan; the highest fix version among them is 2.6.7" in body


def test_no_npm_issue_is_flagged_as_a_pre_release_or_a_major_jump():
    """Grype's database lists only stable fixes for these. The 8.0.0-alpha.4
    fix in the GitHub advisory for @babel/traverse does not reach the scan."""
    findings = scan()
    for key in FILED_AT_HIGH:
        _, body, _ = render_issue(findings[key], findings)
        assert "pre-release" not in body
        assert "crosses a major version" not in body


def test_a_zero_major_minor_bump_is_not_flagged_known_gap():
    """minimist 0.0.8 -> 0.2.4. SemVer treats a 0.x minor bump as breaking;
    this tool compares the first release number only, so it says nothing.
    Documented in CLAUDE.md as a known gap rather than an npm-specific rule.
    If this test starts failing, the gap was closed: update CLAUDE.md."""
    findings = scan()
    _, body, _ = render_issue(findings["CVE-2021-44906::npm::minimist"], findings)
    assert "crosses a major version" not in body


def test_the_mixed_inventory_names_both_ecosystems():
    rendered = inventory_markdown(state_of(scan()))
    assert "| Package | Ecosystem | Version in use |" in rendered
    assert "| @babel/traverse | JavaScript (npm) |" in rendered
    assert "| pyyaml | Python (PyPI) |" in rendered
    for jargon in ("purl", "fix_state", "not-fixed", "cyclonedx"):
        assert jargon not in rendered.lower()
