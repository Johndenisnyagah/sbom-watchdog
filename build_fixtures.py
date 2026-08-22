"""Writes the fixture set. Run once; the JSON files are the artefact, not this script."""
import json
import pathlib

ROOT = pathlib.Path(__file__).parent / "tests" / "fixtures"
GRYPE = ROOT / "grype"
STATE = ROOT / "state"


# Grype labels a package by ecosystem in three places at once. Deriving them
# from pkg_type keeps an npm entry from claiming a pypi purl.
ECOSYSTEMS = {
    "python": {"purl_type": "pypi", "language": "python"},
    "npm": {"purl_type": "npm", "language": "javascript"},
}


def match(vuln_id, name, version, severity, fixed_in, related=None,
          pkg_type="python", fix_state="fixed"):
    ecosystem = ECOSYSTEMS[pkg_type]
    return {
        "vulnerability": {
            "id": vuln_id,
            "dataSource": f"https://github.com/advisories/{vuln_id}",
            "namespace": f"github:language:{ecosystem['language']}",
            "severity": severity,
            "fix": {"versions": fixed_in, "state": fix_state},
        },
        "relatedVulnerabilities": [
            {"id": r, "namespace": "nvd:cpe", "severity": severity}
            for r in (related or [])
        ],
        "matchDetails": [{"type": "exact-direct-match", "matcher": "python-matcher"}],
        "artifact": {
            "name": name,
            "version": version,
            "type": pkg_type,
            "language": ecosystem["language"],
            "purl": f"pkg:{ecosystem['purl_type']}/{name}@{version}",
            "locations": [{"path": "/src/requirements.txt"}],
        },
    }


def report(matches):
    return {
        "matches": matches,
        "source": {"type": "directory", "target": "/src"},
        "distro": {"name": "", "version": ""},
        # Grype 0.117 shape. The DB build timestamp used to sit at db.built
        # and moved under db.status; db.providers is omitted as twenty feeds
        # of noise nothing reads.
        "descriptor": {
            "name": "grype",
            "version": "0.117.0",
            "db": {
                "status": {
                    "built": "2026-08-21T01:31:00Z",
                    "schemaVersion": "v6.1.9",
                },
            },
        },
    }


PYYAML = match("GHSA-8q59-q68h-6hv4", "PyYAML", "5.3.1", "Critical", ["5.4"],
               related=["CVE-2020-14343"])
REQUESTS = match("GHSA-x84v-xcm2-53pg", "requests", "2.19.1", "High", ["2.20.0"],
                 related=["CVE-2018-18074"])
SETUPTOOLS = match("GHSA-r9hx-vwmv-q579", "setuptools", "65.5.0", "Medium", ["65.5.1"],
                   related=["CVE-2022-40897"])

BASELINE = [PYYAML, REQUESTS, SETUPTOOLS]

files = {}

# 01 — three findings, one of them below the default High threshold.
files["01_baseline.json"] = report(BASELINE)

# 02 — baseline plus one genuinely new High finding.
files["02_new_finding.json"] = report(BASELINE + [
    match("GHSA-v845-jxx5-vc9f", "urllib3", "1.26.17", "High", ["1.26.18", "2.0.7"],
          related=["CVE-2023-45803"]),
])

# 03 — requests bumped 2.19.1 -> 2.19.2, still below the 2.20.0 fix.
#      Same CVE, same package, different version. Must NOT be new.
files["03_version_bump.json"] = report([
    PYYAML,
    match("GHSA-x84v-xcm2-53pg", "requests", "2.19.2", "High", ["2.20.0"],
          related=["CVE-2018-18074"]),
    SETUPTOOLS,
])

# 04 — requests upgraded past the fix; that finding is gone.
files["04_resolved.json"] = report([PYYAML, SETUPTOOLS])

# 05 — advisory with no CVE assigned yet. Key falls back to the GHSA ID.
files["05_ghsa_only.json"] = report(BASELINE + [
    match("GHSA-aaaa-bbbb-cccc", "jinja2", "3.1.2", "High", ["3.1.3"], related=[]),
])

# 06 — same advisory as 05, one day later, now carrying a CVE.
#      Alias reconciliation must recognise it. Must NOT be new.
files["06_alias_flip.json"] = report(BASELINE + [
    match("GHSA-aaaa-bbbb-cccc", "jinja2", "3.1.2", "High", ["3.1.3"],
          related=["CVE-2026-11111"]),
])

# 07 — setuptools re-rated Medium -> Critical. It crossed the threshold upward,
#      so it belongs in `changed` and it does deserve an issue.
files["07_severity_rerated.json"] = report([
    PYYAML,
    REQUESTS,
    match("GHSA-r9hx-vwmv-q579", "setuptools", "65.5.0", "Critical", ["65.5.1"],
          related=["CVE-2022-40897"]),
])

# 08 — same CVE and package present twice at different versions in the tree.
#      Must collapse to one Finding with two versions.
files["08_duplicate_versions.json"] = report([
    match("GHSA-v845-jxx5-vc9f", "urllib3", "1.26.15", "High", ["1.26.18", "2.0.7"],
          related=["CVE-2023-45803"]),
    match("GHSA-v845-jxx5-vc9f", "urllib3", "1.26.17", "High", ["1.26.18", "2.0.7"],
          related=["CVE-2023-45803"]),
])

# 09 — clean scan. Everything previously known is resolved.
files["09_empty.json"] = report([])

# 10 — same package name on a different ecosystem. Must not collide with PyPI.
files["10_cross_ecosystem.json"] = report([
    match("GHSA-x84v-xcm2-53pg", "requests", "2.19.1", "High", ["2.20.0"],
          related=["CVE-2018-18074"]),
    match("GHSA-dddd-eeee-ffff", "requests", "2.88.2", "High", ["3.0.0"],
          related=["CVE-2026-22222"], pkg_type="npm"),
])

# 11 — the python requests finding is gone and an npm package of the same name
#      carries the SAME CVE. Everything except package_type says "reconcile".
#      Guards the one field that must not be dropped from the match condition.
files["11_same_cve_other_ecosystem.json"] = report([
    PYYAML,
    SETUPTOOLS,
    match("GHSA-x84v-xcm2-53pg", "requests", "2.88.2", "High", ["3.0.0"],
          related=["CVE-2018-18074"], pkg_type="npm"),
])

for name, payload in files.items():
    (GRYPE / name).write_text(json.dumps(payload, indent=2) + "\n")


def finding(key, vid, aliases, name, ptype, versions, severity, fixed_in,
            first_seen, last_seen, issue_number=None):
    # aliases is the full identifier set for this finding, canonical id included.
    return key, {
        "id": vid,
        "aliases": sorted({vid, *aliases}),
        "package": {"name": name, "type": ptype, "versions": versions},
        "severity": severity,
        "fixed_in": fixed_in,
        "fix_state": "fixed",
        "first_seen": first_seen,
        "last_seen": last_seen,
        "issue_number": issue_number,
    }


def state(findings, generated="2026-08-20T03:00:00Z"):
    return {
        "schema_version": 1,
        "generated_at": generated,
        "tooling": {
            "syft": "1.20.0",
            "grype": "0.87.0",
            "grype_db_built": "2026-08-20T01:29:00Z",
        },
        "findings": dict(findings),
    }


baseline_findings = [
    finding("CVE-2020-14343::python::pyyaml", "CVE-2020-14343",
            ["GHSA-8q59-q68h-6hv4"], "pyyaml", "python", ["5.3.1"],
            "Critical", ["5.4"], "2026-08-01", "2026-08-20"),
    finding("CVE-2018-18074::python::requests", "CVE-2018-18074",
            ["GHSA-x84v-xcm2-53pg"], "requests", "python", ["2.19.1"],
            "High", ["2.20.0"], "2026-08-01", "2026-08-20"),
    finding("CVE-2022-40897::python::setuptools", "CVE-2022-40897",
            ["GHSA-r9hx-vwmv-q579"], "setuptools", "python", ["65.5.0"],
            "Medium", ["65.5.1"], "2026-08-01", "2026-08-20"),
]

(STATE / "baseline.json").write_text(
    json.dumps(state(baseline_findings), indent=2) + "\n")

# The same state after phase 4 has run: the two findings above the threshold
# carry issue numbers, the Medium one does not.
with_issues = [
    (k, {**v, "issue_number": n})
    for (k, v), n in zip(baseline_findings, [42, 43, None])
]
(STATE / "with_issue_numbers.json").write_text(
    json.dumps(state(with_issues), indent=2) + "\n")

# Baseline plus the GHSA-only jinja2 finding, so fixture 06 has something
# to reconcile against.
ghsa_only = baseline_findings + [
    finding("GHSA-aaaa-bbbb-cccc::python::jinja2", "GHSA-aaaa-bbbb-cccc",
            ["GHSA-aaaa-bbbb-cccc"], "jinja2", "python", ["3.1.2"],
            "High", ["3.1.3"], "2026-08-19", "2026-08-20", issue_number=44),
]
(STATE / "ghsa_only.json").write_text(
    json.dumps(state(ghsa_only), indent=2) + "\n")

print(f"wrote {len(files)} grype fixtures and 3 state fixtures")
