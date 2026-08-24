# Fixtures

Each file exists because of a specific failure mode. Do not delete one to make a test pass.

The Grype reports are trimmed: `description`, `cvss`, `advisories`, `cpes`, and most of `matchDetails` are dropped because nothing in the diff engine reads them. The fields that remain match Grype 0.117 JSON output, so a real report drops in without changing the parser. The one exception is `packaging/real_0117.json`, which is genuine captured output rather than a reconstruction.

CVE identifiers and their package pairings are real (CVE-2020-14343 is the PyYAML `full_load` flaw, CVE-2018-18074 is the requests redirect credential leak). GHSA identifiers, and the two `CVE-2026-*` IDs used for the alias and cross-ecosystem cases, are synthetic placeholders in the correct format.

Severity ratings are chosen to exercise the threshold logic and deliberately do not match NVD. Real Grype rates CVE-2022-40897 (setuptools) High; the fixtures use Medium so that it sits below the default High threshold and exercises the record-but-do-not-file path. Do not "correct" these against a live scan.

## Grype reports

| File | Guards against |
| --- | --- |
| `01_baseline.json` | The reference state. Three findings, one below the default threshold. |
| `02_new_finding.json` | Baseline plus one genuinely new High finding. The happy path. |
| `03_version_bump.json` | requests 2.19.1 → 2.19.2, still below the 2.20.0 fix. Same CVE. Filing a second issue here is the most annoying possible bug and the reason version is excluded from the key. |
| `04_resolved.json` | requests upgraded past the fix. Detects the resolved set without treating the two survivors as new. |
| `05_ghsa_only.json` | An advisory with no CVE assigned. The key falls back to the GHSA ID. |
| `06_alias_flip.json` | The same advisory one day later, now carrying a CVE. The key changes. Alias reconciliation must recognise it as the same finding, or it files a duplicate. |
| `07_severity_rerated.json` | setuptools re-rated Medium → Critical. Not new, but it crossed the threshold and was never filed, so it earns an issue. |
| `08_duplicate_versions.json` | The same package at two versions in one dependency tree. One finding, two versions, one issue. |
| `09_empty.json` | A clean scan. Everything previously known resolves at once. |
| `10_cross_ecosystem.json` | `requests` on PyPI and `requests` on npm in the same repo. Keys must not collide, and an alias overlap must not match across package types. |
| `11_same_cve_other_ecosystem.json` | The python `requests` finding is gone and an npm package of the same name carries the same CVE. Every reconciliation condition except `package_type` is satisfied, so it guards the one field that must not be dropped from the match. |

## State files

| File | Purpose |
| --- | --- |
| `baseline.json` | The committed state that `01_baseline.json` would produce, dated one day earlier. |
| `with_issue_numbers.json` | The same state after phase 4 has run. Two findings carry issue numbers, the Medium one carries `null`. Used to test deduplication. |
| `ghsa_only.json` | Baseline plus the jinja2 GHSA-only finding, so `06_alias_flip.json` has something to reconcile against. |

## Regenerating

`build_fixtures.py` at the repository root wrote all of these. Editing the JSON directly is fine for a one-off; edit the script when a change affects several files at once, so the reports stay internally consistent.

## The captured document

`packaging/real_0117.json` is genuine Grype 0.117.0 output against a stale requirements.txt, 22 findings, with absolute paths scrubbed and nothing else altered. It is semantically verbatim but re-serialised through `json.dumps(indent=2)`, so its whitespace differs from raw Grype output; every value and the key order are preserved.

It lives under `packaging/` rather than here because the composite action bundles it and must work from a checkout with no test directory. There is exactly one copy on purpose. Two would let the action's startup self-check and this suite assert against different bytes, which is how a packaged action passes its own check while the parser has drifted.

`test_diff.py::test_parses_real_grype_output` and `test_run.py` both read it from there. It is captured, not generated: `build_fixtures.py` neither overwrites nor recreates it. Replacing it means re-running Syft and Grype against the same pinned requirements and scrubbing the paths again.
