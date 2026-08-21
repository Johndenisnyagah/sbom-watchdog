# sbom-watchdog — working agreement

A GitHub Action that generates an SBOM daily, scans it for known vulnerabilities, and opens an issue only for findings that were not present yesterday.

This file is the contract. When something here conflicts with a suggestion made mid-session, this file wins. If a decision genuinely needs to change, change it here first and say so, rather than working around it in one module.

## Current phase

Step 2 is complete: `model.py`, `state.py` and `diff.py` are implemented and all 30 tests in `tests/test_diff.py` pass, including `11_same_cve_other_ecosystem.json`, the only fixture constraining `package_type` in the reconciler. Step 1 has now been done retroactively — Syft 1.51.0 and Grype 0.117.0 were run against a stale requirements.txt and `parse_grype` handled the real output without changes. Two fixture-schema drifts are recorded below and not yet corrected. Next is step 3, the `workflow_dispatch` workflow. `issues.py` and `report.py` are still empty.

Step numbers refer to the build order below, not to the six phases in the original project brief. The two do not line up, and the build order governs.

Update this line at the end of every session.

## Build order

1. Local shell script running Syft and Grype against a real repo, output inspected by hand.
2. **Diff engine** (`model.py`, `state.py`, `diff.py`) with the fixture tests in `tests/`. Pure Python, no network, no GitHub.
3. Workflow file, `workflow_dispatch` only, proving the tools install and run on GitHub's runners.
4. Issue creation with deduplication, labelled by severity.
5. CycloneDX SBOM committed under a dated path, plus a generated `SECURITY-INVENTORY.md`.
6. Composite action packaging and README.

Phase 2 comes before the workflow deliberately. The diff logic is the part worth thinking about and it runs fine on a laptop; fighting Actions permissions first teaches less and burns a whole evening.

## Out of scope for v1

Multi-repo scanning. Web dashboard. Container image scanning. Reachability analysis. PR-blocking checks. Slack notifications. Ecosystems beyond the one chosen.

The dashboard is the specific trap. It is more fun to build than diff logic and produces a screenshot after an afternoon, which is why the repo would then go quiet with no working scanner behind it. If asked to build any of the above, say it is out of scope and point at this section.

## Definition of done for v1

A person who is not the author adds the action to their own repository and, within 24 hours, receives a GitHub issue about a genuinely new vulnerability in a dependency they did not know they had.

## Finding identity

A finding is keyed on three parts, joined by `::`:

```
{vulnerability_id}::{package_type}::{package_name}
```

Package name is lowercased. Version is deliberately excluded from the key, so upgrading a package from 1.2.0 to 1.3.0 while it remains vulnerable to the same CVE updates the existing record instead of filing a second issue. Package type is included because `requests` on PyPI and `requests` on npm are unrelated packages.

### Vulnerability ID normalisation

Grype frequently reports a GHSA identifier as `match.vulnerability.id` and carries the CVE in `match.relatedVulnerabilities`. If the raw ID were used as the key, the same flaw could change identity between runs when the advisory database updates, and a duplicate issue would be filed.

Rule: if any entry in `relatedVulnerabilities` has an ID starting with `CVE-`, that CVE is the canonical ID. Otherwise the primary ID is used as-is.

When several CVEs are present, take the lexicographically smallest. The advisory database reorders that list between releases, and picking the first would let the key move on a day when nothing about the vulnerability changed.

`aliases` holds every identifier ever seen for the finding, canonical ID included. Storing it inclusively matters more than it looks: if `aliases` excluded the canonical ID, a state file written yesterday would never compare equal to a fresh Grype parse today, and every finding would show up as changed on every run.

### Alias reconciliation

Normalisation alone does not cover the case where a vulnerability had no CVE assigned yesterday and has one today. Before computing the set difference, each current finding whose key is absent from the previous state is checked against previous findings with the same `package_type` and `package_name`. If the alias sets intersect, it is the same finding: carry forward the previous key, `first_seen`, and `issue_number`, and merge the alias sets.

A finding that survives reconciliation is not new and must not produce an issue.

## State file

Path: `.sbom-watchdog/findings.json`, committed to the repository. Committing is noisier in git history than the Actions cache but survives cache eviction and doubles as the audit trail, which is half the point of the project.

```json
{
  "schema_version": 1,
  "generated_at": "2026-08-21T03:00:00Z",
  "tooling": {
    "syft": "1.20.0",
    "grype": "0.87.0",
    "grype_db_built": "2026-08-21T01:31:00Z"
  },
  "findings": {
    "CVE-2020-14343::python::pyyaml": {
      "id": "CVE-2020-14343",
      "aliases": ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"],
      "package": {
        "name": "pyyaml",
        "type": "python",
        "versions": ["5.3.1"]
      },
      "severity": "Critical",
      "fixed_in": ["5.4"],
      "fix_state": "fixed",
      "first_seen": "2026-08-01",
      "last_seen": "2026-08-21",
      "issue_number": 42
    }
  }
}
```

`aliases` is sorted, and so is `versions`, for the same reason: an unsorted list rewrites the committed file on every run and fills the git history with noise.

When two matches collapse to one finding, take the highest severity, not the first. Grype can report the same package under both the NVD and GitHub namespaces with different ratings, and a security tool that rounds down is the wrong kind of wrong. `SEVERITY_ORDER` therefore lives in `model.py`, which is where the domain vocabulary belongs; `diff.py` re-exports it so the public API in this file stays accurate.

`fixed_in` is sorted for the same anti-churn reason as `aliases` and `versions`. All three use plain string sort, so `1.26.10` sorts before `1.26.9`. That is only cosmetic while nothing compares versions semantically. Phase 4 renders these into issue text, which is the point to revisit it — with a hand-rolled natural sort key, since the stdlib-only rule stands.

The findings map is written sorted by key, alongside aliases, versions and fixed_in. The first save against an existing state file therefore reorders it once; every save after that is stable.

`first_seen` and `last_seen` are derived from `generated_at`, never from a separate clock call. Two date lookups either side of midnight UTC eventually write a record first seen after it was last seen.

When matches collapse, `fixed_in` is the union across all of them and `fix_state` is "fixed" if any match reports a fix. Fix data does not follow the severity winner: NVD and GitHub disagree about fix availability, and reporting "no fix" for a package that has one is the more damaging error.

`versions` is a list because a dependency tree genuinely ships two copies of the same package at different versions, and both are vulnerable. Sort it before writing so the committed file does not churn.

`issue_number` is the deduplication mechanism. Its presence means the issue already exists; skip creation. `null` means the finding was recorded but no issue was filed, which is the normal state for anything below the severity threshold.

Bump `schema_version` on any shape change and write a migration in `state.py`. Never silently reinterpret an old file.

## Three behaviours that must not regress

**Bootstrap.** If the state file is absent, the run records the baseline, files zero issues, and logs the count. Without this, the first run against a real project opens several hundred issues at once.

**Severity is recorded, not filtered, at state level.** Every finding Grype reports goes into the state file regardless of severity. The threshold applies only when deciding what to file an issue about. If low-severity findings were dropped from state, a Medium later re-rated to Critical by NVD would look brand new, and the audit trail would have a hole in it.

**Ordering under partial failure.** Scan, diff, create issues, write issue numbers into state, commit. If the commit fails after issues are created, the next run refiles them. The cheap safety net is putting the finding key in the issue title and doing one `GET /search/issues` before creating.

## Module boundaries

```
src/
├── model.py    Grype JSON -> Finding objects, ID normalisation
├── state.py    load/save state file, schema versioning, bootstrap detection
├── diff.py     pure: (previous, current) -> DiffResult
├── issues.py   GitHub API
└── report.py   SECURITY-INVENTORY.md generation
```

`diff.py` imports from `model.py` only. It does not touch the filesystem, the network, the clock, or `os.environ`. Everything it needs arrives as an argument. This is what makes the fixture tests possible, and it is the constraint most likely to get quietly violated when wiring up phase 4.

## Public API

```python
# model.py
@dataclass(frozen=True)
class Finding:
    key: str
    id: str
    aliases: frozenset[str]
    package_name: str
    package_type: str
    versions: tuple[str, ...]
    severity: str            # Critical | High | Medium | Low | Negligible | Unknown
    fixed_in: tuple[str, ...]
    fix_state: str           # fixed | not-fixed | wont-fix | unknown

def parse_grype(report: dict) -> dict[str, Finding]: ...

# state.py
def provenance_from_state(state: dict) -> dict[str, dict]: ...
def findings_from_state(state: dict) -> dict[str, Finding]: ...
def state_from_findings(findings: dict[str, Finding], *, provenance: dict,
                        generated_at: str, tooling: dict) -> dict: ...
def load_state(path) -> dict | None: ...      # None when the file is absent
def save_state(path, state: dict) -> None: ...
def utc_now() -> str: ...                     # ISO 8601, trailing Z

# provenance maps finding key -> {"first_seen": str, "issue_number": int|None}.
# Phase 4 mutates that dict after filing issues, then serialises once.
#
# Timestamp formatting lives with the serialiser: leaving the orchestrator to
# invent it invites drift from the convention above. provenance_from_state
# enforces schema_version exactly as the other document readers do, so no
# reader can quietly reinterpret an old file.

# model.py, re-exported from diff.py
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

# diff.py
@dataclass(frozen=True)
class DiffResult:
    bootstrap: bool
    new: dict[str, Finding]
    resolved: dict[str, Finding]
    unchanged: dict[str, Finding]
    changed: dict[str, tuple[Finding, Finding]]   # key -> (previous, current)

def diff(previous: dict[str, Finding] | None,
         current: dict[str, Finding]) -> DiffResult: ...

def select_for_issues(result: DiffResult,
                      threshold: str = "High") -> list[Finding]: ...
```

`diff(None, current)` returns `bootstrap=True` with everything in `unchanged` and `new` empty. The caller does not special-case the first run; the function already did.

`changed` covers a finding present in both runs where any recorded field differs: severity, versions, fix availability, alias set, or canonical ID. Alias and ID movement counts because a GHSA that gains a CVE needs its state record and issue title rewritten even though the vulnerability itself did not move.

A changed finding files an issue in exactly one situation: its severity was below the threshold in the previous run and is at or above it now. NVD re-rates things, and a dependency that quietly became Critical overnight is exactly the alert this tool exists to send. Every other change is recorded and stays silent, since a version bump that leaves the package vulnerable does not deserve a second notification.

That rule is derivable from `DiffResult` alone, because `changed` holds both the previous and the current `Finding`. `select_for_issues` therefore stays pure and never needs to know whether an issue already exists; deduplication against `issue_number` happens in `issues.py`.

## Severity threshold

Configurable, default `High`. Ordering, high to low: Critical, High, Medium, Low, Negligible, Unknown. Compare by index in that list, never by string. Unknown sorts last and is therefore never filed by default.

An unrecognised threshold raises `ValueError`. Scoring it as unknown sorts it last and files every finding in the repo, which is the loudest possible failure mode for a silent typo.

## Tests

Fixtures live in `tests/fixtures/grype/` and `tests/fixtures/state/`, described in `tests/fixtures/README.md`. Every fixture exists because of a specific failure mode; do not delete one to make a test pass.

Tests are the specification for phase 2. If a test fails, the implementation is wrong until an argument is made here that the test is.

## Conventions

Python 3.11+, standard library only for `model`, `state`, and `diff`. `requests` is permitted in `issues.py`. Type hints throughout. `pytest` for tests, `ruff` for lint.

Timestamps are UTC, ISO 8601, with a trailing `Z`. Dates in `first_seen` and `last_seen` are `YYYY-MM-DD`.

Workflow permissions are `contents: write` and `issues: write`. Nothing else.

Two Actions facts that affect design: scheduled workflows are disabled automatically after 60 days without repository activity, so the README must warn about it. Commits pushed with the default `GITHUB_TOKEN` do not trigger other workflows, which is what prevents the commit-back step from re-triggering the scan.
