# sbom-watchdog — working agreement

A GitHub Action that generates an SBOM daily, scans it for known vulnerabilities, and opens an issue only for findings that were not present yesterday.

This file is the contract. When something here conflicts with a suggestion made mid-session, this file wins. If a decision genuinely needs to change, change it here first and say so, rather than working around it in one module.

## Current phase

Phase 6 part 1 is done: `action.yml` is a composite action at the repository root, shipping `packaging/real_0117.json` for the startup self-check and `packaging/syft.yaml` as the default scan config. It installs and verifies pinned Syft and Grype, scans, diffs and files issues, and deliberately does not commit — the adopter's workflow owns writes to their repository. `.github/workflows/example.yml` is the snippet they paste, including the commit-back they own. Verified against a checkout with no `tests/`. Still outstanding for part 2: the README, `.gitattributes` guidance for adopters, `report.py` shipping empty, and a `v1` tag. Previously: schema 2: resolved findings stay in the state document with `resolved_on`, their issues are closed with a comment, and a finding that returns is reported as new and references the issue it was filed under. Previously: step 5 is wired and the issue bodies have been read at volume. `render_issue` takes the whole scan so every issue for a package names the same highest fix, flags a major-version jump, and no longer claims a closed issue would be refiled. Previously: step 5 is wired: the workflow holds `contents: write` and `issues: write`, passes `--repo` from `github.repository` and the token through the environment, and takes a `dry_run` boolean input defaulting to true, so a first dispatch prints what it would file rather than filing it. Anything other than an explicit `false` selects the dry run. Nothing has been installed in the testbed at https://github.com/Johndenisnyagah/watchdog-testbed yet; that is the next step. Previously: step 5 part 1, standard library only: `issues.py` renders a finding as (title, body, labels) and carries `find_existing_issue`, `create_issue` and `ensure_labels` over `urllib.request`. `run.py --file-issues` needs `--repo` and `GITHUB_TOKEN` and is mutually exclusive with `--dry-run-issues`; it updates provenance in place as each number is obtained, which closes the within-run duplicate window and means a partial failure still writes what it collected. Nothing calls it yet: the workflow is untouched and has no `issues: write`. Previously: `issues.py` renders a finding as (title, body, labels), and carries `find_existing_issue`, `create_issue` and `ensure_labels` behind a lazy `requests` import, so rendering and `--dry-run-issues` work without it. `run.py --file-issues` needs `--repo` and `GITHUB_TOKEN` and is mutually exclusive with `--dry-run-issues`; it writes issue numbers into provenance before the state document is built, and writes state even when filing fails partway. Nothing calls it yet: the workflow is untouched and has no `issues: write`. Previously: step 5 part 1: `issues.py` renders a finding as (title, body, labels) and prints what it would post. `run.py --dry-run-issues` drives it. No GitHub API, no `issues: write`, no workflow change; the API is part 2. Previously: step 4 is done. The workflow reads committed state, diffs, writes back, survives a concurrent run and commits only when something changed. Proven on runners: two runs dispatched 41 seconds apart at the same pinned SHA produced exactly one baseline commit, the second syncing the first's state and skipping its commit step. Previously: step 4 part 2: `run.py` gained `--write-state`, which updates the state file in place and only when the document actually changed. The workflow now holds `contents: write`, is serialised with `concurrency`, and commits `.sbom-watchdog/findings.json` as github-actions[bot], rebasing before it pushes. Issue creation is still not built; that is part 3 and needs `issues: write`. `tests/test_run.py` covers bootstrap, idempotency, provenance carry-forward and the reconciled-key case. Previously: step 4 part 1: `src/run.py` wires parse, load, diff and save together, takes every path as an argument, prints a summary and writes the next state document. It files no issues and commits nothing. The workflow runs it after the scan and uploads the state document it *would* write as an artifact, still under `contents: read`. Step 3 is complete: `.github/workflows/watchdog.yml` exists, `workflow_dispatch` only, `contents: read` only. It installs pinned Syft 1.51.0 and Grype 0.117.0, runs the suite, produces an SBOM and a scan, validates the Grype document has a `matches` key, and uploads both as artifacts. It deliberately does not diff, write state, file issues or commit. Scanning this repo yields three components and no findings — the toolchain is what is being proved, not the scanner. Steps 1 and 2 are complete and all 38 tests pass. `issues.py` and `report.py` are still empty. Nothing has been granted `contents: write` or `issues: write`.

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
  "schema_version": 2,
  "generated_at": "2026-08-21T03:00:00Z",
  "tooling": {
    "syft": "1.51.0",
    "grype": "0.117.0",
    "grype_db_built": "2026-08-21T01:31:00Z",
    "grype_db_schema_version": "v6.1.9"
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
      "issue_number": 42,
      "resolved_on": null
    }
  }
}
```

`aliases` is sorted, and so is `versions`, for the same reason: an unsorted list rewrites the committed file on every run and fills the git history with noise.

When two matches collapse to one finding, take the highest severity, not the first. Grype can report the same package under both the NVD and GitHub namespaces with different ratings, and a security tool that rounds down is the wrong kind of wrong. `SEVERITY_ORDER` therefore lives in `model.py`, which is where the domain vocabulary belongs; `diff.py` re-exports it so the public API in this file stays accurate.

`fixed_in` is sorted for the same anti-churn reason as `aliases` and `versions`. All three use plain string sort in the state file, so `1.26.10` is stored before `1.26.9`. That stays cosmetic because nothing reads the order back. Comparison is a separate matter and now exists: `issues.py` carries `version_key`, a hand-rolled natural sort — split on dots, numeric parts as integers — used to pick the highest fix across a package's findings. Plain string sort there would recommend `1.26.9` over `1.26.10` and send a reader to an older release than the one that fixes their problem.

The findings map is written sorted by key, alongside aliases, versions and fixed_in. The first save against an existing state file therefore reorders it once; every save after that is stable.

`first_seen` and `last_seen` are derived from `generated_at`, never from a separate clock call. Two date lookups either side of midnight UTC eventually write a record first seen after it was last seen.

When matches collapse, `fixed_in` is the union across all of them and `fix_state` is "fixed" if any match reports a fix. Fix data does not follow the severity winner: NVD and GitHub disagree about fix availability, and reporting "no fix" for a package that has one is the more damaging error.

`versions` is a list because a dependency tree genuinely ships two copies of the same package at different versions, and both are vulnerable. Sort it before writing so the committed file does not churn.

`issue_number` is the deduplication mechanism. Its presence means the issue already exists; skip creation. `null` means the finding was recorded but no issue was filed, which is the normal state for anything below the severity threshold.

`tooling` is provenance only. Nothing reads it back: both document readers touch `findings` alone. Adding a key there therefore does not require a `schema_version` bump, which is why `grype_db_schema_version` arrived without one.

`tooling.grype_db_built` is read through a tolerant accessor that tries both the 0.117 path (`descriptor.db.status.built`) and the older 0.87 path (`descriptor.db.built`). Grype relocated the field once already. A missing value is recorded as null rather than raising: provenance degrading is survivable, a scan aborting is not.

The vulnerability database is deliberately not cached between runs. On a runner Grype downloads a fresh DB and completes the scan in about 60 seconds. Caching it would trade a stale-CVE risk against under a minute of wall time, in a tool whose entire premise is catching newly-disclosed CVEs. `tooling.grype_db_built` records which DB a given run actually used, so a stale one would at least be visible after the fact.

The commit-back decides whether to commit with `state_documents_equal`, not with `git diff`. `generated_at` moves on every run, so a textual comparison would commit daily with nothing in it. The comparison is semantic, and it ignores `generated_at` and nothing else. No special-casing of `tooling` or `last_seen`.

That means a repo with any findings commits once a day, because `last_seen` advances. That is correct and deliberate. `last_seen` advancing is the information: it distinguishes "still vulnerable as of yesterday" from "we stopped scanning in March", which is the question the audit trail exists to answer. Suppressing it to keep `git log` tidy would trade the point of the project for cosmetics.

`findings.json` is working state, committed for durability; its current contents matter, not its history. The append-only audit trail is phase 5's dated SBOM path, not this file. The commit message is built by `run.py` and written to a file for the workflow to read, not assembled in workflow shell. `$GITHUB_OUTPUT` is per-step: a later step reading it sees an empty file, which is how a real baseline was once committed as `no change (scan of )` with the date missing and the bootstrap branch never reached. Message text is permanent in someone's history, so it belongs where it can be tested. The commit-back refuses to commit at all if the message file is missing or empty.

The message carries the signal, in three forms: `baseline, N findings recorded` on a first run, `N new, M resolved` when findings moved, and `no change (scan of YYYY-MM-DD)` when only the scan date did. Bootstrap is checked first and is not optional. A first run reports zero new by design, so without its own branch a baseline would be committed as "no change" - a two hundred finding inventory announced as nothing having happened. That commit is permanent, and it is the first thing someone reads when deciding whether to trust the tool. It is how a security tool gets uninstalled on day one. Both carry `[skip ci]`, which is redundant while the default `GITHUB_TOKEN` is in use — its commits do not trigger workflows — but is what prevents a loop if a PAT is ever swapped in.

Resolved findings are **not** deleted. They stay in the document with `resolved_on` set. The earlier rule — drop them, git history preserves them — is withdrawn: git history can tell you a finding was resolved but not which issue it was, and reconstructing that means diffing two commits of a file nobody reads that way. The record is the only link between a finding and the issue it was filed under. Delete it and nothing can close that issue, or reference it if the vulnerability returns.

A resolved record is not currently present, so `findings_from_state` excludes it and `resolved_from_state` returns it separately. A finding with `resolved_on` that reappears in a scan is therefore absent from `previous` and lands in `new`, which is correct: that is a regression, and it is louder than an unchanged finding deliberately. Its `issue_number` and `first_seen` carry forward through provenance, so the new issue can reference the old one, and its `last_seen` stays at the day it was last actually seen.

Schema 2 does exactly that. `migrate` upgrades a v1 document by adding `resolved_on: null` to every record: v1 deleted resolved findings, so everything a v1 file carries is currently present and nothing is inferred.

Bump `schema_version` on any shape change and write a migration in `state.py`. Never silently reinterpret an old file.

## Three behaviours that must not regress

**Bootstrap.** If the state file is absent, the run records the baseline, files zero issues, and logs the count. Without this, the first run against a real project opens several hundred issues at once.

**Severity is recorded, not filtered, at state level.** Every finding Grype reports goes into the state file regardless of severity. The threshold applies only when deciding what to file an issue about. If low-severity findings were dropped from state, a Medium later re-rated to Critical by NVD would look brand new, and the audit trail would have a hole in it.

**A resolved finding gets its issue closed.** `issues.py` posts a comment naming why, then PATCHes the issue closed. A close failure never fails the run: the state write matters more, because a stale open issue is visible and recoverable where a lost issue number is not.

**Only an open issue counts as prior filing.** `find_existing_issue` asks for `is:open`. A closed issue means the finding was resolved and dealt with; if it is being filed again the vulnerability has returned, and treating the closed issue as evidence would swallow the regression. Missing a returning vulnerability is the one direction this tool must not fail in.

**Ordering under partial failure.** Scan, diff, create issues, write issue numbers into state, commit. If the commit fails after issues are created, the next run refiles them. The cheap safety net is putting the finding key in the issue title and doing one `GET /search/issues` before creating.

The workflow expresses this with `continue-on-error` on the run step and `if: always()` on the commit step, failing the run in a later step instead. The natural YAML, where a failing step skips the rest, is backwards here: it would abandon the issue numbers collected before the failure and refile those issues tomorrow. Verified by forcing a failure on the second of two issues — the first issue's number reached the state file, the second stayed null for a retry, and the process still exited nonzero.

Labels degrade rather than block. A token without permission to create a label files the issue without it and logs the shortfall once: labels are decoration, the issue is the product. A non-403 failure still raises, because that is a bug rather than a permission boundary.

## Module boundaries

```
src/
├── model.py    Grype JSON -> Finding objects, ID normalisation
├── state.py    load/save state file, schema versioning, bootstrap detection
├── diff.py     pure: (previous, current) -> DiffResult
├── run.py      orchestrator: paths in, summary out, state document written
├── selfcheck.py parses the bundled sample, asserts the parser still works
├── issues.py   GitHub API
└── report.py   SECURITY-INVENTORY.md generation
```

`run.py` is the only module that reads a clock, touches the filesystem and
knows where files live. Every path arrives as a command-line argument, so
nothing hardcodes `.sbom-watchdog/findings.json`: the workflow passes it and
the tests point somewhere else. It writes the state document from the diff
result rather than from the parsed scan, because reconciliation moves a
finding back to the key it was first filed under and that key is what
`first_seen` and `issue_number` hang off. Resolved findings stay in the new
state with a `resolved_on` date.

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
def migrate(state: dict) -> dict: ...            # v1 -> v2, never in place
def provenance_from_state(state: dict) -> dict[str, dict]: ...
def findings_from_state(state: dict) -> dict[str, Finding]: ...    # unresolved
def resolved_from_state(state: dict) -> dict[str, Finding]: ...    # resolved
def state_from_findings(findings: dict[str, Finding], *, provenance: dict,
                        generated_at: str, tooling: dict,
                        resolved: dict[str, Finding] | None = None) -> dict: ...
def load_state(path) -> dict | None: ...      # None when the file is absent
def save_state(path, state: dict) -> None: ...
def utc_now() -> str: ...                     # ISO 8601, trailing Z
def tooling_from_grype(report: dict,
                       syft_version: str | None = None) -> dict: ...
def state_documents_equal(previous: dict | None, current: dict | None, *,
                          ignore: tuple[str, ...] = ("generated_at",)) -> bool: ...

# provenance maps finding key -> {"first_seen", "last_seen", "issue_number",
# "resolved_on"}.
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

`real_0117.json` is the one observed fixture rather than a reconstruction: genuine Grype 0.117.0 output, absolute paths scrubbed and nothing else altered. `build_fixtures.py` does not generate it, so regenerating the fixture set neither overwrites nor recreates it. It is the only thing that would catch a Grype schema change before a red workflow run does.

Tests are the specification for phase 2. If a test fails, the implementation is wrong until an argument is made here that the test is.

## Packaging notes for phase 6

Collected from installing the tool into the testbed by hand. Every item is
something an adopter would otherwise have to work out themselves.

**Issue bodies reason about the package, not just the finding.** `render_issue` takes the whole current scan, not the subset being filed. urllib3 in the testbed had four findings above the threshold with fix versions 2.6.3, 2.6.0, 2.6.0 and 2.7.0: each issue answered "what do I install" differently and only one was right, so a reader closing one of them by upgrading to 2.6.3 still had three open. Every issue for a package now names the highest fix across all of its findings, including ones below the threshold — the reader installs one version, and it has to satisfy everything known about that package, not just what happened to cross the threshold. One issue per finding stays right, because they resolve independently. Where the recommended fix crosses a major version, the body says so: 1.26.17 to 2.7.0 is a breaking change presented as a version bump.

**A schedule event carries no inputs, and the default must favour acting.** `inputs.dry_run` is empty under cron, so any shell test of the form `[ "$DRY_RUN" = "false" ]` sends every scheduled run down the dry-run branch: it files nothing, commits nothing, and the log looks perfectly healthy. Resolve the input once at workflow level as `${{ inputs.dry_run || 'false' }}` and have everything — the shell branch and the commit gate — read that single value, so the two cannot drift apart. Caution belongs on the manual button; the schedule is the part that has to work.

**Scheduled workflows are disabled after 60 days without repository activity.** For a watchdog this is backwards: the repository nobody has touched in two months is precisely the one still shipping a dependency someone disclosed a CVE against last week, and it is the one that goes quiet. The tool partly inoculates itself, because a real finding produces a state commit and a commit resets the clock — but only while it keeps finding things. A repository that is clean for sixty days stops being watched exactly when it has been quiet longest. Adopters need this in the README, not buried here.

**The packaged action carries a self-check.** Done: `src/selfcheck.py` parses `packaging/real_0117.json` at startup and asserts 22 findings, failing with the Grype version named. A misparse looks exactly like "no vulnerabilities found", so this is the only thing standing between a schema change and a silently clean scan on an adopter's runner. The sample is shipped under `packaging/` rather than `tests/`, because the action must work from a checkout that has no test directory — which means the file exists twice, and phase 6 part 2 should point the fixture tests at the packaged copy.

**The action must not call `actions/setup-python`.** Doing so changes the interpreter every later step in the adopter's job sees, which is not this action's business. `src/` is standard library only; the self-check reports clearly when the runner's Python is older than 3.11 and tells the adopter to add `setup-python` themselves.

**`PYTHONPATH` is what makes the package work.** The action runs `python3 -m src.run` with the adopter's repository as the working directory, so `src` must resolve from `github.action_path` rather than from their tree. Everything else — the scan target, the state path — stays relative to their repository, which is the whole point.

**The test steps do not ship.** `Install test dependencies` and `Run the test
suite` reference `requirements-dev.txt` and `tests/`, neither of which belongs
in a scan target. Left in, they fail the run before the scan. Removing them is
the first thing every adopter would hit.

**`.syft.yaml` must not carry our paths.** Done: the action ships `packaging/syft.yaml`, which excludes only `.git`, `node_modules` and virtualenvs. This repository's own `.syft.yaml` still excludes `./scratch/**`, which is correct here and is no longer inherited by anyone, because a `.syft.yaml` in the scanned repository wins and the action's default is used only when there is none.

**Adopters need `.gitattributes` with `* text=auto eol=lf`.** `save_state`
forces LF, so a runner is fine, but without the attribute a Windows
contributor introduces CRLF churn in the committed state file.

**`report.py` is empty and shipping.** Either fill it in phase 5 or exclude it
from the package; dead weight in a security tool invites the question of what
else is not doing anything.

**A dry run must not write state.** Fixed in the orchestrator rather than the
workflow: `--dry-run-issues` declines the state write, because recording a
baseline during a preview permanently consumes the one bootstrap a repository
gets and makes the first real run file nothing. The workflow also skips the
commit step outright when `dry_run` is true, since the commit is the
irreversible half and should be unreachable from a preview by any route.

## Conventions

Python 3.11+, standard library only. Every module, `issues.py` included. Type hints throughout. `pytest` for tests, `ruff` for lint.

The earlier permission for `requests` in `issues.py` is withdrawn. This tool's premise is that dependencies are liability: adding one to file issues means the SBOM grows, the scanner starts reporting CVEs against itself, and every adopter inherits our transitive tree. For four calls against one API that is not a trade worth making, and zero runtime dependencies is the stronger claim for a supply-chain security tool to be able to make.

`issues.py` therefore uses `urllib.request`. It raises `HTTPError` for 4xx and 5xx rather than returning a response, so every call is normalised into one shape before the retry logic reads it — the rate-limit headers arrive on the exception, and that is the part most likely to go wrong.

Timestamps are UTC, ISO 8601, with a trailing `Z`. Dates in `first_seen` and `last_seen` are `YYYY-MM-DD`.

Workflow permissions are `contents: write` and `issues: write`. Nothing else.

Logic that decides what gets written to the repository lives in Python, not in workflow shell. `set -e` does not fire on a failing condition inside an `if`, so `[ "" -gt 0 ]` errored and fell through to the wrong branch silently, committing a baseline as "no change (scan of )". The workflow calls `run.py` and checks an exit code; it does not compute. Anything it cannot express as "run this, then branch on the result" belongs in a module with a test.

Four Actions facts that affect design.

Scheduled workflows are disabled automatically after 60 days without repository activity, so the README must warn about it.

Commits pushed with the default `GITHUB_TOKEN` do not trigger other workflows, which is what prevents the commit-back step from re-triggering the scan.

`actions/checkout` v6 no longer persists a credential in `.git/config`. Confirmed from a run: the commit-back step logged "no ambient credential in .git/config - the explicit token is doing the work". The push therefore passes `GITHUB_TOKEN` explicitly through the remote URL. **README item for phase 6:** anyone copying an older commit-back pattern, which relies on the ambient credential, gets a failure on the very last step, after the scan has already run and the state has already been computed. That is the most expensive place to fail and the least obvious to diagnose.

`workflow_dispatch` pins `github.sha` at dispatch time, so `actions/checkout` can hand a job a tree older than the branch tip. Two runs dispatched a minute apart both checked out the same pre-baseline commit and both bootstrapped, even though `concurrency` correctly serialised them: the second job started three seconds after the first finished and still read a stale tree. Serialising runs does not make them read current state. The workflow therefore re-reads the state file from the ref before scanning, and the commit-back recomputes rather than rebases if a push is rejected: the state file is derived output, not text to merge.
