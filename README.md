# sbom-watchdog

[![ci](https://github.com/Johndenisnyagah/sbom-watchdog/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Johndenisnyagah/sbom-watchdog/actions/workflows/ci.yml)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![live demo: daily scan](https://github.com/Johndenisnyagah/watchdog-testbed/actions/workflows/watchdog.yml/badge.svg)](https://github.com/Johndenisnyagah/watchdog-testbed/actions/workflows/watchdog.yml)

A GitHub Action that generates a software bill of materials for your repository
every night, scans it for known vulnerabilities, and opens an issue only for
findings that were not there yesterday.

The "only" is the whole point. Running a scanner on a schedule is easy; the
hard part is not producing two hundred issues on the first run and then a
duplicate set every night after. This one keeps a committed record of what it
has already told you about, and stays quiet about the rest.

**Live demo:** [watchdog-testbed](https://github.com/Johndenisnyagah/watchdog-testbed),
a deliberately vulnerable repository this action has scanned every day since
August 2026 ·
[issues it filed](https://github.com/Johndenisnyagah/watchdog-testbed/issues?q=is%3Aissue+author%3Aapp%2Fgithub-actions) ·
[daily runs](https://github.com/Johndenisnyagah/watchdog-testbed/actions/workflows/watchdog.yml) ·
[security inventory](https://github.com/Johndenisnyagah/watchdog-testbed/blob/main/SECURITY-INVENTORY.md) ·
[SBOM history](https://github.com/Johndenisnyagah/watchdog-testbed/tree/main/sboms).
Its README explains which issues were seeded on purpose and which came from
vulnerabilities published after the scanning started — issues
[#10](https://github.com/Johndenisnyagah/watchdog-testbed/issues/10) and
[#11](https://github.com/Johndenisnyagah/watchdog-testbed/issues/11), filed on
1 October 2026 for a dependency that had been clean the day before.

## What you get

This is a real issue it filed on the testbed, while it was pinned to `urllib3 1.26.17`:

> **High: CVE-2026-21441 in urllib3 [CVE-2026-21441::python::urllib3]**
> `sbom-watchdog` `severity:high`
>
> `urllib3` 1.26.17 is affected by CVE-2026-21441.
>
> | | |
> | --- | --- |
> | Severity | High |
> | Package | `urllib3` (python) |
> | Affected version(s) | 1.26.17 |
> | Fix state | fixed |
>
> **Fixed in:** 2.6.3
>
> This package has 7 findings in this scan; the highest fix version among them
> is 2.7.0. Upgrading to anything below that leaves the others open.
>
> This crosses a major version and may require code changes.
>
> **Advisories**
>
> - [CVE-2026-21441](https://nvd.nist.gov/vuln/detail/CVE-2026-21441)
> - [GHSA-38jv-5279-wg99](https://github.com/advisories/GHSA-38jv-5279-wg99)

The two paragraphs after the fix version are the reason this exists rather than
a shell script around Grype. That scan found seven urllib3 vulnerabilities,
four of them above the threshold, with fix versions 2.6.3, 2.6.0, 2.6.0 and
2.7.0. An issue that only knows about its own CVE tells you to upgrade to
2.6.3 — and you would still have three open findings and no idea why. Every
issue for a package names the highest fix across all of that package's
findings, and says so when taking it crosses a major version.

## Installing it

Add this as `.github/workflows/sbom-watchdog.yml`. It is the file this
repository ships as `.github/workflows/example.yml`, so it is kept working
rather than kept illustrative.

```yaml
name: sbom-watchdog

on:
  workflow_dispatch:
    inputs:
      dry-run:
        type: boolean
        default: true
  schedule:
    - cron: '17 3 * * *'

permissions:
  contents: write   # to commit the state file
  issues: write     # to file and close issues

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: false

env:
  DRY_RUN: ${{ inputs.dry-run || 'false' }}

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0

      - id: watchdog
        uses: Johndenisnyagah/sbom-watchdog@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          dry-run: ${{ env.DRY_RUN }}

      - name: Commit the state file
        if: env.DRY_RUN != 'true' && steps.watchdog.outputs.should-commit == 'true'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          MESSAGE: ${{ steps.watchdog.outputs.commit-message }}
        run: |
          set -euo pipefail
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git remote set-url origin \
            "https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
          git add .sbom-watchdog/findings.json
          # Only present if you turned the evidence files on. `git add` on a
          # path that does not exist is an error, so ask first.
          if [ -d sboms ]; then git add sboms; fi
          if [ -f SECURITY-INVENTORY.md ]; then git add SECURITY-INVENTORY.md; fi
          if git diff --cached --quiet; then exit 0; fi
          git commit -m "${MESSAGE}" -m "Run ${GITHUB_RUN_ID}"
          git pull --rebase origin "${GITHUB_REF_NAME}"
          git push origin "HEAD:${GITHUB_REF_NAME}"
```

Run it once from the Actions tab with the dry-run box ticked before you let it
loose. It will print the issues it would file and write nothing.

Add a `.gitattributes` containing `* text=auto eol=lf` at the same time if you
do not have one. The state file is written with LF endings and a contributor on
Windows would otherwise commit it back with CRLF; there is a longer note under
[Operating it](#operating-it).

`actions/checkout@v7` is written as a tag above for readability. `example.yml`
pins it by commit SHA, which is what you want in a workflow that has write
access to your repository: a tag is somebody else's decision to run new code
there.

`sbom-watchdog@v1` tracks the latest `v1.x`, which is the usual convention for
a major tag and means you pick up fixes without editing anything. If you would
rather decide when the code under you changes, pin an immutable tag — `@v1.1`
— or a commit SHA. `v1` only ever moves forward to a released, backward-
compatible `v1.x`; a breaking change would be `v2` and would leave `v1` where
it is.

Gate the commit on `should-commit` rather than `state-changed`. They differ in one case, and it is the case that matters: a repository with no findings never moves its vulnerability state, so `state-changed` stays `false` forever and its audit trail would never be committed at all. `state-changed` is still there, and is the right signal if you want to act only when a finding actually appeared or went away.

The commit step is yours rather than the action's, deliberately. An action that
pushes to your repository from six lines you pasted is the wrong kind of
surprise, and you should be able to see exactly what it writes and when.

`example.yml` in this repository also carries a step that re-reads the state
file from the branch tip before scanning. You want that if you might ever run
two scans close together — a dispatched run pins its commit when it is created,
so it can otherwise check out a tree older than the branch tip and decide it is
starting from scratch.

### Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `github-token` | none, required | Pass `${{ secrets.GITHUB_TOKEN }}`. Used to search, file and close issues. The action will not reach for a token you did not hand it. |
| `severity-threshold` | `High` | Severity at or above which a new finding earns an issue. Everything found is recorded regardless; this only decides what gets filed. |
| `state-path` | `.sbom-watchdog/findings.json` | Where the committed record lives. |
| `dry-run` | `false` | When exactly `true`, print what would be filed and write nothing. Any other value files for real. |
| `write-sbom-history` | `false` | Write the inventory to `sboms/YYYY-MM-DD.json` as an audit trail. Off by default. |
| `write-inventory` | `false` | Write `SECURITY-INVENTORY.md` at the repository root. Off by default. |
| `syft-version` | `v1.51.0` | Pinned. A scanner that changes its output format under you should do it on a version bump you chose. |
| `grype-version` | `v0.117.0` | Pinned, same reason. |

### Outputs

| Output | Meaning |
| --- | --- |
| `new` | Findings not present in the previous scan. |
| `resolved` | Findings no longer reported. |
| `unchanged` | Findings present and unchanged. |
| `bootstrap` | `true` when there was no previous state file. |
| `should-commit` | `true` when this run produced something to commit. **Gate your commit step on this.** |
| `state-changed` | `true` when the vulnerability state itself moved. Narrower than `should-commit`, and useful if you want to act only when a finding appeared or went away. |
| `sbom-path` | Path of the dated SBOM written this run, empty when that output is off. |
| `inventory-path` | Path of the inventory written this run, empty when that output is off. |
| `commit-message` | The message to commit under. Use it rather than composing one from the counts. |

## How it works

Syft builds a CycloneDX inventory of the repository. Grype scans that inventory
against its vulnerability database, which is downloaded fresh on every run
rather than cached — caching it would trade a stale-CVE risk against about
sixty seconds of wall time, in a tool whose entire premise is catching
newly-disclosed vulnerabilities.

The result is then compared against `.sbom-watchdog/findings.json`, committed in
your repository. Anything not in that file is new, and new findings at or above
the threshold get an issue. Everything else is recorded and stays silent.

If the state file is absent, the run records a baseline and files nothing. That
is not a special case a caller has to remember: the diff function is told there
was no previous state and returns everything as already-known. Without it, the
first run against a real project would open several hundred issues at once.

### The state file

```json
{
  "schema_version": 2,
  "generated_at": "2026-08-24T03:17:00Z",
  "tooling": { "syft": "1.51.0", "grype": "0.117.0", "grype_db_built": "..." },
  "findings": {
    "CVE-2020-14343::python::pyyaml": {
      "id": "CVE-2020-14343",
      "aliases": ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"],
      "package": { "name": "pyyaml", "type": "python", "versions": ["5.3.1"] },
      "severity": "Critical",
      "fixed_in": ["5.4"],
      "fix_state": "fixed",
      "first_seen": "2026-08-01",
      "last_seen": "2026-08-24",
      "issue_number": 42,
      "resolved_on": null
    }
  }
}
```

It is committed rather than cached because a cache eviction would silently
re-announce everything you have already seen, and because the file doubles as
an audit trail you can read in a diff.

A resolved finding is not deleted. It stays with a `resolved_on` date, because
the record is the only link between a finding and the issue it was filed under:
delete it and nothing can close that issue, or reference it if the
vulnerability comes back. The file therefore grows over time, and nothing
prunes it. That is deliberate — a fixed vulnerability is a fact worth keeping —
but it does mean the file is append-heavy by design.

### Finding identity

A finding is keyed on `{vulnerability_id}::{package_type}::{package_name}`.
Three decisions are buried in that:

The version is deliberately excluded. Upgrading a package from 1.2.0 to 1.2.1
while it remains vulnerable to the same CVE updates the existing record rather
than filing a second issue about the same problem.

The package type is included, because `requests` on PyPI and `requests` on npm
are unrelated packages that happen to share a name.

The vulnerability ID is normalised. Grype frequently reports a GHSA identifier
and carries the CVE alongside it, and which one is primary can change when the
advisory database updates. If the raw identifier were the key, the same flaw
would change identity between runs and get filed twice. The CVE wins where one
exists, every identifier ever seen is kept as an alias, and a finding whose key
changes because a CVE was assigned overnight is matched back to its old record
by alias overlap.

## The evidence files

Two files, both off by default, because an action that starts creating files in
your repository after you pinned a version is a bad surprise. Turn them on with
`write-inventory: 'true'` and `write-sbom-history: 'true'`, and commit them in
the same step that commits the state file.

`SECURITY-INVENTORY.md` is written for whoever asks you what is in your
software and what you know about its vulnerabilities — a procurement reviewer,
an auditor, a customer's security questionnaire. It is a record of monitoring,
not a certificate: it says what the scanner reported and when, not that the
software is safe. It deliberately contains no scanner vocabulary. This is the real
thing, from a repository with 34 open findings:

> # Security inventory
>
> This file is generated automatically and should not be edited by hand. It lists every known security vulnerability in the software this project depends on, and what can be done about each one.
>
> **Last checked:** 24 August 2026
> **Vulnerabilities currently open:** 34
> **Vulnerabilities resolved since tracking began:** 0
>
> ## What is open now
>
> | Severity | Count |
> | --- | ---: |
> | Critical | 2 |
> | High | 15 |
> | Medium | 11 |
> | Low | 6 |
> | **Total** | **34** |
>
> Severity is the rating published by the public vulnerability databases, not an assessment of how this project uses the software. A high severity vulnerability in a component that is never reached may present little practical risk, and judging that is a human decision this tool does not make.
>
> ### Can be fixed by updating (31)
>
> 31 of the 34 open vulnerabilities have a newer version of the affected software available that resolves them.
>
> ### No fix available (3)
>
> 3 of the 34 open vulnerabilities have no published fix. Updating will not resolve these: the software has to be replaced with a maintained alternative, or removed, or the risk accepted and recorded. This is a different decision from the ones above, and usually a slower one.
>
> | Package | Version in use | Severity | Advisory | Fixed in |
> | --- | --- | --- | --- | --- |
> | pycrypto | 2.6.1 | Critical | CVE-2013-7459 | none published |
> | pycrypto | 2.6.1 | High | CVE-2018-6594 | none published |
> | paramiko | 2.4.1 | Low | CVE-2026-44405 | none published |
>
> *(a full table of all open vulnerabilities follows)*
>
> ## What has been resolved
>
> 7 vulnerabilities were reported previously and are no longer present. They are kept here because a record of having fixed something is part of the trail, not clutter to be tidied away.
>
> | Package | Severity | Advisory | Resolved on |
> | --- | --- | --- | --- |
> | urllib3 | High | CVE-2026-21441 | 24 August 2026 |
>
> ## How this was checked
>
> | | |
> | --- | --- |
> | Date of this check | 24 August 2026 |
> | Software inventory produced by | Syft 1.51.0 |
> | Vulnerabilities identified by | Grype 0.117.0 |
> | Vulnerability data published on | 24 August 2026 |

The "no fix available" split is the part a reviewer will ask about. A package
awaiting an upgrade is scheduled work; a package with no published fix is a
decision about whether to keep depending on it at all, and those are different
answers to give someone.

The resolved section is why this is more than a snapshot. A finding that stops
being reported is kept with the date it went away, rather than deleted, so the
file shows what was fixed and when.

### The SBOM history

`sboms/YYYY-MM-DD.json` is the CycloneDX inventory, one file per day the scan
ran. It is written every day and never skipped for being unchanged, which is a
deliberate choice with a real cost: most days it is near-identical to the day
before.

The reason is that a missing file has to mean one thing. If it could mean
either "no scan ran" or "nothing had changed", then the trail cannot distinguish
a stable project from an abandoned one — and since GitHub disables scheduled
workflows after 60 days of inactivity, going quiet is a realistic way for this
to end. A reviewer asking "show me you checked your dependencies on 14 March"
is answered by `sboms/2026-03-14.json`, and answering instead with a
de-duplication rule they have to take on trust is a worse story. What the file
proves is that a scan ran that day and what the repository declared; it does
not prove what you shipped.

Two files from consecutive days differ only in the document's serial number and
timestamp when nothing changed, which is itself the evidence that nothing
changed.

The first scan of a day writes that day's file; later scans the same day leave
it alone. Syft stamps a fresh serial number on every run, so rewriting would
produce a commit whose entire content is a changed identifier — and it would
quietly change what the file means, from the day's record to the last scan of
that day, with nothing saying which. The run history already shows that a later
scan happened.

`SECURITY-INVENTORY.md` is the opposite, because it is not a dated snapshot: it
describes the current state, so the newest scan is always the right content and
it is rewritten whenever it would differ.

### What the SBOM is and is not

It is a *source* SBOM, in CISA's terms: Syft reads the manifests and lockfiles
in your repository, not a built or installed artefact. On the testbed it lists
34 components, each with a name, version and package URL. Licences are present
for the 26 npm packages only; there are no file hashes, no supplier or creator
details, and Python packages appear without their own dependencies, because a
`requirements.txt` does not record them. GitHub Actions used by the workflow are
listed too, although they never ship.

That is useful for knowing what you depend on and for matching it against
vulnerability databases. It is not the SBOM a manufacturer would hand over with
a product: it meets only part of what BSI TR-03183-2 (version 2.1.0) asks for,
which includes hashes, creator details and complete dependency relationships.

## Operating it

**Scheduled workflows are disabled after 60 days without repository activity.**
This is GitHub's behaviour, not this tool's, and for a watchdog it is backwards:
the repository nobody has touched in two months is precisely the one still
shipping a dependency someone disclosed a CVE against last week. A real finding
produces a state commit, and a commit resets the clock, so this partly
inoculates itself — but only while it keeps finding things. A repository that
stays clean for sixty days stops being watched exactly when it has been quiet
longest. Check the Actions tab occasionally, or give yourself a calendar
reminder.

**A scheduled run passes no inputs.** `inputs.dry-run` is empty under cron, not
`false`. The workflow above resolves it once with `${{ inputs.dry-run || 'false' }}`
so that an absent input files for real and only an explicit tick previews. If
you invert that — defaulting to the dry run when the value is missing — every
scheduled run quietly files nothing while the logs look perfectly healthy.

**Add a `.gitattributes` with `* text=auto eol=lf`.** The state file is written
with LF endings. Without the attribute, a contributor on Windows can commit it
back with CRLF and every line of it shows as changed.

**The action self-checks before it scans.** It parses a captured Grype document
bundled with the action and asserts it still yields 22 findings. If that fails,
the run stops and names the Grype version. Take it seriously: it means the
scanner's output format has moved and the parser is no longer reading it
correctly. A misparse produces an empty finding list, which is indistinguishable
from a clean scan — that check is the only thing standing between a schema
change and a report of no vulnerabilities that you would have believed.

**Closing an issue is safe.** The issue number is kept in the state file, so
nothing refiles it. Closing does not mark the finding resolved; only the
dependency no longer being reported does that.

## Why not Dependabot alerts?

Use them as well; they are on for the testbed too. Dependabot alerts are free on
every repository, cost no CI minutes, are maintained by GitHub, flag malicious
packages, and can open a pull request that fixes the problem. sbom-watchdog
fixes nothing.

It answers a different question: what did we know, and when? Dependabot alerts
live in the Security tab, visible to administrators, people with write access
and anyone granted access explicitly. sbom-watchdog puts findings in the issue
tracker, where anyone who can read issues can follow them, and in git: a
committed findings record, a dated SBOM per day and an inventory written for
people who are not developers, all readable in a diff and kept with the
repository. On a public repository that also means the issues are public, which
is a choice to make deliberately.

It matches against Grype's database, which includes NVD records that Dependabot
does not alert on until GitHub has reviewed the advisory, so the two will
sometimes disagree. Scanner actions such as `anchore/scan-action` run Grype too,
but fail a build or upload results rather than keeping a record between runs,
so every run reports everything again.

The cost is a daily job, a second set of notifications, and no fixes.

## The Cyber Resilience Act

The EU Cyber Resilience Act (Regulation (EU) 2024/2847) places obligations on
manufacturers of products with digital elements. sbom-watchdog does not make a
product compliant. It helps produce evidence for part of the vulnerability
handling those manufacturers have to do.

| Obligation | What this action does |
| --- | --- |
| Annex I Part II (1): identify and document components and vulnerabilities, including an SBOM | Supports it: a daily CycloneDX SBOM and vulnerability scan |
| Annex I Part II (2), (3): remediate without delay; test regularly | Partly: records when each finding appeared and was resolved. Fixing and testing are yours. |
| Art. 13(5), 13(8): due diligence on third-party components; handle vulnerabilities over the support period | Helps produce evidence: the committed findings record and the dated SBOMs |
| Art. 14: report actively exploited vulnerabilities and severe incidents to ENISA (24 hours for an early warning) | Not covered. A scanner match does not mean a vulnerability is actively exploited, and nothing is reported anywhere. |
| Annex I Part II (4), (5), (7), (8): public disclosure, a disclosure policy, secure update distribution, free security updates | Not covered |
| Art. 13(13): keep technical documentation for at least 10 years | Not covered. A git repository is not a retention system. |

The SBOM it produces is a source SBOM with known gaps (see
[What the SBOM is and is not](#what-the-sbom-is-and-is-not)). The Act does not
require SBOMs to be published; committing them to a public repository is your
choice. This table paraphrases the regulation and is not legal advice.

## Scope

One repository, scanned as a whole, in whatever ecosystems Syft detects in it.
Two have been run in anger: Python and npm, both on the public
[testbed](https://github.com/Johndenisnyagah/watchdog-testbed), and genuine
Grype output from each is part of the test suite. Other ecosystems Syft
supports should work, because nothing in the identity rules or the issue text
is specific to one, but they have not been exercised.

For npm, Syft reads `package-lock.json`; a `package.json` on its own produces
no components. Syft also leaves `devDependencies` out by default, so a
vulnerable build tool listed there is not reported unless your `.syft.yaml`
sets `javascript.include-dev-dependencies: true`.

Version comparison, used to name the highest fix and to warn about a major
version jump, covers the shapes PyPI and npm advisories carry rather than all
of PEP 440 or SemVer. One gap worth knowing for npm: an upgrade from `0.0.8`
to `0.2.4` is not flagged as breaking, though SemVer treats a `0.x` minor bump
as one.

Issues are filed for findings that are new, or that crossed the severity
threshold since the last run because a rating changed. A finding that changes in
some other way — a version bump that leaves it vulnerable, an alias gaining a
CVE — is recorded and stays silent, because a second notification about a
problem you already know about is how a tool gets muted.

Not in scope, and not planned: scanning multiple repositories from one place, a
web dashboard, container image scanning, reachability analysis to determine
whether a vulnerable function is actually called, blocking pull requests, and
notifications anywhere other than the issue tracker. Each of those is a
reasonable thing to want and a different project.

## Development

Standard library only, everywhere, including the GitHub API client. A tool whose
premise is that dependencies are liability should not add one to make four API
calls: the inventory would grow, this scanner would start reporting
vulnerabilities against itself, and every adopter would inherit the transitive
tree.

```
pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
```

`ci.yml` runs the same two commands on every pull request and every push to
`main`, on Python 3.11 (the oldest the action supports), 3.12 and 3.14. The
action itself runs under whatever `python3` the runner provides, so the range
matters more than any one version. It holds read
access only and needs no secrets. `validate-action.yml` additionally loads
`action.yml` through GitHub's own parser whenever something that ships in the
action changes.

### Updating Syft and Grype

Dependabot keeps the SHA-pinned actions and the development dependencies
current, weekly and a week behind each release. It cannot see the Syft and
Grype versions, which are plain strings in `action.yml`, and that is acceptable
here: a scanner release can change its output format or what it reports, so a
bump is a reviewed change rather than a background one. To bump either, change
the default in `action.yml`, re-capture `packaging/real_0117.json` if the Grype
output format moved, run the suite, and let `validate-action.yml` load the
result before tagging a release.

Three things the suite is built to guarantee rather than to accumulate. Rules
are verified by breaking them: where a decision matters, the rule was reverted
and a test confirmed to fail, so the coverage is demonstrated rather than
inferred from a green run. The GitHub API tests prove they are offline instead
of assuming it — `socket.socket` and `socket.create_connection` are poisoned for
every test in that module, and a test asserts the poison is live, so a code path
that reached the network would fail loudly rather than pass quietly on one
machine and break in CI. And `action.yml` is checked as a document GitHub has to
load, not as YAML: a parser reads `${{ ... }}` as ordinary text while GitHub
evaluates it, which is how a `v1` shipped that could not load at all. Those
tests assert the shape of the rules — expressions only in slots meant to hold
them, contexts only from the set a composite action can resolve — rather than
any one name that went wrong once.

`CLAUDE.md` is the working agreement: what each module may depend on, why the
decisions above were made, and what was tried and rejected. `tests/fixtures/`
holds a fixture per named failure mode, described in its own README.

## How this was built

Built with Claude Code as a pair programmer. I set the scope and the decisions
recorded in `CLAUDE.md`; Claude wrote much of the code and the tests, and many
commits carry its co-author trailer. I reviewed each change before merging it.
The test suite and the daily run on the
[testbed](https://github.com/Johndenisnyagah/watchdog-testbed) are the evidence
that it works, not the tool that helped write it.

Release-by-release changes are in [`CHANGELOG.md`](CHANGELOG.md).
