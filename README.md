# sbom-watchdog

A GitHub Action that generates a software bill of materials for your repository
every night, scans it for known vulnerabilities, and opens an issue only for
findings that were not there yesterday.

The "only" is the whole point. Running a scanner on a schedule is easy; the
hard part is not producing two hundred issues on the first run and then a
duplicate set every night after. This one keeps a committed record of what it
has already told you about, and stays quiet about the rest.

## What you get

This is a real issue it filed, against a repository pinned to `urllib3 1.26.17`:

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
          # Only present if you turned the compliance outputs on. `git add` on a
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

## The compliance output

Two files, both off by default, because an action that starts creating files in
your repository after you pinned a version is a bad surprise. Turn them on with
`write-inventory: 'true'` and `write-sbom-history: 'true'`, and commit them in
the same step that commits the state file.

`SECURITY-INVENTORY.md` is written for whoever asks you what is in your
software — a procurement reviewer, an auditor, a customer's security
questionnaire. It deliberately contains no scanner vocabulary. This is the real
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

The "no fix available" split is the part an auditor cares about. A package
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
to end. An auditor asking "prove you generated an inventory on 14 March" is
answered by `sboms/2026-03-14.json`, and answering instead with a
de-duplication rule they have to take on trust is a worse story.

Two files from consecutive days differ only in the document's serial number and
timestamp when nothing changed, which is itself the evidence that nothing
changed.

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

## Scope

One repository, scanned as a whole. Whatever ecosystems Syft detects in it —
this has been exercised against Python, and the identity rules are written so
that a second ecosystem cannot collide with the first, but only Python has been
run in anger.

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
ruff check src/ tests/
```

`CLAUDE.md` is the working agreement: what each module may depend on, why the
decisions above were made, and what was tried and rejected. `tests/fixtures/`
holds a fixture per named failure mode, described in its own README.
