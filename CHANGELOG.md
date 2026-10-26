# Changelog

All notable changes to sbom-watchdog, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/2.0.0/) and versions follow
[semantic versioning](https://semver.org/). Version tags such as `v1.3` are
created once and never move; the floating `v1` tag moves forward only, to a
released and compatible `v1.x`.

## [Unreleased]

### Added
- README: a section on the Cyber Resilience Act that says what the tool
  supports, what it supports only in part, and what it does not cover
  (Article 14 reporting to ENISA among the latter), and what the SBOM is: a
  source SBOM that meets only part of BSI TR-03183-2.
- README: a live-demo link to the public
  [watchdog-testbed](https://github.com/Johndenisnyagah/watchdog-testbed), and
  a section on why this tool exists next to Dependabot alerts.
- README: a "How this was built" note on AI assistance.
- This changelog.

### Changed
- The README no longer calls the inventory and SBOM files "the compliance
  output". They are "the evidence files", because they record what was
  scanned and when, and do not make anyone compliant.
- npm is now documented as run in anger, backed by a real Grype capture
  (`tests/fixtures/grype/real_python_npm_0117.json`).

### Repository only (not part of the action)
- Continuous integration on every push and pull request: the suite on Python
  3.11, 3.12 and 3.14, plus `ruff check .`. Dependabot proposes action and
  dev-dependency updates weekly. The old dispatch-only `watchdog.yml` was
  removed.

## [1.6] - 2026-10-26

### Fixed
- Version ordering. `1.2.10-beta.1` used to rank below `1.2.9`, so an issue
  could name a version that does not fix the package. Pre-releases, a leading
  `v`, build metadata and PEP 440 epochs now order correctly.
- Finding an existing issue matched on part of a name, so an open issue for
  `lodash.set` could hide a new finding for `lodash`. It now matches the
  bracketed key at the end of the title exactly.

### Added
- When the recommended fix is a pre-release, the issue body says it needs
  `--pre` (pip) or an exact version (npm).
- When an inventory covers more than one ecosystem, every table gains an
  Ecosystem column. Single-ecosystem output is unchanged.

## [1.5] - 2026-08-24

### Fixed
- Only the first scan of a day writes that day's SBOM. Later scans the same day
  used to rewrite it with a new serial number and timestamp, producing commits
  whose only change was an identifier.

## [1.4] - 2026-08-24

### Fixed
- A repository with no findings could never commit its dated SBOM, because the
  commit was gated on the vulnerability state changing. It is now gated on
  there being something to write, so a missing daily file always means that no
  scan ran.

## [1.3] - 2026-08-24

### Added
- `SECURITY-INVENTORY.md`, a plain-language summary of current findings, and
  `sboms/YYYY-MM-DD.json`, one dated CycloneDX SBOM per scan. Both are opt-in
  through `write-inventory` and `write-sbom-history`.

## [1.2] - 2026-08-24

### Changed
- Issue bodies for packages with no published fix, or with a mix of fixable and
  unfixable findings, say so and name the decision (replace the dependency or
  accept the risk) instead of reading like a broken upgrade notice.

## [1.1] - 2026-08-24

### Changed
- A finding with no fix is described as a decision rather than an upgrade, and
  carries a `no-fix` label.

### Added
- Tests for the shape of `action.yml`, and a workflow that loads the action
  through GitHub's own parser on every change to it.

## [1.0] - 2026-08-24

First release: a composite action that installs pinned Syft and Grype,
generates a CycloneDX SBOM, scans it, compares the result with the committed
state in `.sbom-watchdog/findings.json`, and opens one issue per new finding at
or above a severity threshold (default High). A first run records a baseline
and files nothing. Findings that disappear are marked resolved and their issues
are closed with a comment.

### Notes
- The first release of `v1` pointed at a build whose `action.yml` GitHub
  refused to load (an expression inside an input description). It was fixed and
  `v1` was force-moved once. That is the only time a tag was moved to change
  what an existing pin resolved to, and it is the reason for the tag rules at
  the top of this file.
