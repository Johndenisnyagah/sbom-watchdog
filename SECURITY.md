# Security policy

## Supported versions

Only the latest `v1.x` release receives fixes. The `v1` tag moves forward to
each compatible release, so pinning `@v1` picks fixes up automatically.
Version tags such as `v1.6` never move; if you pin one, upgrade to the latest
release to get a fix.

## Reporting a vulnerability

Please do **not** open a public issue. Report privately through GitHub:
[Report a vulnerability](https://github.com/Johndenisnyagah/sbom-watchdog/security/advisories/new)
(the **Security** tab, then **Report a vulnerability**).

Include what you found, how to reproduce it, and the version or commit you
tested. This is a one-person project, maintained alongside study, so reports
are handled on a best-effort basis: I aim to acknowledge a report within 14
days and will keep you updated until it is fixed or closed. With your
agreement, you will be credited in the advisory.

## What is in scope

- The action itself: `action.yml` and the code in `src/`.
- How it handles the `GITHUB_TOKEN` it is given.
- Anything that makes it miss a vulnerability it should report, record a
  finding as already filed when it was not, or write something misleading into
  an issue, the state file or `SECURITY-INVENTORY.md`.
- The example workflow in `.github/workflows/example.yml`, which adopters copy.

## What is not

- Vulnerabilities in Syft or Grype themselves. Report those to
  [Anchore](https://github.com/anchore), which maintains both.
- Vulnerabilities the action reports in *your* dependencies. Those are the
  tool working as intended; fix them in your project.
- The [watchdog-testbed](https://github.com/Johndenisnyagah/watchdog-testbed)
  repository, which is deliberately vulnerable and runs no code.
