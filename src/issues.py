"""Issue rendering. No GitHub API yet: this module only decides what an issue
would say, and prints it.

`requests` is permitted here by the conventions in CLAUDE.md, but nothing in
this file needs it while there is no API call to make. Rendering is pure: a
Finding in, text out, no clock and no network. That is what makes the output
reviewable before anything reaches anyone's tracker.
"""
from __future__ import annotations

from .model import Finding

__all__ = ["advisory_url", "dry_run", "render_issue"]

LABEL = "sbom-watchdog"


def advisory_url(identifier: str) -> str | None:
    """Where a human goes to read about this identifier.

    Only the two forms this tool actually produces are mapped. Anything else
    returns None rather than a guessed URL: a wrong link in a security issue
    costs more than a missing one.
    """
    if identifier.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{identifier}"
    if identifier.startswith("GHSA-"):
        return f"https://github.com/advisories/{identifier}"
    return None


def _join(values: tuple[str, ...]) -> str:
    return ", ".join(values) if values else "none"


def render_issue(finding: Finding) -> tuple[str, str, list[str]]:
    """Render a finding as (title, body, labels).

    The finding key is in the title because that is the deduplication net: one
    `GET /search/issues` for the key before creating tells us whether a
    previous run already filed this, even if the state file was never
    committed because the job died after creating issues.
    """
    title = (f"{finding.severity}: {finding.id} in {finding.package_name} "
             f"[{finding.key}]")

    versions = _join(finding.versions)
    fixed_in = _join(finding.fixed_in)

    if finding.fixed_in:
        remedy = f"Upgrade `{finding.package_name}` to {fixed_in}."
    elif finding.fix_state == "wont-fix":
        remedy = "The maintainers have marked this as wont-fix. No upgrade will resolve it."
    else:
        remedy = "No fixed version has been published yet."

    links = []
    for identifier in sorted(finding.aliases):
        url = advisory_url(identifier)
        if url:
            links.append(f"- [{identifier}]({url})")
    advisories = "\n".join(links) if links else "- none published"

    body = f"""`{finding.package_name}` {versions} is affected by {finding.id}.

| | |
| --- | --- |
| Severity | {finding.severity} |
| Package | `{finding.package_name}` ({finding.package_type}) |
| Affected version(s) | {versions} |
| Fixed in | {fixed_in} |
| Fix state | {finding.fix_state} |

{remedy}

**Advisories**

{advisories}

<!-- Do not edit the line below: it is how this tool recognises its own issues. -->
Finding key: `{finding.key}`

---
Filed by [sbom-watchdog](https://github.com/Johndenisnyagah/sbom-watchdog). This
issue was opened because the finding was not present in the previous scan, or
because it crossed the severity threshold since the last run. Closing it will
not suppress it; the finding stays in `.sbom-watchdog/findings.json` until the
dependency is no longer reported as vulnerable.
"""

    labels = [LABEL, f"severity:{finding.severity.lower()}"]
    return title, body, labels


def dry_run(findings: list[Finding]) -> str:
    """What would be posted, as text. Posts nothing."""
    if not findings:
        return "no issues would be filed"

    blocks = [f"{len(findings)} issue(s) would be filed. Nothing was posted.\n"]
    for index, finding in enumerate(findings, start=1):
        title, body, labels = render_issue(finding)
        blocks.append(
            f"{'=' * 72}\n"
            f"ISSUE {index} of {len(findings)}\n"
            f"{'=' * 72}\n"
            f"title:  {title}\n"
            f"labels: {', '.join(labels)}\n"
            f"{'-' * 72}\n"
            f"{body}"
        )
    return "\n".join(blocks)
