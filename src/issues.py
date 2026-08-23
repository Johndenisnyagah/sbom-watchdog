"""Issue rendering, and the GitHub calls that file them.

Rendering is pure and imports nothing beyond the standard library: a Finding
in, text out. That is what lets the output be reviewed before it reaches
anyone's tracker, and what keeps the dry-run path working on a machine with no
`requests` installed.

`requests` is permitted here by CLAUDE.md, but it is imported lazily inside the
API helpers rather than at module scope, so importing this module for rendering
never requires it.
"""
from __future__ import annotations

import time
from urllib.parse import quote

from .model import Finding

__all__ = [
    "advisory_url",
    "create_issue",
    "dry_run",
    "ensure_labels",
    "find_existing_issue",
    "fix_line",
    "fixed_in_phrase",
    "render_issue",
]

LABEL = "sbom-watchdog"
API_ROOT = "https://api.github.com"
KEY_MARKER = "Finding key:"

# Label colours by severity, so a tracker full of these is skimmable.
_LABEL_COLOURS = {
    "sbom-watchdog": "0e8a16",
    "severity:critical": "b60205",
    "severity:high": "d93f0b",
    "severity:medium": "fbca04",
    "severity:low": "c2e0c6",
    "severity:negligible": "d4c5f9",
    "severity:unknown": "cccccc",
}


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


def fixed_in_phrase(versions: tuple[str, ...]) -> str:
    """Describe the fixed versions without choosing between them.

    Two fixed versions usually means two separate release lines, and this tool
    has no idea which one the reader can adopt. Picking one would mean
    comparing versions, and the plain string sort in use would eventually pick
    wrong. Frame the choice instead of making it.
    """
    if not versions:
        return "none published"
    if len(versions) == 1:
        return versions[0]
    joined = " or ".join(versions)
    return (joined + " (separate release lines — pick the one matching "
            "your major version)")


def fix_line(finding: Finding) -> str:
    """The line telling the reader what to do about it."""
    if finding.fixed_in:
        return "**Fixed in:** " + fixed_in_phrase(finding.fixed_in)
    if finding.fix_state == "wont-fix":
        return ("**Fixed in:** nothing. The maintainers have marked this "
                "wont-fix, so no upgrade will resolve it.")
    return "**Fixed in:** no fixed version has been published yet."


def render_issue(finding: Finding) -> tuple[str, str, list[str]]:
    """Render a finding as (title, body, labels).

    The finding key is in the title because that is the deduplication net: one
    `GET /search/issues` for the key before creating tells us whether a
    previous run already filed this, even if the state file was never committed
    because the job died after creating issues.
    """
    title = (f"{finding.severity}: {finding.id} in {finding.package_name} "
             f"[{finding.key}]")

    versions = ", ".join(finding.versions) if finding.versions else "unknown"

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
| Fix state | {finding.fix_state} |

{fix_line(finding)}

**Advisories**

{advisories}

<!-- Do not edit the line below: it is how this tool recognises its own issues. -->
{KEY_MARKER} `{finding.key}`

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


# --- the GitHub API -------------------------------------------------------

_MAX_ATTEMPTS = 3
_MAX_SLEEP_SECONDS = 120


def _requests():
    try:
        import requests
    except ImportError as exc:
        raise RuntimeError(
            "filing issues needs the `requests` package; rendering and "
            "--dry-run-issues do not"
        ) from exc
    return requests


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": LABEL,
    }


def _pause_for_rate_limit(response, sleep=time.sleep) -> bool:
    """Wait if GitHub has asked us to. True when the call should be retried.

    Two mechanisms, both real: `Retry-After` on a secondary limit, and
    `X-RateLimit-Remaining: 0` with a reset timestamp on the primary one. The
    search endpoint used for deduplication has its own much smaller budget, so
    a repo with many new findings meets this rather than never seeing it.
    """
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            wait = min(int(retry_after), _MAX_SLEEP_SECONDS)
        except ValueError:
            wait = 5
        print(f"    rate limited; waiting {wait}s (Retry-After)")
        sleep(wait)
        return True

    remaining = response.headers.get("X-RateLimit-Remaining")
    reset = response.headers.get("X-RateLimit-Reset")
    if remaining is not None and reset is not None:
        try:
            if int(remaining) <= 0:
                wait = max(0, int(reset) - int(time.time())) + 1
                wait = min(wait, _MAX_SLEEP_SECONDS)
                print(f"    rate limit exhausted; waiting {wait}s for reset")
                sleep(wait)
                return True
        except ValueError:
            return False
    return False


def _request(method: str, url: str, token: str, *, expect: tuple[int, ...],
             params: dict | None = None, payload: dict | None = None):
    requests = _requests()
    last = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        response = requests.request(
            method, url, headers=_headers(token), params=params, json=payload,
            timeout=30,
        )
        last = response
        if response.status_code in expect:
            return response
        if response.status_code in (403, 429) and _pause_for_rate_limit(response):
            continue
        if response.status_code >= 500 and attempt < _MAX_ATTEMPTS:
            sleep_for = min(2 ** attempt, _MAX_SLEEP_SECONDS)
            print(f"    {response.status_code} from GitHub; retrying in {sleep_for}s")
            time.sleep(sleep_for)
            continue
        break

    raise RuntimeError(
        f"{method} {url} returned {last.status_code}: {last.text[:300]}"
    )


def find_existing_issue(repo: str, key: str, token: str) -> int | None:
    """The number of an existing issue for this finding key, or None.

    This is the safety net for the ordering problem in CLAUDE.md: if a previous
    run created issues and then failed before committing state, the numbers are
    lost from state but the issues exist. Searching by key finds them.

    Caveat worth knowing: GitHub's search index is eventually consistent, so an
    issue created seconds ago may not come back. This narrows the window for
    duplicates; it does not close it.
    """
    response = _request(
        "GET", f"{API_ROOT}/search/issues", token, expect=(200,),
        params={"q": f'repo:{repo} is:issue in:title "{key}"', "per_page": 20},
    )
    for item in response.json().get("items", []):
        if key in (item.get("title") or ""):
            return item.get("number")
    return None


def ensure_labels(repo: str, labels: list[str], token: str) -> None:
    """Create any label that does not exist yet.

    Posting an issue with a label the repository does not have does not fail;
    the label is silently dropped. Since severity is how these get triaged,
    losing it quietly is worse than an error.
    """
    for label in labels:
        response = _request(
            "GET", f"{API_ROOT}/repos/{repo}/labels/{quote(label)}", token,
            expect=(200, 404),
        )
        if response.status_code == 200:
            continue
        _request(
            "POST", f"{API_ROOT}/repos/{repo}/labels", token, expect=(201,),
            payload={
                "name": label,
                "color": _LABEL_COLOURS.get(label, "ededed"),
                "description": "Managed by sbom-watchdog",
            },
        )
        print(f"    created label {label}")


def create_issue(repo: str, title: str, body: str, labels: list[str],
                 token: str) -> int:
    """File the issue and return its number."""
    response = _request(
        "POST", f"{API_ROOT}/repos/{repo}/issues", token, expect=(201,),
        payload={"title": title, "body": body, "labels": labels},
    )
    return int(response.json()["number"])
