"""Issue rendering, and the GitHub calls that file them.

Standard library only, like everything else here. A tool whose premise is that
dependencies are liability should not acquire one to make four API calls: the
SBOM would grow, this scanner would start reporting CVEs against itself, and
every adopter would inherit the transitive tree. Zero runtime dependencies is
also the stronger claim for a supply-chain security tool to be able to make.

Rendering is pure: a Finding in, text out, no clock and no network. Nothing in
the rendering path touches the transport code below it, which is what lets the
output be reviewed before it reaches anyone's tracker.

urllib raises HTTPError for 4xx and 5xx rather than returning a response, so
every call is normalised into a _Response first and the retry logic reads the
same either way. Rate-limit headers arrive on the exception, not on a response
object, and that is the part most likely to go wrong.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, NamedTuple

from .model import Finding

__all__ = [
    "GitHubError",
    "advisory_url",
    "close_comment",
    "close_issue",
    "create_issue",
    "dry_run",
    "ensure_labels",
    "find_existing_issue",
    "fix_line",
    "fixed_in_phrase",
    "has_fix",
    "highest_version",
    "package_findings",
    "package_line",
    "render_issue",
    "version_key",
]

LABEL = "sbom-watchdog"
NO_FIX_LABEL = "no-fix"
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
    "no-fix": "5319e7",
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


def version_key(version: str) -> tuple:
    """A sort key that orders 1.26.9 before 1.26.10.

    CLAUDE.md deferred this until something compared versions semantically.
    Something does now: picking the highest fix across a package's findings.
    Plain string sort puts "1.26.10" before "1.26.9" and would recommend an
    older version than the one that actually fixes everything.

    Hand-rolled and standard library only. Split on dots; numeric parts compare
    as integers, non-numeric parts as text and always lower, so 2.0 sorts above
    2.0rc1. A shorter version sorts below a longer one sharing its prefix, so
    1.26 is below 1.26.1.
    """
    key = []
    for part in version.split("."):
        if part.isdigit():
            key.append((1, int(part), ""))
        else:
            key.append((0, 0, part))
    return tuple(key)


def highest_version(versions) -> str | None:
    """The greatest version by natural order, or None when there are none."""
    candidates = [v for v in versions if v]
    return max(candidates, key=version_key) if candidates else None


def package_findings(finding: Finding, findings) -> list[Finding]:
    """Every finding in the scan against the same package.

    Same name and same ecosystem, matching the identity rule: `requests` on
    PyPI and `requests` on npm are unrelated packages.
    """
    if not findings:
        return [finding]
    return [
        candidate for candidate in findings.values()
        if candidate.package_name == finding.package_name
        and candidate.package_type == finding.package_type
    ]


def _major(version: str) -> str:
    return version.split(".", 1)[0]


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


def has_fix(finding: Finding) -> bool:
    """Whether there is a version to install. The whole shape of the issue
    depends on this: with a fix it is a version bump, without one it is a
    decision about whether to keep the dependency at all."""
    return bool(finding.fixed_in)


def fix_line(finding: Finding) -> str:
    """The line telling the reader what to do about it.

    A finding with no fix is a different kind of work item from one with a
    version to install, and the sentence has to say so. "Fixed in: no fixed
    version has been published yet" reads as a template that failed to fill
    itself in - the bold label promises a version and then negates itself - and
    it leaves the reader to work out on their own that upgrading is not on the
    table. Lead with the situation, then name the decision they actually face.
    """
    if has_fix(finding):
        return "**Fixed in:** " + fixed_in_phrase(finding.fixed_in)
    if finding.fix_state == "wont-fix":
        return ("**No fix is planned.** The maintainers have marked this "
                "wont-fix, so no upgrade will resolve it. The realistic options "
                "are to replace the dependency with a maintained alternative, "
                "or to accept the risk and record why.")
    return ("**No fix is available.** No patched release has been published, so "
            "there is nothing to upgrade to. The realistic options are to "
            "replace the dependency with a maintained alternative, or to accept "
            "the risk and record why.")


def package_line(total: int, fixable: int, recommended: str | None) -> str:
    """What upgrading, or not upgrading, does to the rest of this package.

    Three shapes, because they lead to three different actions.

    With no fix anywhere, the reader is deciding about the dependency rather
    than about a version, and the useful fact is that one decision closes
    everything. Without it, two issues against the same abandoned package read
    as two separate decisions and the same "replace it or accept the risk"
    paragraph appears twice, neither acknowledging the other.

    With a fix everywhere, the question is which version, answered by the
    highest.

    Mixed is the dangerous one, and it used to take the fixable wording and
    imply an upgrade covered everything. Upgrading closes some and leaves the
    rest, so a reader could reasonably upgrade and believe they were done. Both
    halves are stated and counted: what the upgrade closes, and what only
    removing the package closes.

    Counts cover every finding for the package in the scan, not only those
    above the threshold. A below-threshold finding is still resolved by
    replacing the package, and the count has to be honest about the work.
    """
    findings = f"{total} findings"

    if not fixable:
        return (f"This package has {findings} in this scan, none with an "
                f"available fix. Replacing or removing it resolves all of them.")

    if fixable == total:
        return (f"This package has {findings} in this scan; the highest fix "
                f"version among them is {recommended}. Upgrading to anything "
                f"below that leaves the others open.")

    remaining = total - fixable
    has_have = "has" if remaining == 1 else "have"
    return (f"This package has {findings} in this scan. Upgrading to "
            f"{recommended} closes {fixable} of them; the remaining "
            f"{remaining} {has_have} no available fix and {'is' if remaining == 1 else 'are'} "
            f"resolved only by replacing or removing the package.")


def render_issue(finding: Finding, findings=None,
                 previous=None) -> tuple[str, str, list[str]]:
    """Render a finding as (title, body, labels).

    `findings` is every finding in the current scan, not just the ones being
    filed. A reader installs one version of a package, and that version has to
    satisfy everything known about it: choosing from the filed subset alone can
    recommend a version that leaves a below-threshold finding unfixed. One
    issue per finding stays right - they resolve independently - but every one
    of them has to give the same answer to "what do I install".

    The finding key is in the title because that is the deduplication net: one
    `GET /search/issues` for the key before creating tells us whether a
    previous run already filed this, even if the state file was never committed
    because the job died after creating issues.
    """
    title = (f"{finding.severity}: {finding.id} in {finding.package_name} "
             f"[{finding.key}]")

    versions = ", ".join(finding.versions) if finding.versions else "unknown"

    # A finding that was resolved and has come back is a regression. Saying so,
    # and naming the issue it was filed under last time, is the difference
    # between "here is a new CVE" and "the fix you applied did not hold".
    regression = ""
    previous = previous or {}
    if previous.get("resolved_on") and previous.get("issue_number"):
        regression = (
            f"This finding was previously reported in #{previous['issue_number']} "
            f"and resolved on {previous['resolved_on']}. It has returned."
            + chr(10) * 2
        )

    # The Fix state row is dropped where the prose already says it. With no
    # fix, "not-fixed" is raw scanner vocabulary restating the sentence below
    # it in a second dialect; with a fix, it still adds something next to a
    # version number.
    rows = [
        f"| Severity | {finding.severity} |",
        f"| Package | `{finding.package_name}` ({finding.package_type}) |",
        f"| Affected version(s) | {versions} |",
    ]
    if has_fix(finding):
        rows.append(f"| Fix state | {finding.fix_state} |")
    table = chr(10).join(rows)

    # "until it is no longer reported as vulnerable" is accurate for something
    # fixable and quietly wrong for something that is not: pycrypto's last
    # release was 2013, so it never stops being reported, and the sentence
    # would imply that waiting is a strategy.
    if has_fix(finding):
        persistence = "until the dependency is no longer reported as vulnerable"
    else:
        persistence = "until the dependency is removed or replaced"

    siblings = package_findings(finding, findings)
    guidance = [fix_line(finding)]

    recommended = highest_version([v for s in siblings for v in s.fixed_in])
    fixable = [s for s in siblings if has_fix(s)]

    if len(siblings) > 1:
        guidance.append(package_line(len(siblings), len(fixable), recommended))

    if recommended and any(_major(v) != _major(recommended)
                           for v in finding.versions):
        guidance.append("This crosses a major version and may require code "
                        "changes.")

    links = []
    for identifier in sorted(finding.aliases):
        url = advisory_url(identifier)
        if url:
            links.append(f"- [{identifier}]({url})")
    advisories = "\n".join(links) if links else "- none published"

    body = f"""{regression}`{finding.package_name}` {versions} is affected by {finding.id}.

| | |
| --- | --- |
{table}

{(chr(10)+chr(10)).join(guidance)}

**Advisories**

{advisories}

<!-- Do not edit the line below: it is how this tool recognises its own issues. -->
{KEY_MARKER} `{finding.key}`

---
Filed by [sbom-watchdog](https://github.com/Johndenisnyagah/sbom-watchdog). This issue was opened because the finding was not present in the previous scan, or because it crossed the severity threshold since the last run.

Closing this issue does not resolve the finding: it stays recorded in `.sbom-watchdog/findings.json` {persistence}. Closing is safe - the issue number is kept in state, so nothing refiles it.
"""

    labels = [LABEL, f"severity:{finding.severity.lower()}"]
    if not has_fix(finding):
        # A separate kind of work item: a dependency-replacement decision
        # rather than a version bump, and worth filtering for on its own.
        labels.append(NO_FIX_LABEL)
    return title, body, labels


def dry_run(selected: list[Finding], findings=None, provenance=None) -> str:
    """What would be posted, as text. Posts nothing."""
    if not selected:
        return "no issues would be filed"

    blocks = [f"{len(selected)} issue(s) would be filed. Nothing was posted.\n"]
    for index, finding in enumerate(selected, start=1):
        title, body, labels = render_issue(
            finding, findings, (provenance or {}).get(finding.key))
        blocks.append(
            f"{'=' * 72}\n"
            f"ISSUE {index} of {len(selected)}\n"
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
_TIMEOUT = 30


class GitHubError(RuntimeError):
    """An API call that did not return what was expected.

    Carries the status code so callers can branch on it. A 403 on label
    creation is survivable and a 422 is not, and telling them apart by
    matching on the text of a message is how that distinction rots.
    """

    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


class _Response(NamedTuple):
    """A normalised HTTP result.

    urllib delivers a success through a context manager and a failure through
    an exception. Both carry a status, headers and a body, so both are turned
    into this before anything looks at them.
    """

    status: int
    headers: Any
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body or b"{}")


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": LABEL,
    }


def _perform(method: str, url: str, token: str, *, params: dict | None = None,
             payload: dict | None = None) -> _Response:
    """One HTTP call, with 4xx and 5xx returned rather than raised."""
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"

    data = None
    headers = _headers(token)
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            return _Response(response.status, response.headers, response.read())
    except urllib.error.HTTPError as error:
        # HTTPError is itself a response: the rate-limit headers this tool
        # depends on arrive here, not on a success.
        return _Response(error.code, error.headers, error.read())


def _pause_for_rate_limit(headers: Any) -> bool:
    """Wait if GitHub has asked us to. True when the call should be retried.

    Two mechanisms, both real: `Retry-After` on a secondary limit, and
    `X-RateLimit-Remaining: 0` with a reset timestamp on the primary one. The
    search endpoint used for deduplication has its own much smaller budget, so
    a repo with many new findings meets this rather than never seeing it.
    """
    retry_after = headers.get("Retry-After")
    if retry_after:
        try:
            wait = min(int(retry_after), _MAX_SLEEP_SECONDS)
        except ValueError:
            wait = 5
        print(f"    rate limited; waiting {wait}s (Retry-After)")
        time.sleep(wait)
        return True

    remaining = headers.get("X-RateLimit-Remaining")
    reset = headers.get("X-RateLimit-Reset")
    if remaining is not None and reset is not None:
        try:
            if int(remaining) <= 0:
                wait = max(0, int(reset) - int(time.time())) + 1
                wait = min(wait, _MAX_SLEEP_SECONDS)
                print(f"    rate limit exhausted; waiting {wait}s for reset")
                time.sleep(wait)
                return True
        except ValueError:
            return False
    return False


def _request(method: str, url: str, token: str, *, expect: tuple[int, ...],
             params: dict | None = None, payload: dict | None = None) -> _Response:
    last = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        response = _perform(method, url, token, params=params, payload=payload)
        last = response
        if response.status in expect:
            return response
        if response.status in (403, 429) and _pause_for_rate_limit(response.headers):
            continue
        if response.status >= 500 and attempt < _MAX_ATTEMPTS:
            sleep_for = min(2 ** attempt, _MAX_SLEEP_SECONDS)
            print(f"    {response.status} from GitHub; retrying in {sleep_for}s")
            time.sleep(sleep_for)
            continue
        # Everything else - 422 for a validation failure, 404 where one is not
        # expected - is a decision, not a hiccup. Retrying it just posts the
        # same broken request again.
        break

    detail = (last.body or b"")[:300].decode("utf-8", "replace")
    raise GitHubError(f"{method} {url} returned {last.status}: {detail}",
                      last.status)


def find_existing_issue(repo: str, key: str, token: str) -> int | None:
    """The number of an existing issue for this finding key, or None.

    This is the safety net for the ordering problem in CLAUDE.md: if a previous
    run created issues and then failed before committing state, the numbers are
    lost from state but the issues exist. Searching by key finds them.

    Only an OPEN issue counts. A closed one means the finding was resolved and
    the issue dealt with; if the finding is being filed again the vulnerability
    has returned, and treating the closed issue as evidence of prior filing
    would swallow the regression silently. Missing a returning vulnerability is
    the one direction this tool must not fail in.

    Caveat worth knowing: GitHub's search index is eventually consistent, so an
    issue created seconds ago may not come back. This narrows the window for
    duplicates across runs; the within-run window is closed by the caller
    checking provenance before it gets here.
    """
    response = _request(
        "GET", f"{API_ROOT}/search/issues", token, expect=(200,),
        params={"q": f'repo:{repo} is:issue is:open in:title "{key}"',
                "per_page": 20},
    )
    for item in response.json().get("items", []):
        if item.get("state") not in (None, "open"):
            continue
        if key in (item.get("title") or ""):
            return item.get("number")
    return None


def ensure_labels(repo: str, labels: list[str], token: str) -> list[str]:
    """Create any label that does not exist yet. Returns the usable ones.

    Posting an issue with a label the repository does not have does not fail;
    the label is silently dropped. Since severity is how these get triaged,
    losing it quietly is worse than an error, so missing labels are created.

    A token without permission to create labels must not cost the adopter the
    issue itself. On 403 the label is dropped from the list and the shortfall
    is logged once: labels are decoration, the issue is the product.
    """
    usable: list[str] = []
    denied: list[str] = []

    for label in labels:
        try:
            response = _request(
                "GET",
                f"{API_ROOT}/repos/{repo}/labels/{urllib.parse.quote(label)}",
                token, expect=(200, 404),
            )
        except GitHubError as error:
            if error.status != 403:
                raise
            denied.append(label)
            continue

        if response.status == 200:
            usable.append(label)
            continue

        try:
            _request(
                "POST", f"{API_ROOT}/repos/{repo}/labels", token, expect=(201,),
                payload={
                    "name": label,
                    "color": _LABEL_COLOURS.get(label, "ededed"),
                    "description": "Managed by sbom-watchdog",
                },
            )
        except GitHubError as error:
            if error.status != 403:
                raise
            denied.append(label)
            continue

        usable.append(label)
        print(f"    created label {label}")

    if denied:
        print(f"    no permission to create label(s) {', '.join(denied)}; "
              f"filing without them")
    return usable


def create_issue(repo: str, title: str, body: str, labels: list[str],
                 token: str) -> int:
    """File the issue and return its number."""
    response = _request(
        "POST", f"{API_ROOT}/repos/{repo}/issues", token, expect=(201,),
        payload={"title": title, "body": body, "labels": labels},
    )
    return int(response.json()["number"])


def close_comment(finding: Finding, installed: str | None = None) -> str:
    """What to say when closing. The reason belongs in the tracker, not only in
    a state file nobody reads."""
    lines = [
        (f"`{finding.package_name}` is no longer reported as affected by "
         f"{finding.id}, so this finding is resolved."),
    ]
    if installed:
        lines.append(f"The scan now sees `{finding.package_name}` {installed}.")
    elif finding.fixed_in:
        fixed = highest_version(finding.fixed_in)
        lines.append(f"A fix for this was published in {fixed}.")
    lines.append(
        "Closed automatically by "
        "[sbom-watchdog](https://github.com/Johndenisnyagah/sbom-watchdog). "
        "If the vulnerability returns, a new issue will be filed referencing "
        "this one."
    )
    return (chr(10) + chr(10)).join(lines)


def close_issue(repo: str, number: int, comment: str, token: str) -> None:
    """Comment, then close.

    The comment goes first deliberately. If the close fails afterwards the
    issue is still annotated with why it was going to be closed, which a person
    can act on; a silent close with no reason is worse than an open issue.
    """
    _request(
        "POST", f"{API_ROOT}/repos/{repo}/issues/{number}/comments", token,
        expect=(201,), payload={"body": comment},
    )
    _request(
        "PATCH", f"{API_ROOT}/repos/{repo}/issues/{number}", token,
        expect=(200,), payload={"state": "closed", "state_reason": "completed"},
    )
