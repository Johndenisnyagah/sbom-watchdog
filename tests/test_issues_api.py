"""Specification for the GitHub calls.

Everything here mocks urllib at the transport layer: `urllib.request.urlopen`
is replaced, so no test opens a socket. That is asserted rather than assumed -
`socket.socket` is poisoned for every test in this module, so a code path that
tried to reach the network would fail loudly instead of quietly succeeding on
somebody's machine and failing in CI.

urllib signals failure by raising HTTPError rather than returning a response,
and the rate-limit headers this tool depends on arrive on that exception. These
tests exercise both shapes deliberately.
"""
import io
import json
import socket
import time
import urllib.error
import urllib.request
from email.message import Message

import pytest

from src.issues import (
    GitHubError,
    close_issue,
    create_issue,
    ensure_labels,
    find_existing_issue,
)

TOKEN = "ghs_test_token"
REPO = "owner/name"


# --- transport doubles ----------------------------------------------------

def headers(mapping: dict[str, str]) -> Message:
    """Real header container, so .get() is case-insensitive as in production."""
    message = Message()
    for key, value in mapping.items():
        message[key] = value
    return message


class Ok:
    """A successful urlopen result: a context manager with status/headers/read."""

    def __init__(self, status: int = 200, body: object = None,
                 header_map: dict[str, str] | None = None):
        self.status = status
        self.headers = headers(header_map or {})
        self._body = json.dumps(body if body is not None else {}).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def fail(status: int, header_map: dict[str, str] | None = None,
         body: object = None) -> urllib.error.HTTPError:
    """The failure shape: HTTPError carrying the status, headers and body."""
    payload = json.dumps(body if body is not None else {}).encode()
    return urllib.error.HTTPError(
        "https://api.github.com/test", status, "error",
        headers(header_map or {}), io.BytesIO(payload),
    )


class Transport:
    """Replaces urllib.request.urlopen and records what it was asked to send."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.requests: list[urllib.request.Request] = []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        if not self.outcomes:
            raise AssertionError("transport called more times than expected")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    @property
    def call_count(self) -> int:
        return len(self.requests)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Poison the socket layer. Nothing in this module may reach the network."""
    def blocked(*args, **kwargs):
        raise RuntimeError("network access is blocked in tests")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


@pytest.fixture(autouse=True)
def sleeps(monkeypatch):
    """Record sleeps instead of taking them, so backoff is assertable."""
    recorded: list[float] = []
    monkeypatch.setattr(time, "sleep", recorded.append)
    return recorded


def transport(monkeypatch, *outcomes) -> Transport:
    fake = Transport(*outcomes)
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    return fake


def body_of(request: urllib.request.Request) -> dict:
    return json.loads(request.data.decode())


# --- the guard itself -----------------------------------------------------

def test_no_test_performs_real_network_io():
    """Proves the poison is active. If this passes, every other test in this
    module is genuinely offline rather than merely believed to be."""
    with pytest.raises(RuntimeError, match="network access is blocked"):
        socket.socket()
    with pytest.raises(RuntimeError, match="network access is blocked"):
        socket.create_connection(("api.github.com", 443))


# --- create_issue ---------------------------------------------------------

def test_create_issue_posts_and_returns_the_number(monkeypatch):
    fake = transport(monkeypatch, Ok(201, {"number": 42}))

    number = create_issue(REPO, "a title", "a body", ["sbom-watchdog"], TOKEN)

    assert number == 42
    assert fake.call_count == 1
    request = fake.requests[0]
    assert request.get_method() == "POST"
    assert request.full_url == "https://api.github.com/repos/owner/name/issues"
    assert body_of(request) == {
        "title": "a title",
        "body": "a body",
        "labels": ["sbom-watchdog"],
    }


def test_create_issue_sends_the_token_and_api_version(monkeypatch):
    fake = transport(monkeypatch, Ok(201, {"number": 1}))
    create_issue(REPO, "t", "b", [], TOKEN)

    request = fake.requests[0]
    assert request.get_header("Authorization") == f"Bearer {TOKEN}"
    assert request.get_header("Content-type") == "application/json"


def test_create_issue_number_is_an_int_even_if_the_api_sends_a_string(monkeypatch):
    transport(monkeypatch, Ok(201, {"number": "77"}))
    assert create_issue(REPO, "t", "b", [], TOKEN) == 77


# --- find_existing_issue --------------------------------------------------

def test_find_existing_issue_returns_the_number_on_a_hit(monkeypatch):
    key = "CVE-2023-45803::python::urllib3"
    fake = transport(monkeypatch, Ok(200, {
        "items": [{"number": 7, "title": f"High: CVE-2023-45803 in urllib3 [{key}]"}]
    }))

    assert find_existing_issue(REPO, key, TOKEN) == 7
    request = fake.requests[0]
    assert request.get_method() == "GET"
    assert request.full_url.startswith("https://api.github.com/search/issues?")
    assert "in%3Atitle" in request.full_url


def test_find_existing_issue_returns_none_on_an_empty_result(monkeypatch):
    transport(monkeypatch, Ok(200, {"items": []}))
    assert find_existing_issue(REPO, "CVE-1::python::x", TOKEN) is None


def test_find_existing_issue_ignores_a_match_whose_title_lacks_the_key(monkeypatch):
    """Search is fuzzy. A result that does not actually carry the key is not
    this finding, and treating it as one would suppress a real issue."""
    transport(monkeypatch, Ok(200, {
        "items": [{"number": 9, "title": "something else entirely"}]
    }))
    assert find_existing_issue(REPO, "CVE-1::python::x", TOKEN) is None


# --- ensure_labels --------------------------------------------------------

def test_ensure_labels_creates_only_the_missing_ones(monkeypatch):
    fake = transport(
        monkeypatch,
        Ok(200),                       # sbom-watchdog exists
        fail(404),                     # severity:high does not
        Ok(201, {"name": "severity:high"}),
    )

    ensure_labels(REPO, ["sbom-watchdog", "severity:high"], TOKEN)

    assert fake.call_count == 3
    methods = [r.get_method() for r in fake.requests]
    assert methods == ["GET", "GET", "POST"]
    created = body_of(fake.requests[2])
    assert created["name"] == "severity:high"
    assert created["color"] == "d93f0b"


def test_ensure_labels_posts_nothing_when_all_exist(monkeypatch):
    fake = transport(monkeypatch, Ok(200), Ok(200))
    ensure_labels(REPO, ["sbom-watchdog", "severity:low"], TOKEN)

    assert fake.call_count == 2
    assert all(r.get_method() == "GET" for r in fake.requests)


def test_ensure_labels_returns_the_usable_labels(monkeypatch):
    transport(monkeypatch, Ok(200), Ok(200))
    assert ensure_labels(REPO, ["sbom-watchdog", "severity:low"], TOKEN) == [
        "sbom-watchdog", "severity:low",
    ]


def test_ensure_labels_degrades_when_creation_is_forbidden(monkeypatch, capsys):
    """A restrictive token must cost the adopter a label, not the issue. Labels
    are decoration; the issue is the product."""
    fake = transport(
        monkeypatch,
        Ok(200),                                   # sbom-watchdog exists
        fail(404),                                 # severity:high does not
        fail(403, {}, {"message": "Resource not accessible by integration"}),
    )

    usable = ensure_labels(REPO, ["sbom-watchdog", "severity:high"], TOKEN)

    assert usable == ["sbom-watchdog"]
    assert fake.call_count == 3
    printed = capsys.readouterr().out
    assert "no permission to create label(s) severity:high" in printed
    assert "filing without them" in printed


def test_ensure_labels_degrades_when_even_the_lookup_is_forbidden(monkeypatch):
    transport(monkeypatch, fail(403), fail(403))
    assert ensure_labels(REPO, ["sbom-watchdog", "severity:high"], TOKEN) == []


def test_ensure_labels_logs_the_shortfall_once(monkeypatch, capsys):
    transport(monkeypatch, fail(404), fail(403), fail(404), fail(403))
    ensure_labels(REPO, ["severity:high", "severity:low"], TOKEN)

    printed = capsys.readouterr().out
    assert printed.count("no permission to create label(s)") == 1
    assert "severity:high, severity:low" in printed


def test_ensure_labels_still_raises_on_a_non_403_failure(monkeypatch):
    """422 is a malformed request, not a permission boundary. Swallowing it
    would hide a real bug behind a silently unlabelled issue."""
    transport(monkeypatch, fail(404), fail(422, {}, {"message": "Validation Failed"}))

    with pytest.raises(GitHubError) as caught:
        ensure_labels(REPO, ["severity:high"], TOKEN)
    assert caught.value.status == 422


def test_github_error_carries_the_status_code(monkeypatch):
    transport(monkeypatch, fail(404, {}, {"message": "Not Found"}))
    with pytest.raises(GitHubError) as caught:
        create_issue(REPO, "t", "b", [], TOKEN)
    assert caught.value.status == 404


def test_ensure_labels_url_encodes_the_label_name(monkeypatch):
    fake = transport(monkeypatch, Ok(200))
    ensure_labels(REPO, ["severity:high"], TOKEN)
    assert fake.requests[0].full_url.endswith("/labels/severity%3Ahigh")


# --- rate limiting --------------------------------------------------------

def test_primary_rate_limit_sleeps_and_retries(monkeypatch, sleeps):
    """403 with the remaining budget at zero is a wait, not a failure."""
    reset_at = int(time.time()) + 30
    fake = transport(
        monkeypatch,
        fail(403, {"X-RateLimit-Remaining": "0",
                   "X-RateLimit-Reset": str(reset_at)}),
        Ok(201, {"number": 5}),
    )

    assert create_issue(REPO, "t", "b", [], TOKEN) == 5
    assert fake.call_count == 2
    assert len(sleeps) == 1
    assert 0 < sleeps[0] <= 120


def test_secondary_rate_limit_honours_retry_after(monkeypatch, sleeps):
    fake = transport(
        monkeypatch,
        fail(429, {"Retry-After": "7"}),
        Ok(201, {"number": 6}),
    )

    assert create_issue(REPO, "t", "b", [], TOKEN) == 6
    assert fake.call_count == 2
    assert sleeps == [7]


def test_rate_limit_wait_is_capped(monkeypatch, sleeps):
    transport(monkeypatch, fail(429, {"Retry-After": "99999"}), Ok(201, {"number": 1}))
    create_issue(REPO, "t", "b", [], TOKEN)
    assert sleeps == [120]


def test_403_without_rate_limit_headers_is_a_failure_not_a_wait(monkeypatch, sleeps):
    """A 403 for a missing permission must fail immediately. Sleeping and
    retrying would turn a misconfigured token into a two minute hang."""
    fake = transport(monkeypatch, fail(403, {}, {"message": "Resource not accessible"}))

    with pytest.raises(RuntimeError, match="403"):
        create_issue(REPO, "t", "b", [], TOKEN)

    assert fake.call_count == 1
    assert sleeps == []


# --- server errors and validation failures --------------------------------

def test_5xx_retries_with_backoff_then_gives_up(monkeypatch, sleeps):
    fake = transport(monkeypatch, fail(502), fail(502), fail(502))

    with pytest.raises(RuntimeError, match="502"):
        create_issue(REPO, "t", "b", [], TOKEN)

    assert fake.call_count == 3
    assert sleeps == [2, 4]


def test_5xx_that_recovers_returns_normally(monkeypatch, sleeps):
    transport(monkeypatch, fail(500), Ok(201, {"number": 11}))
    assert create_issue(REPO, "t", "b", [], TOKEN) == 11
    assert sleeps == [2]


def test_422_does_not_retry(monkeypatch, sleeps):
    """A validation failure is a decision, not a hiccup. Retrying it just posts
    the same broken request twice more."""
    fake = transport(monkeypatch, fail(422, {}, {"message": "Validation Failed"}))

    with pytest.raises(RuntimeError, match="422"):
        create_issue(REPO, "t", "b", [], TOKEN)

    assert fake.call_count == 1
    assert sleeps == []


def test_the_error_carries_the_response_body(monkeypatch):
    """Whoever reads the failing log needs GitHub's reason, not just a code."""
    transport(monkeypatch, fail(422, {}, {"message": "Validation Failed"}))

    with pytest.raises(RuntimeError, match="Validation Failed"):
        create_issue(REPO, "t", "b", [], TOKEN)


# --- only an open issue counts as prior filing ----------------------------

def test_find_existing_issue_asks_for_open_issues_only(monkeypatch):
    fake = transport(monkeypatch, Ok(200, {"items": []}))
    find_existing_issue(REPO, "CVE-1::python::x", TOKEN)
    assert "is%3Aopen" in fake.requests[0].full_url


def test_a_closed_issue_is_not_evidence_of_prior_filing(monkeypatch):
    """A closed issue means the finding was resolved and dealt with. If it is
    being filed again the vulnerability has returned, and treating the closed
    issue as prior filing swallows the regression silently."""
    key = "CVE-2023-45803::python::urllib3"
    transport(monkeypatch, Ok(200, {
        "items": [{"number": 45, "state": "closed",
                   "title": f"High: CVE-2023-45803 in urllib3 [{key}]"}]
    }))

    assert find_existing_issue(REPO, key, TOKEN) is None


def test_an_open_issue_is_still_evidence(monkeypatch):
    key = "CVE-2023-45803::python::urllib3"
    transport(monkeypatch, Ok(200, {
        "items": [{"number": 45, "state": "open",
                   "title": f"High: CVE-2023-45803 in urllib3 [{key}]"}]
    }))

    assert find_existing_issue(REPO, key, TOKEN) == 45


# --- closing --------------------------------------------------------------

def test_close_issue_comments_then_closes(monkeypatch):
    """The comment goes first. A close that succeeds after a failed comment is
    a silent close; a comment that survives a failed close is actionable."""
    fake = transport(monkeypatch, Ok(201, {"id": 1}), Ok(200, {"number": 3}))

    close_issue(REPO, 3, "it is fixed", TOKEN)

    assert fake.call_count == 2
    comment, close = fake.requests
    assert comment.get_method() == "POST"
    assert comment.full_url.endswith("/repos/owner/name/issues/3/comments")
    assert body_of(comment) == {"body": "it is fixed"}

    assert close.get_method() == "PATCH"
    assert close.full_url.endswith("/repos/owner/name/issues/3")
    assert body_of(close) == {"state": "closed", "state_reason": "completed"}


def test_close_issue_raises_when_the_close_fails(monkeypatch):
    """run.py swallows this so the state write still happens; the API layer
    must still report it rather than pretending."""
    transport(monkeypatch, Ok(201, {"id": 1}), fail(404, {}, {"message": "Not Found"}))

    with pytest.raises(GitHubError) as caught:
        close_issue(REPO, 3, "it is fixed", TOKEN)
    assert caught.value.status == 404
