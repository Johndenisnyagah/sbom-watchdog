"""Grype JSON to Finding objects, with vulnerability ID normalisation.

Standard library only. Nothing here touches the filesystem, the network or the
clock; a report arrives as a already-parsed dict and Finding objects come back.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["SEVERITY_ORDER", "Finding", "normalize_severity", "parse_grype", "severity_rank"]

# The domain vocabulary lives here, ordered most severe first; diff.py re-exports
# it. Compare by index, never as a string: "Unknown" sorts above "Low"
# alphabetically and below it in reality.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

_CANONICAL_SEVERITY = {s.lower(): s for s in SEVERITY_ORDER}


@dataclass(frozen=True)
class Finding:
    """One vulnerability in one package, independent of how many versions of
    that package the dependency tree happens to ship."""

    key: str
    id: str
    aliases: frozenset[str]
    package_name: str
    package_type: str
    versions: tuple[str, ...]
    severity: str            # Critical | High | Medium | Low | Negligible | Unknown
    fixed_in: tuple[str, ...]
    fix_state: str           # fixed | not-fixed | wont-fix | unknown


def make_key(vulnerability_id: str, package_type: str, package_name: str) -> str:
    """The identity of a finding. Version is deliberately excluded, so a package
    upgraded while still vulnerable to the same CVE keeps its record."""
    return f"{vulnerability_id}::{package_type}::{package_name.lower()}"


def canonical_id(primary_id: str, related: list[dict[str, Any]]) -> str:
    """Prefer a CVE from relatedVulnerabilities over a GHSA primary ID.

    Grype often reports the GHSA as the primary and carries the CVE alongside.
    Keying on the primary lets a finding change identity when the advisory
    database updates, which files a duplicate issue. Where several CVEs are
    related, the smallest is taken rather than the first, so a reordering of
    the list between runs does not move the key either.
    """
    cves = sorted(
        str(entry.get("id", ""))
        for entry in related
        if str(entry.get("id", "")).startswith("CVE-")
    )
    return cves[0] if cves else primary_id


def severity_rank(severity: str) -> int:
    """Position in SEVERITY_ORDER. An unrecognised rating sorts last, so a
    rating this module does not know about never outranks one it does."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def normalize_severity(raw: str | None) -> str:
    """Canonical casing for a severity, "Unknown" when absent.

    Public because state.py needs the identical treatment on load: a state file
    saying "critical" against a fresh parse saying "Critical" would otherwise
    mark the finding changed on every run.
    """
    if not raw:
        return "Unknown"
    return _CANONICAL_SEVERITY.get(raw.lower(), raw)


def _merge_fix_state(*states: str) -> str:
    """"fixed" if any collapsed match reports a fix, else the first state seen."""
    if "fixed" in states:
        return "fixed"
    return states[0]


def parse_grype(report: dict) -> dict[str, Finding]:
    """Turn a Grype JSON report into Findings keyed by finding identity.

    Matches sharing a key are collapsed into one Finding: the same package at
    two versions in one dependency tree is one vulnerability, not two issues.
    Versions, fix versions and aliases are sorted so the state file written
    from these objects does not churn between runs. Where collapsed matches
    disagree, the highest severity wins, while `fixed_in` is the union across
    matches and `fix_state` is "fixed" if any of them reports a fix.
    """
    findings: dict[str, Finding] = {}

    for match in report.get("matches") or []:
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        related = match.get("relatedVulnerabilities") or []

        primary_id = str(vulnerability.get("id", ""))
        package_name = str(artifact.get("name", ""))
        package_type = str(artifact.get("type", ""))

        identifier = canonical_id(primary_id, related)
        key = make_key(identifier, package_type, package_name)

        aliases = {identifier, primary_id}
        aliases.update(str(entry.get("id", "")) for entry in related)
        aliases.discard("")

        fix = vulnerability.get("fix") or {}
        versions = {str(artifact["version"])} if artifact.get("version") else set()
        fixed_in = {str(v) for v in fix.get("versions") or []}

        severity = normalize_severity(vulnerability.get("severity"))
        fix_state = str(fix.get("state") or "unknown")

        existing = findings.get(key)
        if existing is not None:
            aliases |= set(existing.aliases)
            versions |= set(existing.versions)
            fixed_in |= set(existing.fixed_in)
            # Highest severity wins: Grype can report one package under both the
            # NVD and GitHub namespaces at different ratings, and rounding a
            # security finding down is the wrong kind of wrong.
            if severity_rank(existing.severity) <= severity_rank(severity):
                severity = existing.severity
            # Fix data does not follow the severity winner. The namespaces
            # disagree about fix availability too, and reporting "no fix" for a
            # package that has one is the more damaging error.
            fix_state = _merge_fix_state(existing.fix_state, fix_state)

        findings[key] = Finding(
            key=key,
            id=identifier,
            aliases=frozenset(aliases),
            package_name=package_name.lower(),
            package_type=package_type,
            versions=tuple(sorted(versions)),
            severity=severity,
            fixed_in=tuple(sorted(fixed_in)),
            fix_state=fix_state,
        )

    return findings
