"""The diff engine: (previous, current) -> DiffResult.

Pure by contract. Nothing here touches the filesystem, the network, the clock
or the environment; everything it needs arrives as an argument. That is what
makes the fixture tests possible, and it is the constraint most likely to get
quietly violated while wiring up phase 4.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

# SEVERITY_ORDER is re-exported here per CLAUDE.md: the vocabulary belongs to
# model.py, but the public API names it on diff.py. __all__ keeps it exported.
from .model import SEVERITY_ORDER, Finding, severity_rank

__all__ = ["SEVERITY_ORDER", "DiffResult", "diff", "select_for_issues"]


@dataclass(frozen=True)
class DiffResult:
    bootstrap: bool
    new: dict[str, Finding]
    resolved: dict[str, Finding]
    unchanged: dict[str, Finding]
    changed: dict[str, tuple[Finding, Finding]]   # key -> (previous, current)


def _reconcile(finding: Finding, previous: dict[str, Finding], taken: set[str]) -> str | None:
    """Find the previous key for a finding whose own key is absent.

    A vulnerability with no CVE yesterday and a CVE today changes key, which
    normalisation alone cannot catch. Matching needs all three of package name,
    package type and an alias overlap: name and type alone would merge two
    unrelated advisories against one package, and alias overlap alone would
    merge `requests` on PyPI with `requests` on npm.
    """
    for previous_key, prior in previous.items():
        if previous_key in taken:
            continue
        if prior.package_name != finding.package_name:
            continue
        if prior.package_type != finding.package_type:
            continue
        if finding.aliases & prior.aliases:
            return previous_key
    return None


def diff(previous: dict[str, Finding] | None,
         current: dict[str, Finding]) -> DiffResult:
    """Compare two scans.

    `previous is None` means no state file: the run records a baseline and
    reports nothing as new, so the caller never has to special-case the first
    run. An empty dict is a different thing entirely — a repo that was clean
    yesterday and has findings today is a real alert.
    """
    if previous is None:
        return DiffResult(
            bootstrap=True,
            new={},
            resolved={},
            unchanged=dict(current),
            changed={},
        )

    # Reconciliation runs before the set difference, so a finding that merely
    # changed identity is never mistaken for a new one.
    matched: dict[str, str] = {}
    taken: set[str] = set()
    for key in current:
        if key in previous:
            matched[key] = key
            taken.add(key)
    for key, finding in current.items():
        if key in matched:
            continue
        previous_key = _reconcile(finding, previous, taken)
        if previous_key is not None:
            matched[key] = previous_key
            taken.add(previous_key)

    new: dict[str, Finding] = {}
    unchanged: dict[str, Finding] = {}
    changed: dict[str, tuple[Finding, Finding]] = {}

    for key, finding in current.items():
        previous_key = matched.get(key)
        if previous_key is None:
            new[key] = finding
            continue
        prior = previous[previous_key]
        # The previous key is carried forward so issue_number and first_seen
        # survive, and the alias sets are merged so the identifier the finding
        # was filed under is never lost.
        reconciled = replace(
            finding,
            key=previous_key,
            aliases=finding.aliases | prior.aliases,
        )
        if reconciled == prior:
            unchanged[previous_key] = reconciled
        else:
            changed[previous_key] = (prior, reconciled)

    resolved = {k: v for k, v in previous.items() if k not in taken}

    return DiffResult(
        bootstrap=False,
        new=new,
        resolved=resolved,
        unchanged=unchanged,
        changed=changed,
    )


def select_for_issues(result: DiffResult, threshold: str = "High") -> list[Finding]:
    """Decide what earns an issue. Pure: it never asks whether one exists.

    Deduplication against `issue_number` happens in issues.py. A changed
    finding files in exactly one situation — it was below the threshold last
    run and is at or above it now. Everything else is recorded and stays
    silent, since a version bump that leaves a package vulnerable does not
    deserve a second notification.
    """
    if threshold not in SEVERITY_ORDER:
        raise ValueError(
            f"unknown severity threshold {threshold!r}; expected one of "
            f"{SEVERITY_ORDER}"
        )
    limit = severity_rank(threshold)

    selected = [f for f in result.new.values() if severity_rank(f.severity) <= limit]
    selected += [
        current
        for prior, current in result.changed.values()
        if severity_rank(prior.severity) > limit >= severity_rank(current.severity)
    ]
    return selected
