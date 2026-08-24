"""Load and save the committed state file, and convert it to and from Findings.

Round-trip fidelity is the whole job. `diff.py` counts a finding as changed
when any recorded field differs, so a load that drops a field, reorders a list
or changes the case of a package name would mark every finding as changed on
every run and rewrite the committed file each time. Everything below normalises
exactly the way `model.parse_grype` does.
"""
from __future__ import annotations

import json
import logging
from datetime import date, datetime, timezone
from pathlib import Path

from .model import Finding, normalize_severity

__all__ = [
    "SCHEMA_VERSION",
    "findings_from_state",
    "load_state",
    "migrate",
    "provenance_from_state",
    "resolved_from_state",
    "save_state",
    "state_documents_equal",
    "state_from_findings",
    "tooling_from_grype",
    "utc_now",
]

SCHEMA_VERSION = 2
_READABLE = (1, 2)

_LOG = logging.getLogger(__name__)


def utc_now() -> str:
    """The current time as the state file records it: ISO 8601 UTC, trailing Z.

    Formatting lives with the serialiser rather than the orchestrator, so every
    caller writes `generated_at` the same way. `state_from_findings` takes the
    timestamp as an argument and derives both dates from it, which is why this
    is the only clock call in the module.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _first_present(*candidates):
    """The first candidate that is not None, or None if there is no such thing."""
    for value in candidates:
        if value is not None:
            return value
    return None


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def tooling_from_grype(report: dict, syft_version: str | None = None) -> dict:
    """Extract the tooling block for the state file from a Grype report.

    The DB build timestamp is read through both known paths: Grype 0.117 puts
    it at descriptor.db.status.built, 0.87 put it at descriptor.db.built. It
    has moved once, so assume it moves again — every lookup here degrades to
    None rather than raising. Losing a line of provenance is survivable; a scan
    aborting because a metadata field was relocated is not.

    `syft_version` is passed in because a Grype report does not record which
    Syft produced the SBOM it consumed.
    """
    descriptor = _as_dict(_as_dict(report).get("descriptor"))
    db = _as_dict(descriptor.get("db"))
    status = _as_dict(db.get("status"))

    tooling = {
        "syft": syft_version,
        "grype": descriptor.get("version"),
        "grype_db_built": _first_present(status.get("built"), db.get("built")),
        "grype_db_schema_version": _first_present(
            status.get("schemaVersion"), db.get("schemaVersion")
        ),
    }
    if tooling["grype_db_built"] is None:
        _LOG.info(
            "no DB build timestamp at descriptor.db.status.built or "
            "descriptor.db.built; recording null. Grype may have moved it again."
        )
    return tooling


def migrate(state: dict) -> dict:
    """Bring a state document up to the current schema, or refuse it.

    v1 -> v2 adds `resolved_on` to every record. A v1 document has no resolved
    records by construction - v1 deleted them - so every finding it carries is
    currently present and stays unresolved. Nothing is inferred and nothing is
    reinterpreted; the field simply did not exist.
    """
    version = state.get("schema_version")
    if version == SCHEMA_VERSION:
        return state
    if version not in _READABLE:
        raise ValueError(
            f"unsupported state schema_version {version!r}; this build reads "
            f"{_READABLE}. Write a migration rather than reinterpreting the file."
        )

    upgraded = dict(state)
    upgraded["schema_version"] = SCHEMA_VERSION
    upgraded["findings"] = {
        key: {**record, "resolved_on": record.get("resolved_on")}
        for key, record in (state.get("findings") or {}).items()
    }
    return upgraded


def _serialise(state: dict) -> str:
    return json.dumps(state, indent=2, ensure_ascii=False) + "\n"


def provenance_from_state(state: dict) -> dict[str, dict]:
    """Extract the per-finding history a scan cannot reconstruct.

    `first_seen` and `issue_number` are provenance, not scan results: a Finding
    has no clock and no memory of previous runs, so it cannot carry them.
    Phase 4 mutates the returned dict after filing issues, then hands it back
    to `state_from_findings` for a single serialisation.
    """
    state = migrate(state)
    return {
        key: {
            "first_seen": record.get("first_seen"),
            "last_seen": record.get("last_seen"),
            "issue_number": record.get("issue_number"),
            "resolved_on": record.get("resolved_on"),
        }
        for key, record in (state.get("findings") or {}).items()
    }


def findings_from_state(state: dict) -> dict[str, Finding]:
    """Rebuild Findings from a parsed state file.

    The mapping key is authoritative and is never recomputed from the record's
    `id`. After alias reconciliation a finding keeps the key it was first filed
    under, so a GHSA that later gained a CVE still lives at its GHSA key while
    carrying the CVE as its `id`. Recomputing would undo that and file a
    duplicate issue.
    """
    return _findings(state, resolved=False)


def resolved_from_state(state: dict) -> dict[str, Finding]:
    """The findings this document records as already resolved.

    Kept so the link between a finding and the issue it was filed under
    survives the finding going away. Without them a resolved finding's
    issue_number is simply deleted, and nothing can close that issue or
    reference it if the vulnerability returns.
    """
    return _findings(state, resolved=True)


def _findings(state: dict, *, resolved: bool) -> dict[str, Finding]:
    state = migrate(state)

    findings: dict[str, Finding] = {}
    for key, record in (state.get("findings") or {}).items():
        if bool(record.get("resolved_on")) != resolved:
            continue
        package = record.get("package") or {}
        findings[key] = Finding(
            key=key,
            id=str(record.get("id", "")),
            aliases=frozenset(str(a) for a in record.get("aliases") or []),
            package_name=str(package.get("name", "")).lower(),
            package_type=str(package.get("type", "")),
            versions=tuple(sorted(str(v) for v in package.get("versions") or [])),
            severity=normalize_severity(record.get("severity")),
            fixed_in=tuple(sorted(str(v) for v in record.get("fixed_in") or [])),
            fix_state=str(record.get("fix_state") or "unknown"),
        )
    return findings


def state_from_findings(
    findings: dict[str, Finding],
    *,
    provenance: dict,
    generated_at: str,
    tooling: dict,
    resolved: dict[str, Finding] | None = None,
) -> dict:
    """Build a writable state document from the current Findings.

    Both dates come from `generated_at` rather than a clock call of their own.
    Two lookups either side of midnight UTC would eventually write a record
    first seen after it was last seen.

    `resolved` holds findings no longer reported. They stay in the document
    with a `resolved_on` date rather than being deleted, because the record is
    the only link between a finding and the issue it was filed under: delete it
    and nothing can close that issue, or reference it if the finding returns.
    Their `last_seen` stays at the day they were last actually seen.

    Findings are emitted in key order and every list is sorted, so an unchanged
    scan rewrites the file byte for byte identically.
    """
    day = date.fromisoformat(generated_at[:10]).isoformat()
    resolved = resolved or {}

    def record_for(finding: Finding, *, resolved_on: str | None) -> dict:
        prior = provenance.get(finding.key) or {}
        return {
            "id": finding.id,
            "aliases": sorted(finding.aliases),
            "package": {
                "name": finding.package_name,
                "type": finding.package_type,
                "versions": sorted(finding.versions),
            },
            "severity": finding.severity,
            "fixed_in": sorted(finding.fixed_in),
            "fix_state": finding.fix_state,
            "first_seen": prior.get("first_seen") or day,
            "last_seen": prior.get("last_seen") or day if resolved_on else day,
            "issue_number": prior.get("issue_number"),
            "resolved_on": resolved_on,
        }

    records: dict[str, dict] = {}
    for key, finding in findings.items():
        records[key] = record_for(finding, resolved_on=None)

    for key, finding in resolved.items():
        # A finding that is present again is not resolved, whatever the
        # previous document said. That is a regression, and it is handled as
        # new rather than quietly re-marked.
        if key in records:
            continue
        prior = provenance.get(key) or {}
        records[key] = record_for(
            finding, resolved_on=prior.get("resolved_on") or day)

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "tooling": tooling,
        "findings": {key: records[key] for key in sorted(records)},
    }


def state_documents_equal(
    previous: dict | None,
    current: dict | None,
    *,
    ignore: tuple[str, ...] = ("generated_at",),
) -> bool:
    """Compare two state documents, ignoring keys that move on every run.

    `generated_at` changes on every scan by definition, so a textual diff of
    the file always reports a change and would commit one daily whether or not
    anything was found. This comparison is semantic: it answers "is there
    anything here worth committing", which is not a question `git diff` can be
    asked.

    Only top-level keys can be ignored. `findings` is compared in full,
    `last_seen` included - a finding still being present today is a fact the
    audit trail records.

    A missing document (None) never equals a present one, so the first run
    always writes.
    """
    if previous is None or current is None:
        return previous is None and current is None
    return (
        {k: v for k, v in previous.items() if k not in ignore}
        == {k: v for k, v in current.items() if k not in ignore}
    )


def load_state(path) -> dict | None:
    """Return the parsed state document, or None when the file does not exist.

    None means "no state file", which is what triggers bootstrap. A state file
    holding zero findings is a different thing entirely: a repo that was clean
    yesterday. Never collapse the two.
    """
    file = Path(path)
    if not file.exists():
        return None
    raw = file.read_text(encoding="utf-8")
    state = json.loads(raw)
    _log_if_not_canonical(state, raw, file)
    return state


def _log_if_not_canonical(state: dict, raw: str, file: Path) -> None:
    """Announce a file that will not survive a save unchanged.

    A hand-edited file, or one written by an older build, still loads; it just
    reorders on the next commit. Saying so at load time stops that showing up
    later as an unexplained diff.
    """
    try:
        rebuilt = state_from_findings(
            findings_from_state(state),
            provenance=provenance_from_state(state),
            generated_at=str(state.get("generated_at") or ""),
            tooling=state.get("tooling") or {},
        )
    except (ValueError, TypeError) as exc:
        _LOG.info("%s could not be checked for canonical form: %s", file, exc)
        return
    if _serialise(rebuilt) != raw:
        _LOG.info(
            "%s is not in canonical form and will be rewritten on the next save",
            file,
        )


def save_state(path, state: dict) -> None:
    """Write the state document, creating the directory if needed.

    Newlines are forced to LF: the file is committed, and letting it pick up
    CRLF on a Windows run would rewrite every line of the diff.
    """
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(_serialise(state), encoding="utf-8", newline="\n")
