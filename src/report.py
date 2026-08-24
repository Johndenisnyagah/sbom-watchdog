"""The compliance outputs: a dated SBOM history and SECURITY-INVENTORY.md.

Two different documents for two different readers.

`sboms/YYYY-MM-DD.json` is the append-only audit trail, as distinct from
`findings.json`, which is working state. Its value is evidentiary: it answers
"prove you generated an inventory on 14 March" with a file dated 14 March.

`SECURITY-INVENTORY.md` is written for someone who is not a developer. A
procurement reviewer or an auditor should be able to read it without knowing
what a package URL is, so nothing here repeats the scanner's vocabulary: no
`fix_state`, no `purl`, no `not-fixed`. The same discipline that fixed the
no-fix issue body applies, and for the same reason - the words are the product.

Pure apart from the two functions that write files, so the rendering can be
read in a test without a filesystem.
"""
from __future__ import annotations

import json
import shutil
from datetime import date
from pathlib import Path

from .model import SEVERITY_ORDER

__all__ = [
    "inventory_markdown",
    "sbom_history_path",
    "write_inventory",
    "write_sbom_history",
]

MONTHS = ("January", "February", "March", "April", "May", "June", "July",
          "August", "September", "October", "November", "December")


def _long_date(iso: str) -> str:
    """2026-08-24 -> 24 August 2026, for a reader rather than a parser."""
    try:
        day = date.fromisoformat(iso[:10])
    except ValueError:
        return iso
    return f"{day.day} {MONTHS[day.month - 1]} {day.year}"


def sbom_history_path(directory, generated_at: str) -> Path:
    """Where today's inventory belongs: one file per day, named by that day."""
    return Path(directory) / f"{generated_at[:10]}.json"


def write_sbom_history(sbom: Path, directory, generated_at: str) -> Path:
    """Copy the scan's SBOM into the dated history.

    Written every day the scan runs, never skipped for being unchanged. A
    missing file has to mean "no scan ran that day" and nothing else: if it
    could also mean "the dependencies had not changed", then the trail cannot
    distinguish a stable project from an abandoned one, which is the single
    question it exists to answer. GitHub disables scheduled workflows after 60
    days of inactivity, so "we quietly stopped scanning" is a real way for this
    to end, not a hypothetical.

    The document's serialNumber and timestamp differ on every run even when the
    component list is identical, so byte-comparison would never suppress
    anything anyway; suppressing would mean comparing components and explaining
    that rule to whoever is reading the trail.
    """
    destination = sbom_history_path(directory, generated_at)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sbom, destination)
    return destination


def _open_and_resolved(state: dict) -> tuple[list[dict], list[dict]]:
    records = list((state.get("findings") or {}).values())
    resolved = [r for r in records if r.get("resolved_on")]
    return [r for r in records if not r.get("resolved_on")], resolved


def _has_fix(record: dict) -> bool:
    return bool(record.get("fixed_in"))


def _counts(records: list[dict]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for record in records:
        counts[record.get("severity", "Unknown")] = (
            counts.get(record.get("severity", "Unknown"), 0) + 1)
    return {severity: n for severity, n in counts.items() if n}


def _severity_table(records: list[dict]) -> str:
    counts = _counts(records)
    rows = [f"| {severity} | {count} |" for severity, count in counts.items()]
    rows.append(f"| **Total** | **{len(records)}** |")
    return "\n".join(["| Severity | Count |", "| --- | ---: |", *rows])


def _finding_rows(records: list[dict]) -> str:
    rows = []
    for record in sorted(records, key=lambda r: (
            SEVERITY_ORDER.index(r.get("severity", "Unknown")),
            (r.get("package") or {}).get("name", ""), r.get("id", ""))):
        package = record.get("package") or {}
        versions = ", ".join(package.get("versions") or []) or "unknown"
        fixed = ", ".join(record.get("fixed_in") or []) or "none published"
        rows.append(
            f"| {package.get('name', '')} | {versions} | "
            f"{record.get('severity', 'Unknown')} | {record.get('id', '')} | "
            f"{fixed} |"
        )
    return "\n".join([
        "| Package | Version in use | Severity | Advisory | Fixed in |",
        "| --- | --- | --- | --- | --- |",
        *rows,
    ])


def inventory_markdown(state: dict) -> str:
    """Render SECURITY-INVENTORY.md from a state document."""
    generated_at = str(state.get("generated_at") or "")
    tooling = state.get("tooling") or {}
    current, resolved = _open_and_resolved(state)

    awaiting = [r for r in current if _has_fix(r)]
    no_fix = [r for r in current if not _has_fix(r)]

    parts = [
        "# Security inventory",
        "",
        (
            "This file is generated automatically and should not be edited by hand. "
            "It lists every known security vulnerability in the software this "
            "project depends on, and what can be done about each one."
        ),
        "",
        f"**Last checked:** {_long_date(generated_at)}  ",
        f"**Vulnerabilities currently open:** {len(current)}  ",
        f"**Vulnerabilities resolved since tracking began:** {len(resolved)}",
        "",
        "## What is open now",
        "",
    ]

    if current:
        parts += [
            _severity_table(current),
            "",
            (
                "Severity is the rating published by the public vulnerability "
                "databases, not an assessment of how this project uses the "
                "software. A high severity vulnerability in a component that is "
                "never reached may present little practical risk, and judging that "
                "is a human decision this tool does not make."
            ),
            "",
            f"### Can be fixed by updating ({len(awaiting)})",
            "",
        ]
        parts.append(
            f"{len(awaiting)} of the {len(current)} open vulnerabilities have a "
            f"newer version of the affected software available that resolves "
            f"them." if awaiting else
            "None of the open vulnerabilities can currently be fixed by "
            "updating."
        )
        parts += [
            "",
            f"### No fix available ({len(no_fix)})",
            "",
        ]
        if no_fix:
            parts += [
                (
                    f"{len(no_fix)} of the {len(current)} open vulnerabilities have "
                    f"no published fix. Updating will not resolve these: the "
                    f"software has to be replaced with a maintained alternative, or "
                    f"removed, or the risk accepted and recorded. This is a "
                    f"different decision from the ones above, and usually a slower "
                    f"one."
                ),
                "",
                _finding_rows(no_fix),
            ]
        else:
            parts.append(
                "Every open vulnerability has a published fix available.")
        parts += ["", "### All open vulnerabilities", "", _finding_rows(current)]
    else:
        parts.append(
            "No known vulnerabilities are open. Every component this project "
            "depends on was checked against the vulnerability databases on the "
            "date above and none is currently reported as affected.")

    parts += ["", "## What has been resolved", ""]
    if resolved:
        parts += [
            (
                f"{len(resolved)} vulnerabilities were reported previously and are "
                f"no longer present. They are kept here because a record of having "
                f"fixed something is part of the trail, not clutter to be tidied "
                f"away."
            ),
            "",
            "\n".join([
                "| Package | Severity | Advisory | Resolved on |",
                "| --- | --- | --- | --- |",
                *[f"| {(r.get('package') or {}).get('name', '')} | "
                  f"{r.get('severity', '')} | {r.get('id', '')} | "
                  f"{_long_date(str(r.get('resolved_on') or ''))} |"
                  for r in sorted(resolved, key=lambda r: str(r.get("resolved_on")))],
            ]),
        ]
    else:
        parts.append(
            "Nothing has been resolved yet. Once a vulnerability stops being "
            "reported it is recorded here with the date, rather than being "
            "deleted.")

    parts += [
        "",
        "## How this was checked",
        "",
        "| | |",
        "| --- | --- |",
        f"| Date of this check | {_long_date(generated_at)} |",
        f"| Software inventory produced by | Syft {tooling.get('syft') or 'unknown'} |",
        f"| Vulnerabilities identified by | Grype {tooling.get('grype') or 'unknown'} |",
        f"| Vulnerability data published on | {_long_date(str(tooling.get('grype_db_built') or '')) or 'unknown'} |",
        "",
        (
            "The check runs automatically on a schedule. The full list of software "
            "components is recorded under `sboms/`, one file per day the check ran, "
            "so the absence of a file for a given date means no check ran that day."
        ),
        "",
        "Generated by [sbom-watchdog](https://github.com/Johndenisnyagah/sbom-watchdog).",
        "",
    ]
    return "\n".join(parts)


def write_inventory(path, state: dict) -> Path:
    """Write SECURITY-INVENTORY.md, creating the directory if needed."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(inventory_markdown(state), encoding="utf-8",
                           newline="\n")
    return destination


def load_and_render(state_path) -> str:
    """Convenience for rendering from a state file on disk."""
    return inventory_markdown(
        json.loads(Path(state_path).read_text(encoding="utf-8")))
