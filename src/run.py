"""Orchestrator: Grype JSON in, updated state document out.

Run as a module so the relative imports resolve:

    python -m src.run --scan out/grype.json \
        --state .sbom-watchdog/findings.json --out out/findings.json

This is the only module that reads a clock, touches the filesystem and knows
where files live. `diff.py` stays pure and every path arrives as an argument -
nothing here hardcodes `.sbom-watchdog/findings.json`, because the workflow
passes it and the tests need to point somewhere else.

It deliberately does not create issues or commit anything.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .diff import DiffResult, diff, select_for_issues
from .model import Finding, parse_grype
from .state import (
    findings_from_state,
    load_state,
    provenance_from_state,
    save_state,
    state_from_findings,
    tooling_from_grype,
    utc_now,
)

__all__ = ["findings_to_record", "main"]


def findings_to_record(result: DiffResult) -> dict[str, Finding]:
    """The findings the next state file should carry, under the keys they keep.

    Taking the parsed scan directly would be wrong: alias reconciliation moves
    a finding back to the key it was first filed under, and that key is what
    `first_seen` and `issue_number` hang off. `unchanged` and `changed` are
    already keyed that way, so they are the authority here, not `current`.

    Resolved findings are dropped. They are no longer present in the scan, and
    the committed git history is what preserves them.
    """
    records: dict[str, Finding] = dict(result.unchanged)
    records.update({key: current for key, (_, current) in result.changed.items()})
    records.update(result.new)
    return records


def summarise(result: DiffResult, threshold: str, scan_path: str) -> str:
    """The run's report, for a human reading a workflow log."""
    lines = []
    if result.bootstrap:
        lines.append("bootstrap: no prior state file - recording the baseline.")
        lines.append("           Nothing is new on a first run, and no issues are filed.")
    else:
        lines.append("comparing against the previous state file.")

    total = len(result.new) + len(result.unchanged) + len(result.changed)
    lines.append(f"scan:      {scan_path} - {total} findings")
    lines.append(f"  new:        {len(result.new)}")
    lines.append(f"  resolved:   {len(result.resolved)}")
    lines.append(f"  unchanged:  {len(result.unchanged)}")
    lines.append(f"  changed:    {len(result.changed)}")

    selected = select_for_issues(result, threshold=threshold)
    lines.append(f"would file {len(selected)} issue(s) at threshold {threshold}"
                 " (nothing is filed in this phase)")
    for finding in selected:
        lines.append(f"    {finding.severity:9} {finding.key}")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.run",
        description="Diff a Grype report against the committed state file.",
    )
    parser.add_argument("--scan", required=True,
                        help="path to the Grype JSON report")
    parser.add_argument("--state", required=True,
                        help="path to the existing state file; absent means bootstrap")
    parser.add_argument("--out", required=True,
                        help="path to write the updated state document to")
    parser.add_argument("--threshold", default="High",
                        help="severity at or above which a finding would be filed")
    parser.add_argument("--syft-version", default=None,
                        help="Syft version, recorded as provenance; Grype does not report it")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    report = json.loads(Path(args.scan).read_text(encoding="utf-8"))
    current = parse_grype(report)

    previous_state = load_state(args.state)
    previous = None if previous_state is None else findings_from_state(previous_state)
    provenance = {} if previous_state is None else provenance_from_state(previous_state)

    result = diff(previous, current)
    print(summarise(result, args.threshold, args.scan))

    # One timestamp for the whole run: state_from_findings derives both dates
    # from it, so a second clock call either side of midnight UTC cannot write
    # a record first seen after it was last seen.
    state = state_from_findings(
        findings_to_record(result),
        provenance=provenance,
        generated_at=utc_now(),
        tooling=tooling_from_grype(report, syft_version=args.syft_version),
    )
    save_state(args.out, state)
    print(f"state written to {args.out} ({len(state['findings'])} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
