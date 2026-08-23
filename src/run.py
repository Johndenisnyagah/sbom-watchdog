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
import os
import sys
from pathlib import Path

from .diff import DiffResult, diff, select_for_issues
from .issues import dry_run
from .model import Finding, parse_grype
from .state import (
    findings_from_state,
    load_state,
    provenance_from_state,
    save_state,
    state_documents_equal,
    state_from_findings,
    tooling_from_grype,
    utc_now,
)

__all__ = ["commit_message", "findings_to_record", "main"]


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


def commit_message(result: DiffResult, state: dict) -> str:
    """The one-line summary the commit-back commits under.

    Built here rather than in workflow shell. This text is permanent in
    somebody's git history, and it is the first thing a person reads when
    deciding whether to trust the tool. Assembling it from step outputs in bash
    is how a baseline of findings once got committed as "no change (scan of )":
    $GITHUB_OUTPUT is per-step, so the values simply were not there.

    Bootstrap is checked first because a first run reports zero new by design.
    """
    if result.bootstrap:
        return (f"Vulnerability state: baseline, {len(state['findings'])} "
                f"findings recorded [skip ci]")
    if result.new or result.resolved:
        return (f"Vulnerability state: {len(result.new)} new, "
                f"{len(result.resolved)} resolved [skip ci]")
    return (f"Vulnerability state: no change "
            f"(scan of {state['generated_at'][:10]}) [skip ci]")


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


def _emit_github_output(name: str, value: str) -> None:
    """Publish a step output when running under Actions, and do nothing when not.

    The workflow gates the commit step on this rather than on `git diff`,
    because whether the document changed is a semantic question answered by
    state_documents_equal, not a textual one.
    """
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.run",
        description="Diff a Grype report against the committed state file.",
    )
    parser.add_argument("--scan", required=True,
                        help="path to the Grype JSON report")
    parser.add_argument("--state", required=True,
                        help="path to the existing state file; absent means bootstrap")
    parser.add_argument("--out", default=None,
                        help="path to write the updated state document to; "
                             "not used with --write-state")
    parser.add_argument("--dry-run-issues", action="store_true",
                        help="render the issues that would be filed and print "
                             "them; posts nothing")
    parser.add_argument("--message-file", default=None,
                        help="path to write the commit message to, for the "
                             "commit-back step to read")
    parser.add_argument("--write-state", action="store_true",
                        help="update the state file in place instead of writing "
                             "to --out, and only when the document actually changed")
    parser.add_argument("--threshold", default="High",
                        help="severity at or above which a finding would be filed")
    parser.add_argument("--syft-version", default=None,
                        help="Syft version, recorded as provenance; Grype does not report it")
    args = parser.parse_args(argv)
    if not args.write_state and args.out is None:
        parser.error("--out is required unless --write-state is given")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    report = json.loads(Path(args.scan).read_text(encoding="utf-8"))
    current = parse_grype(report)

    previous_state = load_state(args.state)
    previous = None if previous_state is None else findings_from_state(previous_state)
    provenance = {} if previous_state is None else provenance_from_state(previous_state)

    result = diff(previous, current)
    print(summarise(result, args.threshold, args.scan))

    if args.dry_run_issues:
        print()
        print(dry_run(select_for_issues(result, threshold=args.threshold)))
        print()

    # One timestamp for the whole run: state_from_findings derives both dates
    # from it, so a second clock call either side of midnight UTC cannot write
    # a record first seen after it was last seen.
    state = state_from_findings(
        findings_to_record(result),
        provenance=provenance,
        generated_at=utc_now(),
        tooling=tooling_from_grype(report, syft_version=args.syft_version),
    )
    # The workflow builds its commit message from these rather than parsing
    # anything back out of the document.
    message = commit_message(result, state)
    if args.message_file:
        Path(args.message_file).parent.mkdir(parents=True, exist_ok=True)
        Path(args.message_file).write_text(message + "\n", encoding="utf-8",
                                           newline="\n")
        print(f"commit message: {message}")

    _emit_github_output("bootstrap", "true" if result.bootstrap else "false")
    _emit_github_output("recorded", str(len(state["findings"])))
    _emit_github_output("new", str(len(result.new)))
    _emit_github_output("resolved", str(len(result.resolved)))
    _emit_github_output("unchanged", str(len(result.unchanged)))
    _emit_github_output("changed_findings", str(len(result.changed)))
    _emit_github_output("scan_date", state["generated_at"][:10])

    if not args.write_state:
        save_state(args.out, state)
        print(f"state written to {args.out} ({len(state['findings'])} findings)")
        return 0

    # In-place mode. Writing an unchanged document would rewrite generated_at
    # and hand git a diff with no information in it, so compare first and leave
    # the file alone when nothing moved.
    changed = not state_documents_equal(previous_state, state)
    if changed:
        save_state(args.state, state)
        print(f"state written to {args.state} ({len(state['findings'])} findings)")
    else:
        print("no change; nothing committed")
    _emit_github_output("state_changed", "true" if changed else "false")
    return 0


if __name__ == "__main__":
    sys.exit(main())
