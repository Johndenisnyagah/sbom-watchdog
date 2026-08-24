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
from .issues import (
    close_comment,
    close_issue,
    create_issue,
    dry_run,
    ensure_labels,
    find_existing_issue,
    render_issue,
)
from .model import Finding, parse_grype
from .report import write_inventory, write_sbom_history
from .state import (
    findings_from_state,
    load_state,
    provenance_from_state,
    resolved_from_state,
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


def _print(text: str) -> None:
    """Print text the console may not be able to encode.

    Rendered issue bodies contain typographic characters. The body posted to
    GitHub is UTF-8 regardless; this only protects the local dry-run print,
    because a status print must never be the thing that fails a scan.
    """
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "ascii"
        print(text.encode(encoding, "replace").decode(encoding))


def file_issues(selected, repo: str, token: str, provenance: dict,
                findings=None) -> tuple[dict[str, int], Exception | None]:
    """File an issue per selected finding. Returns (key -> number, error).

    `provenance` is updated in place as each number is obtained, which does two
    jobs. It closes the within-run duplicate window for free: GitHub's search
    index is eventually consistent and can miss an issue created seconds ago,
    but a number already recorded in this process cannot be missed. And it
    means a partial failure still leaves the numbers where the state document
    will pick them up.

    CLAUDE.md fixes the order as scan, diff, create issues, write issue
    numbers, commit. An issue that was created but whose number never reached
    state gets filed again tomorrow, so the numbers must survive any failure
    here.
    """
    filed: dict[str, int] = {}
    try:
        for finding in selected:
            entry = provenance.setdefault(
                finding.key, {"first_seen": None, "issue_number": None})

            recorded = entry.get("issue_number")
            if recorded:
                print(f"  #{recorded} already recorded for {finding.key}; not filing again")
                filed[finding.key] = recorded
                continue

            existing = find_existing_issue(repo, finding.key, token)
            if existing is not None:
                print(f"  #{existing} already exists for {finding.key}")
                entry["issue_number"] = existing
                filed[finding.key] = existing
                continue

            title, body, labels = render_issue(
                finding, findings, provenance.get(finding.key))
            # ensure_labels returns only what can actually be applied; a token
            # without label permission still gets the issue filed.
            usable = ensure_labels(repo, labels, token)
            number = create_issue(repo, title, body, usable, token)
            print(f"  filed #{number} for {finding.key}")
            entry["issue_number"] = number
            filed[finding.key] = number
    # Deliberately broad. Whatever went wrong - a network error, a 500, a
    # token losing its scope halfway through - the numbers collected so far
    # must still reach the state file, or every issue already created gets
    # filed again tomorrow.
    except Exception as exc:  # noqa: BLE001
        return filed, exc
    return filed, None


def close_resolved_issues(result: DiffResult, current, repo: str, token: str,
                          provenance: dict) -> int:
    """Close the issues of findings that are no longer reported.

    A close failure never fails the run. The state write matters more: a stale
    open issue is visible and recoverable, where a lost issue number is not.
    """
    closed = 0
    for key, finding in result.resolved.items():
        number = (provenance.get(key) or {}).get("issue_number")
        if not number:
            continue

        # If the package still appears in the scan, say which version is now
        # installed. A fully resolved package has no findings left to ask.
        installed = next(
            (", ".join(other.versions) for other in current.values()
             if other.package_name == finding.package_name
             and other.package_type == finding.package_type),
            None,
        )
        try:
            close_issue(repo, number, close_comment(finding, installed), token)
            print(f"  closed #{number} for {key}")
            closed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  could not close #{number} for {key}: {exc}")
    return closed


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
    lines.append(f"{len(selected)} finding(s) at or above threshold {threshold}")
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
    issues_mode = parser.add_mutually_exclusive_group()
    issues_mode.add_argument("--dry-run-issues", action="store_true",
                             help="render the issues that would be filed and "
                                  "print them; posts nothing")
    issues_mode.add_argument("--file-issues", action="store_true",
                             help="actually create issues; needs --repo and "
                                  "GITHUB_TOKEN in the environment")
    parser.add_argument("--repo", default=None,
                        help="owner/name of the repository to file issues in")
    parser.add_argument("--sbom", default=None,
                        help="the CycloneDX SBOM the scan produced, copied into "
                             "the dated history when --sbom-history is given")
    parser.add_argument("--sbom-history", default=None,
                        help="directory to write the dated SBOM copy into; "
                             "omitted means no history is written")
    parser.add_argument("--inventory", default=None,
                        help="path to write SECURITY-INVENTORY.md to; omitted "
                             "means no inventory is written")
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
    if args.file_issues and not args.repo:
        parser.error("--file-issues needs --repo owner/name")
    if args.sbom_history and not args.sbom:
        parser.error("--sbom-history needs --sbom, the file to copy")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    report = json.loads(Path(args.scan).read_text(encoding="utf-8"))
    current = parse_grype(report)

    previous_state = load_state(args.state)
    previous = None if previous_state is None else findings_from_state(previous_state)
    provenance = {} if previous_state is None else provenance_from_state(previous_state)
    previously_resolved = (
        {} if previous_state is None else resolved_from_state(previous_state))

    result = diff(previous, current)
    print(summarise(result, args.threshold, args.scan))

    if args.dry_run_issues:
        print()
        _print(dry_run(select_for_issues(result, threshold=args.threshold),
                      current, provenance))
        print()

    filing_error = None
    if args.file_issues:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            print("GITHUB_TOKEN is not set; refusing to file issues")
            return 1
        selected = select_for_issues(result, threshold=args.threshold)
        print(f"\nfiling {len(selected)} issue(s) in {args.repo}")
        # provenance is updated in place, before the state document is built,
        # so the numbers land in the state this run commits rather than the
        # next one.
        filed, filing_error = file_issues(selected, args.repo, token,
                                          provenance, current)
        print(f"recorded {len(filed)} issue number(s) into state")

        if result.resolved:
            closed = close_resolved_issues(result, current, args.repo, token,
                                           provenance)
            print(f"closed {closed} issue(s) for resolved findings")

    # One timestamp for the whole run: state_from_findings derives both dates
    # from it, so a second clock call either side of midnight UTC cannot write
    # a record first seen after it was last seen.
    # Previously-resolved records stay in the document, joined by whatever
    # resolved on this run. A record present again is current, not resolved:
    # state_from_findings drops it from the resolved set for us.
    resolved = dict(previously_resolved)
    resolved.update(result.resolved)

    state = state_from_findings(
        findings_to_record(result),
        provenance=provenance,
        generated_at=utc_now(),
        tooling=tooling_from_grype(report, syft_version=args.syft_version),
        resolved=resolved,
    )
    # The workflow builds its commit message from these rather than parsing
    # anything back out of the document.
    # Compliance outputs, both opt-in. Skipped on a dry run for the same
    # reason the state write is: a preview that leaves files behind in
    # somebody's repository is not a preview.
    wrote_files = False
    if not args.dry_run_issues:
        if args.sbom_history:
            written = write_sbom_history(Path(args.sbom), args.sbom_history,
                                         state["generated_at"])
            if written is None:
                # The day is already recorded. Rewriting would commit a changed
                # UUID and turn the day's record into the last scan of that day.
                print(f"SBOM history: {state['generated_at'][:10]} already "
                      f"recorded; left as it is")
            else:
                print(f"SBOM history: {written}")
                _emit_github_output("sbom_path", str(written))
                wrote_files = True
        if args.inventory:
            written = write_inventory(args.inventory, state)
            if written is None:
                print(f"inventory: {args.inventory} already up to date")
            else:
                print(f"inventory: {written}")
                _emit_github_output("inventory_path", str(written))
                wrote_files = True

    message = commit_message(result, state)
    if args.message_file:
        Path(args.message_file).parent.mkdir(parents=True, exist_ok=True)
        Path(args.message_file).write_text(message + "\n", encoding="utf-8",
                                           newline="\n")
        print(f"commit message: {message}")
    # Also an output, so an adopter's commit step never rebuilds this
    # text in shell. That is how a baseline once shipped as "no change
    # (scan of )": the message is permanent, so it is built in one place.
    _emit_github_output("commit_message", message)

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
        if filing_error is not None:
            print(f"issue creation failed: {filing_error}")
            return 1
        return 0

    # A dry run previews and writes nothing. Recording a baseline here would
    # permanently consume the one bootstrap a repository gets: every finding
    # would be "already known" from then on, and the first real run would file
    # nothing. A preview that changes what the next run does is not a preview.
    if args.dry_run_issues:
        print("dry run: the state file was not written, so the bootstrap is "
              "still available to a real run")
        _emit_github_output("state_changed", "false")
        _emit_github_output("should_commit", "false")
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
    # Two outputs because they are two different facts. `state_changed` says
    # the vulnerability state moved. `should_commit` says there is something to
    # write, which is also true when nothing moved but a dated SBOM was
    # produced. A repository with no findings never moves, and gating its commit
    # on the first would leave its audit trail empty - the readership the trail
    # exists for.
    _emit_github_output("state_changed", "true" if changed else "false")
    _emit_github_output("should_commit",
                        "true" if (changed or wrote_files) else "false")
    if filing_error is not None:
        print(f"issue creation failed: {filing_error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
