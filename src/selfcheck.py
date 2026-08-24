"""Startup sanity check for the packaged action.

An adopter gets `src/` and no test suite. If a future Grype moves a field the
parser reads, `parse_grype` returns fewer findings — or none — and the run
reports a clean scan. A clean scan and a broken parser look identical from the
outside, which is the worst possible failure for this tool.

So the action parses a captured Grype document at startup and asserts it still
yields the number of findings it yielded when it was captured. That turns a
silent misparse into a loud one, before anything decides there is nothing to
report.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .model import parse_grype

__all__ = ["check", "main"]

MINIMUM_PYTHON = (3, 11)
EXPECTED_FINDINGS = 22


def check(fixture: Path, expected: int = EXPECTED_FINDINGS) -> list[str]:
    """Return a list of problems. Empty means the parser is behaving."""
    problems: list[str] = []

    if sys.version_info < MINIMUM_PYTHON:
        problems.append(
            f"Python {'.'.join(map(str, MINIMUM_PYTHON))} or newer is required; "
            f"this runner has {sys.version.split()[0]}. Add actions/setup-python "
            f"before this action."
        )
        return problems

    try:
        report = json.loads(fixture.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        problems.append(f"could not read the bundled sample at {fixture}: {exc}")
        return problems

    captured = (report.get("descriptor") or {}).get("version", "unknown")

    try:
        findings = parse_grype(report)
    except Exception as exc:  # noqa: BLE001 - any parse failure is the problem
        problems.append(
            f"the parser raised on a Grype {captured} document: "
            f"{type(exc).__name__}: {exc}"
        )
        return problems

    if len(findings) != expected:
        problems.append(
            f"the parser found {len(findings)} findings in the bundled Grype "
            f"{captured} sample, expected {expected}. The Grype JSON schema has "
            f"probably moved. Do not trust this run: a misparse reports a clean "
            f"scan."
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.selfcheck",
        description="Assert the Grype parser still works before scanning.",
    )
    parser.add_argument("--fixture", required=True,
                        help="path to the captured Grype document")
    parser.add_argument("--expect", type=int, default=EXPECTED_FINDINGS,
                        help="number of findings the sample should yield")
    args = parser.parse_args(argv)

    problems = check(Path(args.fixture), args.expect)
    for problem in problems:
        print(f"::error::sbom-watchdog self-check failed: {problem}")
    if problems:
        return 1

    print(f"self-check passed: the bundled sample still parses to "
          f"{args.expect} findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
