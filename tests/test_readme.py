"""The README makes no compliance claim the tool cannot back.

sbom-watchdog helps produce evidence for part of the vulnerability handling
the EU Cyber Resilience Act asks of manufacturers. It does not make a product
compliant, its SBOM is a source SBOM that meets only part of BSI TR-03183-2,
and it reports nothing to ENISA. A README that drifts into "CRA-compliant" is
the security-tool equivalent of a severity rounded down: wrong in the
direction that hurts the person relying on it.

The banned phrases are exact. The word "compliant" alone stays legal, because
the honest sentence is "does not make a product compliant".
"""
import pathlib
import re

README = pathlib.Path(__file__).parents[1] / "README.md"

OVERCLAIMS = (
    "cra-compliant",
    "cra compliant",
    "cra-ready",
    "cra ready",
    "compliance output",
    "tr-03183-compliant",
    "tr-03183 compliant",
    "conformant sbom",
    "ensures compliance",
    "guarantees compliance",
)


def text() -> str:
    return README.read_text(encoding="utf-8")


def prose() -> str:
    """The README with line wrapping undone, for sentences that span lines."""
    return " ".join(text().split())


def test_no_overclaiming_phrase_appears():
    lowered = text().lower()
    found = [phrase for phrase in OVERCLAIMS if phrase in lowered]
    assert not found, f"README overclaims: {found}"


def test_the_cra_section_and_its_limits_exist():
    readme = text()
    assert "## The Cyber Resilience Act" in readme
    assert "does not make a product compliant" in prose()
    assert "not legal advice" in prose()


def test_article_14_is_listed_as_not_covered():
    row = next(line for line in text().splitlines() if line.startswith("| Art. 14"))
    assert "Not covered" in row


def test_the_sbom_is_described_with_its_gaps():
    readme = text()
    assert "### What the SBOM is and is not" in readme
    assert re.search(r"source\*? SBOM", readme)
    assert "BSI TR-03183-2" in readme


def test_the_evidence_files_heading_replaced_the_old_one():
    assert "## The evidence files" in text()


def test_the_dependabot_comparison_says_where_dependabot_is_better():
    """The section exists to be fair. If it stops naming what Dependabot does
    that this tool does not, it has turned into a sales pitch."""
    readme = prose()
    assert "## Why not Dependabot alerts?" in text()
    assert "Use them as well" in readme
    assert "fixes nothing" in readme
