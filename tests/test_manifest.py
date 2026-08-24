"""Specification for action.yml as a document GitHub has to load.

Two packaging bugs shipped past a check built on a YAML parser. A parser reads
`${{ ... }}` as ordinary text; GitHub evaluates it. So a manifest can be
perfectly valid YAML, with every path present and every output wired, and still
be rejected before a single step runs.

These tests are deliberately not about any one context name. The bug that
happened used `secrets`; the next one will use something else. They check the
shape of the rules instead: expressions only where expressions belong, contexts
only from the set a composite action actually has, and no keys that are legal
in a workflow but not in an action.

Parsed by hand rather than with PyYAML. This project has no runtime
dependencies and the test suite is not the place to acquire one - and a YAML
parser would discard exactly the distinction under test, which is *where* in
the file an expression appears.
"""
import pathlib
import re

MANIFEST = pathlib.Path(__file__).parents[1] / "action.yml"

# The contexts a composite action can actually resolve. Everything else -
# secrets, job, matrix, needs, vars - exists only in a workflow, and naming one
# here fails the manifest at load time.
COMPOSITE_SAFE_CONTEXTS = {"inputs", "github", "runner", "env", "steps"}

# Legal in a workflow step, rejected in a composite action step.
COMPOSITE_ILLEGAL_KEYS = ("continue-on-error", "timeout-minutes", "strategy",
                          "services")

BLOCK_SCALAR = re.compile(r"^(\s*)([\w-]+):\s*[|>][-+]?\s*$")
MAPPING_KEY = re.compile(r"^(\s*)([\w-]+):\s*$")
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)


class Line:
    """A line of the manifest, with what it sits inside."""

    def __init__(self, number: int, text: str, block: str | None,
                 mapping: str | None):
        self.number = number
        self.text = text
        self.block = block      # the key of the block scalar it belongs to
        self.mapping = mapping  # the key of the nested mapping it belongs to

    def __repr__(self) -> str:
        return f"line {self.number}: {self.text.strip()[:60]}"


def scan(text: str) -> list[Line]:
    """Walk the manifest, tracking which construct each line belongs to.

    Only enough YAML to answer the questions below: block scalars (`run: |`,
    `description: >-`) and one-level mappings (`env:`, `with:`).
    """
    lines: list[Line] = []
    block_key: str | None = None
    block_indent = 0
    mapping_key: str | None = None
    mapping_indent = 0

    for number, raw in enumerate(text.split("\n"), start=1):
        indent = len(raw) - len(raw.lstrip())
        blank = not raw.strip()

        if block_key is not None and not blank and indent <= block_indent:
            block_key = None
        if mapping_key is not None and not blank and indent <= mapping_indent:
            mapping_key = None

        lines.append(Line(number, raw, block_key, mapping_key))

        if block_key is None:
            opened = BLOCK_SCALAR.match(raw)
            if opened:
                block_indent = len(opened.group(1))
                block_key = opened.group(2)
                continue
            nested = MAPPING_KEY.match(raw)
            if nested and nested.group(2) in ("env", "with"):
                mapping_indent = len(nested.group(1))
                mapping_key = nested.group(2)

    return lines


MANIFEST_LINES = scan(MANIFEST.read_text(encoding="utf-8"))


def code_lines() -> list[Line]:
    """Lines that are structure rather than the contents of a block scalar."""
    return [line for line in MANIFEST_LINES if line.block is None]


# --- where expressions are allowed to appear ------------------------------

def test_expressions_appear_only_in_slots_meant_to_hold_them():
    """An expression in prose is not documentation, it is an expression.

    `${{ secrets.GITHUB_TOKEN }}` written inside an input's description as an
    example of what to pass failed the whole manifest at load. The slots that
    legitimately hold expressions are a step's `run` body, an output's `value`,
    a step `if`, and the values of an `env` or `with` mapping. A description,
    a name or a default is prose.
    """
    offenders = []
    for line in MANIFEST_LINES:
        if "${{" not in line.text:
            continue
        if line.block == "run":
            continue                                  # interpolated on purpose
        if line.mapping in ("env", "with"):
            continue                                  # the documented slots
        if re.match(r"^\s*(value|if):\s", line.text):
            continue
        offenders.append(line)

    assert not offenders, (
        "expressions outside an expression slot - GitHub evaluates these:\n  "
        + "\n  ".join(map(repr, offenders))
    )


def test_no_expression_hides_inside_a_prose_block():
    """The specific shape of the bug: a folded or literal scalar holding
    documentation, with an expression inside it."""
    offenders = [line for line in MANIFEST_LINES
                 if "${{" in line.text and line.block not in (None, "run")]
    assert not offenders, (
        "expressions inside a prose block scalar:\n  "
        + "\n  ".join(f"{line!r} (inside {line.block}:)" for line in offenders)
    )


# --- which contexts may be named ------------------------------------------

def test_every_referenced_context_exists_in_a_composite_action():
    """Not a check for one forbidden name. A composite action resolves a fixed
    set of contexts; anything outside it fails at load, whichever it is."""
    referenced = {}
    for line in MANIFEST_LINES:
        for expression in EXPRESSION.findall(line.text):
            # Only the leading identifier of a dotted path is a context.
            # In steps.diff.outputs.new, "diff" and "outputs" are not
            # contexts and must not be judged as if they were.
            for root in re.findall(r"(?<![\w.])([a-z][a-z_]*)\.", expression):
                referenced.setdefault(root, line)

    unsafe = {root: line for root, line in referenced.items()
              if root not in COMPOSITE_SAFE_CONTEXTS}

    assert not unsafe, (
        "contexts a composite action cannot resolve:\n  "
        + "\n  ".join(f"{root!r} at {line!r}" for root, line in unsafe.items())
    )
    assert referenced, "found no expressions at all - has the scan broken?"


# --- keys that are legal in a workflow but not in an action ---------------

def test_no_composite_illegal_keys():
    """watchdog.yml uses continue-on-error legitimately. Copying that pattern
    into the action would fail at load, and the two files look alike enough
    that someone will try."""
    offenders = []
    for line in code_lines():
        for key in COMPOSITE_ILLEGAL_KEYS:
            if re.match(rf"^\s*{re.escape(key)}\s*:", line.text):
                offenders.append((key, line))

    assert not offenders, (
        "keys a composite action rejects:\n  "
        + "\n  ".join(f"{key} at {line!r}" for key, line in offenders)
    )


# --- every run step declares a shell --------------------------------------

def steps() -> list[list[Line]]:
    """The manifest's steps, each as the lines belonging to it."""
    starts = [i for i, line in enumerate(MANIFEST_LINES)
              if line.block is None and re.match(r"^\s{4}- ", line.text)]
    grouped = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(MANIFEST_LINES)
        grouped.append(MANIFEST_LINES[start:end])
    return grouped


def test_the_scan_actually_found_the_steps():
    """A structural test that silently matches nothing passes forever."""
    found = steps()
    assert len(found) >= 5, f"only found {len(found)} steps; the scan is wrong"


def test_every_run_step_declares_a_shell():
    """A run step without `shell` fails the manifest at load. It is the easiest
    thing to forget when adding a step, because a workflow does not need it."""
    offenders = []
    for step in steps():
        structural = [line for line in step if line.block is None]
        has_run = any(re.match(r"^\s*run:", line.text) for line in structural)
        has_shell = any(re.match(r"^\s*shell:", line.text) for line in structural)
        if has_run and not has_shell:
            offenders.append(step[0])

    assert not offenders, (
        "run steps with no shell declared:\n  " + "\n  ".join(map(repr, offenders))
    )


# --- the inputs the manifest promises are the ones it uses ----------------

def test_every_referenced_input_is_declared():
    declared = set()
    inside_inputs = False
    for line in code_lines():
        if re.match(r"^inputs:\s*$", line.text):
            inside_inputs = True
            continue
        if re.match(r"^\S", line.text):
            inside_inputs = False
        if inside_inputs:
            declared_name = re.match(r"^\s{2}([\w-]+):\s*$", line.text)
            if declared_name:
                declared.add(declared_name.group(1))

    used = set(re.findall(r"inputs\.([\w-]+)", MANIFEST.read_text(encoding="utf-8")))

    assert declared, "found no declared inputs - the scan is wrong"
    assert not (used - declared), (
        f"inputs referenced but never declared: {sorted(used - declared)}"
    )
