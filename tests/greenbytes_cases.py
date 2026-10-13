"""Read the greenbytes httpauth test page into cases (see tests/upstream/MANIFEST.json).

Each case on the page shows WWW-Authenticate field lines, a CSS class that marks parse
errors and invalid syntax, and one table per challenge with the scheme, parameter names
and values after post-processing (lower-cased names, unquoted values).
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

_CASE = re.compile(r'<div id="([a-z0-9]+)">(.*?)</div>', re.DOTALL)
_PRE = re.compile(r'<pre(?: class="(\w+)")?>(.*?)</pre>', re.DOTALL)
_TABLE = re.compile(r"After post-processing.*?<tbody>(.*?)</tbody>", re.DOTALL)
_RAW_TABLE = re.compile(r'<table class="extracted">.*?<tbody>(.*?)</tbody>', re.DOTALL)
_QUOTED_PAIR = re.compile(r"\\(.)")
_ROW = re.compile(r"<tr>(.*?)</tr>", re.DOTALL)
_CELL = re.compile(r"<td>(.*?)</td>", re.DOTALL)
FIELD = "WWW-Authenticate:"


@dataclass(frozen=True)
class Case:
    """One test case: its id, the field values, the page's verdict and expected parse."""

    name: str
    values: tuple[str, ...]
    verdict: str
    expected: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]


def _text(fragment: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", fragment))


def _values(pre: str) -> tuple[str, ...]:
    values: list[str] = []
    for line in _text(pre).split("\n"):
        if line.startswith(FIELD):
            values.append(line[len(FIELD) :].lstrip(" "))
        elif line[:1] in (" ", "\t") and values:
            values[-1] += "\r\n" + line
    return tuple(values)


def _post_process(value: str) -> str:
    # Written for this suite: the page gives raw values only for invalid syntax.
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return _QUOTED_PAIR.sub(r"\1", value[1:-1])
    return value


def _expected(block: str) -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    tables = _TABLE.findall(block)
    raw = not tables
    challenges = []
    for table in _RAW_TABLE.findall(block) if raw else tables:
        rows = [[_text(cell) for cell in _CELL.findall(row)] for row in _ROW.findall(table)]
        params = tuple(
            (name.lower(), _post_process(value)) if raw else (name, value)
            for _, name, value in rows
            if name
        )
        challenges.append((rows[0][0].lower(), params))
    return tuple(challenges)


def load(page: str) -> list[Case]:
    """Every case of the page that shows a field value."""
    cases = []
    for name, block in _CASE.findall(page):
        pre = _PRE.search(block)
        assert pre is not None, name
        values = _values(pre.group(2))
        if values:
            cases.append(Case(name, values, pre.group(1) or "valid", _expected(block)))
    return cases
