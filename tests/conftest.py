from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

UPSTREAM = Path(__file__).resolve().parent / "upstream"


def read_upstream(name: str, encoding: str = "utf-8") -> str:
    """Return a third-party reference file as text.

    The files are not committed: `python scripts/fetch_upstream.py` fetches them. Their
    tests skip while a file is absent and fail if it differs from the manifest.
    """
    path = UPSTREAM / name
    if not path.is_file():
        pytest.skip(f"{name} is not fetched; run python scripts/fetch_upstream.py")
    entry = json.loads((UPSTREAM / "MANIFEST.json").read_text(encoding="utf-8"))[name]
    body = path.read_bytes()
    assert hashlib.sha256(body).hexdigest() == entry["sha256"], f"{name} differs from MANIFEST"
    return body.decode(encoding)


def unpaginated(text: str) -> str:
    """Drop the page footers, headers and form feeds of an RFC so sections read as one block."""
    footer = re.compile(r"^(RFC \d{4} .*\S\s{2,}\S.*|.*\[Page \d+\])$")
    return "\n".join(
        line for line in text.splitlines() if "\f" not in line and not footer.match(line)
    )


def section(text: str, start: str, end: str) -> str:
    """The text between two headings that start a line (contents lines are indented)."""
    body = text.split("\n" + start, 1)[1]
    return body.split("\n" + end, 1)[0]


def field_lines(text: str, name: str) -> list[str]:
    """Field values of `name` in an RFC example, joined across its indented lines.

    A line break inside a quoted-string is an artefact of the page width and is dropped;
    elsewhere it stands for the space that separates list elements.
    """
    values: list[str] = []
    current: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(name + ":"):
            if current is not None:
                values.append(current)
            current = stripped[len(name) + 1 :].strip()
        elif current is not None and stripped and line.startswith("     "):
            inside_quote = len(re.findall(r'(?<!\\)"', current)) % 2 == 1
            current += stripped if inside_quote else " " + stripped
        elif current is not None:
            values.append(current)
            current = None
    if current is not None:
        values.append(current)
    return values


def rfc(number: int) -> str:
    return unpaginated(read_upstream(f"rfc{number}.txt"))


@pytest.fixture(scope="session")
def rfc9110() -> str:
    """RFC 9110, see tests/upstream/MANIFEST.json for its source."""
    return rfc(9110)


@pytest.fixture(scope="session")
def rfc7616() -> str:
    """RFC 7616, see tests/upstream/MANIFEST.json for its source."""
    return rfc(7616)


@pytest.fixture(scope="session")
def rfc7617() -> str:
    """RFC 7617, see tests/upstream/MANIFEST.json for its source."""
    return rfc(7617)


@pytest.fixture(scope="session")
def rfc6750() -> str:
    """RFC 6750, see tests/upstream/MANIFEST.json for its source."""
    return rfc(6750)
