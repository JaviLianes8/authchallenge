"""Split a field value into list elements and classify each one (RFC 9110 sections 5.6, 11)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ._grammar import QUOTED_RE, TOKEN_RE, bad_octet, is_token68, unquote
from ._model import AuthError

_PARAM = re.compile(rf"({TOKEN_RE})[ \t]*=[ \t]*({QUOTED_RE}|{TOKEN_RE})", re.DOTALL)
_SCHEME = re.compile(TOKEN_RE)
# obs-fold of RFC 9112 section 5.2: a line break followed by whitespace.
_OBS_FOLD = re.compile(r"[ \t]*\r?\n[ \t]+")


@dataclass(frozen=True)
class Param:
    """One auth-param as read: lower-cased name, unquoted value, how it was written."""

    name: str
    value: str
    quoted: bool
    offset: int


@dataclass
class Item:
    """One list element: empty, an auth-param, the start of a challenge, or junk."""

    offset: int
    kind: str
    scheme: str = ""
    token68: str | None = None
    param: Param | None = None
    open: bool = False
    error: str = ""
    error_at: int = 0


def fail(reason: str, offset: int) -> AuthError:
    """Build the error strict parsing raises, pointing at the offending offset."""
    return AuthError(f"{reason} at offset {offset}")


def prepare(value: str, strict: bool) -> str:
    """Unfold obs-fold and, in strict mode, refuse it and any character a field cannot hold."""
    if strict:
        fold = _OBS_FOLD.search(value)
        if fold is not None:
            raise fail("obsolete line folding", fold.start())
        bad = bad_octet(value)
        if bad is not None:
            raise fail(f"character {value[bad]!r} is not allowed in a field value", bad)
        return value
    return _OBS_FOLD.sub(" ", value)


def split(text: str) -> tuple[list[tuple[int, str]], int | None]:
    """Split on commas outside quoted-strings; also return where an open quote started."""
    parts: list[tuple[int, str]] = []
    start = 0
    quote_at: int | None = None
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif quote_at is not None and char == "\\":
            escaped = True
        elif char == '"':
            quote_at = index if quote_at is None else None
        elif char == "," and quote_at is None:
            parts.append((start, text[start:index]))
            start = index + 1
    parts.append((start, text[start:]))
    return parts, quote_at


def _param(match: re.Match[str], offset: int) -> Param:
    raw = match.group(2)
    return Param(match.group(1).lower(), unquote(raw), raw.startswith('"'), offset)


def _read_param(item: Item, text: str, offset: int) -> bool:
    """Fill item.param from text; record junk after the value. False if no param starts."""
    match = _PARAM.match(text)
    if match is None:
        return False
    item.param = _param(match, offset)
    if match.end() != len(text):
        item.error = f"unexpected text after the value of {item.param.name!r}"
        item.error_at = offset + match.end()
    return True


def classify(offset: int, raw: str, strict: bool) -> Item:
    """Classify one list element; malformed elements carry an error for strict mode."""
    text = raw.strip(" \t")
    at = offset + len(raw) - len(raw.lstrip(" \t"))
    item = Item(at, "empty")
    if not text:
        return item
    if _read_param(item, text, at):
        item.kind = "param"
        return item
    scheme = _SCHEME.match(text)
    after = text[scheme.end() :] if scheme else ""
    if scheme is None or after.lstrip(" \t").startswith("="):
        item.kind, item.error, item.error_at = "junk", "expected an auth-scheme or auth-param", at
        return item
    item.kind, item.scheme = "challenge", scheme.group()
    gap = raw.lstrip(" \t")[scheme.end() :]
    rest = after.lstrip(" \t")
    space = gap[: len(gap) - len(gap.lstrip(" \t"))]
    item.open = space != "" and (" " in space if strict else True)
    if space == "" and after:
        item.error, item.error_at = "expected a space after the auth-scheme", at + scheme.end()
        return item
    if not rest:
        return item
    rest_at = at + len(text) - len(rest)
    if is_token68(rest):
        item.token68, item.open = rest, False
    elif not _read_param(item, rest, rest_at):
        item.error, item.error_at = "expected a token68 or an auth-param", rest_at
    if "\t" in space:
        item.error, item.error_at = "the auth-scheme must be followed by spaces", at + scheme.end()
    return item
