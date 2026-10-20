"""Character classes and quoting of RFC 9110: token, token68, quoted-string, field text."""

from __future__ import annotations

import re
from typing import Any

# tchar of RFC 9110 section 5.6.2: auth-scheme and auth-param names are tokens.
TCHAR = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
# token68 of RFC 9110 section 11.2, without its trailing "=" padding.
TOKEN68_CHARS = "-._~+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

_TCHAR_CLASS = "[" + re.escape(TCHAR) + "]"
TOKEN_RE = _TCHAR_CLASS + "+"
TOKEN68_RE = "[" + re.escape(TOKEN68_CHARS) + "]+=*"
QUOTED_RE = r'"(?:[^"\\]|\\.)*"'
_TOKEN = re.compile(TOKEN_RE)
_TOKEN68 = re.compile(TOKEN68_RE)
_QUOTED_PAIR = re.compile(r"\\(.)", re.DOTALL)


def is_token(value: str) -> bool:
    """Whether the value is a non-empty RFC 9110 token."""
    return _TOKEN.fullmatch(value) is not None


def is_token68(value: str) -> bool:
    """Whether the value is an RFC 9110 token68 (letters, digits, -._~+/ then padding)."""
    return _TOKEN68.fullmatch(value) is not None


def is_field_text(value: str) -> bool:
    """Whether a sender may write the value: HTAB, SP and visible US-ASCII only.

    RFC 9110 section 5.5 asks new fields to stay within VCHAR, SP and HTAB. Anything else,
    CR and LF above all, would let a value break out of the header line.
    """
    return all(char == "\t" or " " <= char <= "~" for char in value)


def bad_octet(value: str) -> int | None:
    """Offset of the first character a field value cannot hold, or None.

    Field values are octets: HTAB, SP, VCHAR and obs-text (0x80 to 0xFF). Controls, DEL
    and code points above 0xFF are refused.
    """
    for index, char in enumerate(value):
        code = ord(char)
        if (code < 0x20 and char != "\t") or code == 0x7F or code > 0xFF:
            return index
    return None


def quote(value: str) -> str:
    """Wrap the value in a quoted-string, escaping only backslash and double quote."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def unquote(value: str) -> str:
    """Strip the quotes of a quoted-string and resolve its quoted-pairs."""
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return _QUOTED_PAIR.sub(r"\1", value[1:-1])
    return value


def shown(value: str, limit: int = 40) -> str:
    """Quote a value for an error message, cut to `limit` characters so input never floods it."""
    return repr(value if len(value) <= limit else value[:limit] + "...")


def need_str(value: Any, what: str) -> str:
    """Return the value if it is a str, else raise TypeError naming the argument."""
    if not isinstance(value, str):
        raise TypeError(f"{what} must be a str, not {type(value).__name__}")
    return value
