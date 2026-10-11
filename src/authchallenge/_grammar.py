"""Low-level RFC 7235 / RFC 7230 grammar: tchar, token68, quoting, list splitting."""

from __future__ import annotations

import re

# tchar, the character set of an RFC 7230 token (auth-scheme and auth-param names).
TCHAR = r"!#$%&'*+\-.^_`|~0-9A-Za-z"
_TOKEN = re.compile(f"[{TCHAR}]+")
# token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=".
_TOKEN68 = re.compile(r"[A-Za-z0-9\-._~+/]+=*")


def is_token(value: str) -> bool:
    """Whether the value is a valid RFC 7230 token."""
    return bool(value) and _TOKEN.fullmatch(value) is not None


def is_token68(value: str) -> bool:
    """Whether the value is a valid RFC 7235 token68 (base64-style with trailing padding)."""
    return bool(value) and _TOKEN68.fullmatch(value) is not None


def quote(value: str) -> str:
    """Wrap the value in a quoted-string, escaping backslashes and double quotes."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def quote_if_needed(value: str) -> str:
    """Emit the value bare when it is a token, otherwise as a quoted-string."""
    return value if is_token(value) else quote(value)


def unquote(value: str) -> str:
    """Strip the surrounding quotes of a quoted-string and unescape its contents."""
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return re.sub(r"\\(.)", r"\1", value[1:-1])
    return value


def split_list(header: str) -> list[str]:
    """Split a header on top-level commas, leaving commas inside quoted strings intact."""
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    escaped = False
    for ch in header:
        if escaped:
            buf.append(ch)
            escaped = False
        elif in_quote and ch == "\\":
            buf.append(ch)
            escaped = True
        elif ch == '"':
            in_quote = not in_quote
            buf.append(ch)
        elif ch == "," and not in_quote:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts
