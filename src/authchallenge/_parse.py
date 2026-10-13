"""Parse WWW-Authenticate, Authorization and Authentication-Info field values (RFC 9110)."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TypeVar

from ._model import AuthError, Challenge, Credentials
from ._scan import Item, Param, classify, fail, prepare, split
from ._schemes import check

_T = TypeVar("_T")


@dataclass
class _Draft:
    scheme: str
    offset: int
    token68: str | None
    open: bool
    params: dict[str, Param] = field(default_factory=dict)

    def values(self) -> dict[str, str]:
        return {name: param.value for name, param in self.params.items()}


def _items(value: str, strict: bool) -> list[list[Item]]:
    """Items of each line. Strict mode refuses line breaks; tolerant mode reads a bare one
    (not obs-fold) as the end of a field line, so the next line keeps its challenges."""
    text = prepare(value, strict)
    lines = [text] if strict else text.replace("\r\n", "\n").split("\n")
    result: list[list[Item]] = []
    for line in lines:
        parts, open_quote = split(line)
        if strict and open_quote is not None:
            raise fail("unterminated quoted-string", open_quote)
        items = [classify(offset, raw, strict) for offset, raw in parts]
        if strict:
            for item in items:
                if item.error:
                    raise fail(item.error, item.error_at)
        result.append(items)
    return result


def _add(params: dict[str, Param], param: Param, strict: bool) -> None:
    if param.name in params:
        if strict:
            raise fail(f"duplicate auth-param {param.name!r}", param.offset)
        return  # the first one wins, as most user agents do
    params[param.name] = param


def _step(drafts: list[_Draft], start: int, item: Item, strict: bool) -> None:
    if item.kind == "challenge":
        drafts.append(_Draft(item.scheme, item.offset, item.token68, item.open))
        if item.param is not None:
            _add(drafts[-1].params, item.param, strict)
    elif item.kind == "param" and item.param is not None:
        current = drafts[-1] if len(drafts) > start else None
        if current is None or current.token68 is not None or not current.open:
            if strict:
                raise fail(f"auth-param {item.param.name!r} outside a challenge", item.offset)
            if current is None or current.token68 is not None:
                return
        current.open = True
        _add(current.params, item.param, strict)


def _drafts(value: str, strict: bool) -> list[_Draft]:
    drafts: list[_Draft] = []
    for line in _items(value, strict):
        start = len(drafts)  # a challenge never continues on the next line
        for item in line:
            _step(drafts, start, item, strict)
    return drafts


def _checked(draft: _Draft, kind: str, strict: bool) -> _Draft:
    if strict:
        try:
            check(draft.scheme, kind, draft.token68, list(draft.params.values()))
        except AuthError as error:
            raise AuthError(f"{error}, in the {kind} at offset {draft.offset}") from None
    return draft


def _each_line(value: str | Iterable[str], read: Callable[[str], _T]) -> list[_T]:
    lines = [value] if isinstance(value, str) else list(value)
    results: list[_T] = []
    for number, line in enumerate(lines, 1):
        try:
            results.append(read(line))
        except AuthError as error:
            if len(lines) == 1:
                raise
            raise AuthError(f"{error} (field line {number})") from None
    return results


def parse_challenges(value: str | Iterable[str], *, strict: bool = False) -> list[Challenge]:
    """Parse WWW-Authenticate or Proxy-Authenticate field values into their challenges.

    Pass one field value or an iterable of them (the field may occur several times).
    By default parsing is tolerant: malformed parts are skipped and the first of two
    params with the same name wins. With `strict=True` anything RFC 9110, RFC 7617,
    RFC 7616 or RFC 6750 forbids raises `AuthError` with the reason and offset.
    """

    def read(line: str) -> list[Challenge]:
        drafts = [_checked(d, "challenge", strict) for d in _drafts(line, strict)]
        return [Challenge(d.scheme, d.token68, d.values()) for d in drafts]

    challenges = [c for found in _each_line(value, read) for c in found]
    if strict and not challenges:
        raise AuthError("the field holds no challenge")
    return challenges


def parse_authorization(value: str, *, strict: bool = False) -> Credentials:
    """Parse an Authorization or Proxy-Authorization field value.

    Tolerant mode returns the first credentials found, or `Credentials("")` if none.
    Strict mode raises `AuthError` unless the value is exactly one valid credentials.
    """
    drafts = _drafts(value, strict)
    if strict:
        if not drafts or value.strip(" \t")[: len(drafts[0].scheme)] != drafts[0].scheme:
            raise AuthError("the field must start with an auth-scheme")
        if len(drafts) > 1:
            raise fail("only one credentials is allowed", drafts[1].offset)
        token68 = drafts[0].token68
        if token68 is not None and not value.rstrip(" \t").endswith(token68):
            raise AuthError("nothing may follow the token68 of credentials")
    if not drafts:
        return Credentials("")
    draft = _checked(drafts[0], "credentials", strict)
    return Credentials(draft.scheme, draft.token68, draft.values())


def parse_auth_info(
    value: str | Iterable[str], *, strict: bool = False, scheme: str | None = None
) -> dict[str, str]:
    """Parse Authentication-Info or Proxy-Authentication-Info, a list of auth-params.

    Names are lower-cased and the first of two equal names wins. Strict mode refuses
    anything but auth-params and, given the `scheme` of the request's credentials,
    applies its rules (Digest: quoting, `nc`, and rspauth, cnonce and nc with qop).
    """
    params: dict[str, Param] = {}

    def read(line: str) -> None:
        for items in _items(line, strict):
            for item in items:
                if item.kind == "param" and item.param is not None:
                    _add(params, item.param, strict)
                elif item.kind != "empty" and strict:
                    raise fail("expected an auth-param", item.offset)

    _each_line(value, read)
    if strict and scheme is not None:
        try:
            check(scheme, "info", None, list(params.values()))
        except AuthError as error:
            raise AuthError(f"{error}, in the {scheme} Authentication-Info") from None
    return {name: param.value for name, param in params.items()}
