"""Group the classified list elements of a field into challenges, line by line (RFC 9110)."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TypeVar

from ._grammar import need_str, shown
from ._model import AuthError
from ._scan import Item, Param, classify, fail, prepare, split
from ._schemes import check

_T = TypeVar("_T")


@dataclass
class Draft:
    scheme: str
    offset: int
    token68: str | None
    open: bool
    params: dict[str, Param] = field(default_factory=dict)

    def values(self) -> dict[str, str]:
        return {name: param.value for name, param in self.params.items()}


def line_items(value: str, strict: bool) -> list[list[Item]]:
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


def add_param(params: dict[str, Param], param: Param, strict: bool) -> None:
    if param.name in params:
        if strict:
            raise fail(f"duplicate auth-param {shown(param.name)}", param.offset)
        return  # the first one wins, as most user agents do
    params[param.name] = param


def _step(drafts: list[Draft], start: int, item: Item, strict: bool) -> None:
    if item.kind == "challenge":
        drafts.append(Draft(item.scheme, item.offset, item.token68, item.open))
        if item.param is not None:
            add_param(drafts[-1].params, item.param, strict)
    elif item.kind == "param" and item.param is not None:
        current = drafts[-1] if len(drafts) > start else None
        if current is None or current.token68 is not None or not current.open:
            if strict:
                name = shown(item.param.name)
                raise fail(f"auth-param {name} outside a challenge", item.offset)
            if current is None or current.token68 is not None:
                return
        current.open = True
        add_param(current.params, item.param, strict)


def read_drafts(value: str, strict: bool) -> list[Draft]:
    drafts: list[Draft] = []
    for line in line_items(value, strict):
        start = len(drafts)  # a challenge never continues on the next line
        for item in line:
            _step(drafts, start, item, strict)
    return drafts


def checked(draft: Draft, kind: str, strict: bool) -> Draft:
    if strict:
        try:
            check(draft.scheme, kind, draft.token68, list(draft.params.values()))
        except AuthError as error:
            raise AuthError(f"{error}, in the {kind} at offset {draft.offset}") from None
    return draft


def each_line(value: str | Iterable[str], read: Callable[[str], _T]) -> list[_T]:
    if isinstance(value, str):
        lines = [value]
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("field values must be str, not bytes: decode them as latin-1 first")
    else:
        try:
            lines = list(value)
        except TypeError:
            raise TypeError(
                f"expected a str or an iterable of str, not {type(value).__name__}"
            ) from None
        for line in lines:
            need_str(line, "each field line")
    results: list[_T] = []
    for number, line in enumerate(lines, 1):
        try:
            results.append(read(line))
        except AuthError as error:
            if len(lines) == 1:
                raise
            raise AuthError(f"{error} (field line {number})") from None
    return results
