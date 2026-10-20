"""RFC 8187 ext-value, the encoding of parameters such as Digest `username*`."""

from __future__ import annotations

import re
from urllib.parse import quote, unquote_to_bytes

from ._grammar import need_str, shown
from ._model import AuthError

# attr-char of RFC 8187 section 3.2.1: token characters except "*", "'" and "%".
_ATTR_CHAR = "!#$&+-.^_`|~"
_EXT_VALUE = re.compile(
    r"(?P<charset>[A-Za-z0-9!#$%&+\-^_`{}~]+)'(?P<language>[A-Za-z0-9-]*)'"
    r"(?P<value>(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9!#$&+\-.^_`|~])*)"
)
# Language-Tag of RFC 5646 section 2.1: langtag / privateuse / grandfathered.
_PRIVATE = r"x(?:-[a-z0-9]{1,8})+"
_LANGTAG = (
    r"(?:[a-z]{2,3}(?:-[a-z]{3}){0,3}|[a-z]{4,8})"  # language, with up to three extlang
    r"(?:-[a-z]{4})?(?:-(?:[a-z]{2}|[0-9]{3}))?"  # script, region
    r"(?:-(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*"  # variants
    r"(?:-[0-9a-wyz](?:-[a-z0-9]{2,8})+)*"  # extensions
    rf"(?:-{_PRIVATE})?"
)
_GRANDFATHERED = (
    "en-gb-oed|i-ami|i-bnn|i-default|i-enochian|i-hak|i-klingon|i-lux|i-mingo|i-navajo|"
    "i-pwn|i-tao|i-tay|i-tsu|sgn-be-fr|sgn-be-nl|sgn-ch-de|art-lojban|cel-gaulish|"
    "no-bok|no-nyn|zh-guoyu|zh-hakka|zh-min|zh-min-nan|zh-xiang"
)
_LANGUAGE = re.compile(rf"{_LANGTAG}|{_PRIVATE}|{_GRANDFATHERED}", re.IGNORECASE)


def _control(text: str) -> bool:
    # C0, DEL and C1: a decoded name must not carry a line break or a terminal escape.
    return any(ord(char) < 0x20 or 0x7F <= ord(char) < 0xA0 for char in text)


def encode_ext_value(text: str) -> str:
    """Encode text as an RFC 8187 ext-value: `UTF-8''` and percent-encoded UTF-8.

    Text with a control character (C0, DEL or C1), which `decode_ext_value` refuses,
    or with a lone surrogate, which UTF-8 cannot encode, raises `AuthError`; whatever
    it returns decodes back to the same text.

    >>> from authchallenge import encode_ext_value
    >>> encode_ext_value("Jäsøn Doe")
    "UTF-8''J%C3%A4s%C3%B8n%20Doe"
    """
    if _control(need_str(text, "text")):
        raise AuthError("the text holds a control character, which an ext-value cannot carry")
    try:
        encoded = quote(text, safe=_ATTR_CHAR, encoding="utf-8")
    except UnicodeEncodeError:
        raise AuthError("the text holds a lone surrogate, which UTF-8 cannot encode") from None
    return "UTF-8''" + encoded


def decode_ext_value(value: str) -> str:
    """Decode an RFC 8187 ext-value, raising AuthError when malformed or not UTF-8.

    RFC 8187 makes UTF-8 the only charset producers may use; ISO-8859-1 is also read,
    since RFC 5987 (which it replaces) allowed it. The language, when present, must be
    an RFC 5646 language tag. Control characters (C0, DEL, C1) in the decoded text are
    refused, so a decoded name cannot carry a line break.

    >>> from authchallenge import decode_ext_value
    >>> decode_ext_value("UTF-8''J%C3%A4s%C3%B8n%20Doe")
    'Jäsøn Doe'
    >>> decode_ext_value("iso-8859-1'en'%A3%20rates")
    '£ rates'
    """
    match = _EXT_VALUE.fullmatch(need_str(value, "value"))
    if match is None:
        raise AuthError(f"invalid ext-value: {shown(value)}")
    language = match.group("language")
    if language and _LANGUAGE.fullmatch(language) is None:
        raise AuthError(f"the ext-value language is not a language tag: {shown(language)}")
    charset = match.group("charset").lower()
    if charset not in ("utf-8", "iso-8859-1"):
        raise AuthError(f"unsupported ext-value charset: {shown(match.group('charset'))}")
    try:
        text = unquote_to_bytes(match.group("value")).decode(charset)
    except UnicodeDecodeError:
        raise AuthError(f"ext-value is not valid {charset}") from None
    if _control(text):
        raise AuthError("ext-value decodes to control characters")
    return text
