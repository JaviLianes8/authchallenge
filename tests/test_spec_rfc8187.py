"""RFC 8187 ext-values, checked against the fetched text (see tests/upstream/MANIFEST.json)."""

from __future__ import annotations

import re
import string

import pytest
from conftest import rfc, section

from authchallenge import AuthError, decode_ext_value, encode_ext_value


@pytest.fixture(scope="module")
def rfc8187() -> str:
    return rfc(8187)


def _production(text: str, name: str) -> set[str]:
    """Characters of an ABNF rule made of ALPHA, DIGIT and quoted single characters."""
    rule = text.split(f"     {name}", 1)[1].split("\n\n", 1)[0]
    rule = "\n".join(line.split(";", 1)[0] for line in rule.splitlines())
    chars = set(re.findall(r'"(.)"', rule))
    assert "ALPHA" in rule and "DIGIT" in rule, rule
    return chars | set(string.ascii_letters + string.digits)


def test_encoding_leaves_exactly_attr_char_unescaped(rfc8187: str) -> None:
    attr_char = _production(rfc8187, "attr-char     =")
    assert len(attr_char) == 62 + 12
    for code in range(0x20, 0x7F):
        char = chr(code)
        encoded = encode_ext_value(char)[len("UTF-8''") :]
        assert (encoded == char) == (char in attr_char), char
        assert decode_ext_value("UTF-8''" + encoded) == char


def test_charset_names_follow_mime_charsetc(rfc8187: str) -> None:
    charsetc = _production(rfc8187, "mime-charsetc =")
    for code in range(0x21, 0x7F):
        char = chr(code)
        if char == "'":
            continue
        with pytest.raises(AuthError) as caught:
            decode_ext_value(f"x{char}y''a")
        reason = "unsupported ext-value charset" if char in charsetc else "invalid ext-value"
        assert reason in str(caught.value), char


def test_the_examples_of_section_3_2_3(rfc8187: str) -> None:
    examples = section(rfc8187, "3.2.3.  Examples", "4.  ")
    values = re.findall(r"title\*=(\S+)", examples)
    assert values == ["utf-8'en'%C2%A3%20rates", "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates"]
    assert [decode_ext_value(v) for v in values] == ["£ rates", "£ and € rates"]
    assert encode_ext_value("£ rates") == "UTF-8''%C2%A3%20rates"
