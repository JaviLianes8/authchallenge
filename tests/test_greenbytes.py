"""Run the greenbytes WWW-Authenticate test cases through both parsing modes.

Source: http://test.greenbytes.de/tech/tc/httpauth/ (pinned in tests/upstream/MANIFEST.json,
fetched by scripts/fetch_upstream.py; skipped while absent).
"""

from __future__ import annotations

import pytest
from conftest import read_upstream
from greenbytes_cases import Case, load

from authchallenge import AuthError, parse_challenges

# RFC 9112 section 5.2 lets a recipient reject obs-fold; strict mode does, the page does not.
FOLDED = {"simplebasiclf"}


@pytest.fixture(scope="module")
def cases() -> list[Case]:
    return load(read_upstream("httpauth.html", encoding="latin-1"))


def _first_of_each(params: tuple[tuple[str, str], ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in params:
        result.setdefault(name, value)
    return result


def test_the_page_has_the_cases_this_suite_counts(cases: list[Case]) -> None:
    assert len(cases) == 31
    verdicts = [case.verdict for case in cases]
    assert (verdicts.count("parseerror"), verdicts.count("invalidsyntax")) == (4, 3)


def test_tolerant_parsing_matches_the_post_processed_tables(cases: list[Case]) -> None:
    checked = 0
    for case in cases:
        if not case.expected:
            continue
        got = parse_challenges(case.values)
        assert len(got) == len(case.expected), case.name
        for challenge, (scheme, params) in zip(got, case.expected, strict=True):
            assert challenge.scheme.lower() == scheme, case.name
            assert challenge.params == _first_of_each(params), case.name
            assert challenge.token68 is None, case.name
        checked += 1
    assert checked == 28


def test_strict_parsing_follows_the_verdicts(cases: list[Case]) -> None:
    for case in cases:
        if case.verdict == "valid" and case.name not in FOLDED:
            parse_challenges(case.values, strict=True)
        else:
            with pytest.raises(AuthError):
                parse_challenges(case.values, strict=True)
