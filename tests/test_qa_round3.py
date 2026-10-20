"""Contracts from the third QA round of 1.0.0: printed tracebacks and non-iterable arguments."""

from __future__ import annotations

import traceback
from collections.abc import Callable
from typing import Any

import pytest

import authchallenge as ac

USER = "s3cretUser"
PARAMS = {"realm": "r", "nonce": "n", "uri": "/", "response": "x", "cnonce": "c", "nc": "00000001"}
TAIL = ', realm="r", nonce="n", uri="/", response="x", cnonce="c", nc=00000001'


def printed(error: BaseException) -> str:
    return "".join(traceback.format_exception(type(error), error, error.__traceback__))


@pytest.mark.parametrize(
    "call",
    [
        lambda: ac.build_authorization("Digest", {"username*": f"UTF-8''{USER}%ZZ", **PARAMS}),
        lambda: ac.build_authorization("Digest", {"username*": f"UTF-8''{USER}%FF%FE", **PARAMS}),
        lambda: ac.parse_authorization(f"Digest username*=UTF-8''{USER}%ZZ" + TAIL, strict=True),
    ],
)
def test_printed_traceback_of_a_bad_username_star_hides_the_user_name(
    call: Callable[[], object],
) -> None:
    with pytest.raises(ac.AuthError) as caught:
        call()
    assert str(caught.value).startswith("the Digest username* parameter is not a valid ext-value")
    assert caught.value.__suppress_context__ is True
    assert USER not in printed(caught.value)


HUGE: Any = 7**300  # deliberately the wrong type


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda: ac.parse_challenges(HUGE), "expected a str or an iterable of str, not int"),
        (lambda: ac.parse_auth_info(HUGE), "expected a str or an iterable of str, not int"),
        (
            lambda: ac.select_challenge(HUGE, "basic"),
            "challenges must be an iterable of Challenge, not int",
        ),
    ],
)
def test_non_iterable_argument_raises_an_exact_short_type_error(
    call: Callable[[], object], message: str
) -> None:
    with pytest.raises(TypeError) as caught:
        call()
    assert str(caught.value) == message
    assert caught.value.__suppress_context__ is True
    assert str(HUGE)[:20] not in printed(caught.value)
