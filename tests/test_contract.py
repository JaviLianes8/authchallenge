from __future__ import annotations

import dataclasses
import importlib.resources

import pytest

import authchallenge

# The public API. Add every exported name here as the library grows; this list is the
# contract and the test below fails if the module and this list disagree.
PUBLIC_API: list[str] = [
    "AuthError",
    "Challenge",
    "Credentials",
    "build_auth_info",
    "build_authorization",
    "build_bearer_challenge",
    "build_challenge",
    "decode_basic",
    "decode_ext_value",
    "encode_basic",
    "encode_ext_value",
    "parse_auth_info",
    "parse_authorization",
    "parse_challenges",
    "select_challenge",
]


def test_all_lists_exactly_the_public_api() -> None:
    assert sorted(authchallenge.__all__) == sorted(PUBLIC_API)


def test_every_exported_name_resolves() -> None:
    for name in authchallenge.__all__:
        assert hasattr(authchallenge, name)


def test_version_is_a_three_part_string() -> None:
    parts = authchallenge.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_the_package_ships_type_information() -> None:
    assert importlib.resources.files("authchallenge").joinpath("py.typed").is_file()


def test_auth_error_is_a_value_error() -> None:
    assert issubclass(authchallenge.AuthError, ValueError)


def test_results_are_frozen() -> None:
    challenge = authchallenge.Challenge("Basic")
    with pytest.raises(dataclasses.FrozenInstanceError):
        challenge.scheme = "Bearer"  # type: ignore[misc]
