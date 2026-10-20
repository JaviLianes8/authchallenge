"""Build the wheel, install it in a throwaway venv and drive the installed package.

Slow and needs the build backend, so it runs only with AUTHCHALLENGE_E2E=1. With
AUTHCHALLENGE_E2E_PYPI=1 it also installs 0.2.0 from PyPI and upgrades it in place.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTHCHALLENGE_E2E") != "1", reason="set AUTHCHALLENGE_E2E=1 to build"
)

PROGRAM = r"""
import importlib.metadata, importlib.resources
import authchallenge as ac

assert "site-packages" in ac.__file__, ac.__file__
assert importlib.metadata.version("authchallenge") == ac.__version__
assert importlib.resources.files("authchallenge").joinpath("py.typed").is_file()

lines = ['Basic realm="a", Newauth realm="b", type=1', "Negotiate abc==", 'Basic\r\n realm="x"']
offered = ac.parse_challenges(lines)
assert [c.scheme for c in offered] == ["Basic", "Newauth", "Negotiate", "Basic"]
assert offered[3].params == {"realm": "x"} and offered[2].token68 == "abc=="
assert ac.select_challenge(offered, "negotiate").token68 == "abc=="
assert ac.parse_challenges('Basic realm="a", realm="b"')[0].params == {"realm": "a"}
digest = {"realm": "r", "qop": "auth", "nonce": "n", "algorithm": "MD5"}
header = ac.build_challenge("Digest", digest)
assert header == 'Digest realm="r", qop="auth", nonce="n", algorithm=MD5'
assert ac.parse_challenges(header, strict=True)[0].params == digest
# RFC 7617 sections 2 and 2.1, https://www.rfc-editor.org/rfc/rfc7617
assert ac.encode_basic("Aladdin", "open sesame") == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
assert ac.decode_basic(ac.parse_authorization("Basic dGVzdDoxMjPCow==")) == ("test", "123£")
assert ac.decode_ext_value(ac.encode_ext_value("Jäsøn")) == "Jäsøn"
bearer = ac.build_bearer_challenge(realm="e", error="invalid_token")
assert bearer == 'Bearer realm="e", error="invalid_token"'
assert ac.parse_auth_info("qop=auth, nc=00000001") == {"qop": "auth", "nc": "00000001"}
for call in (
    lambda: ac.build_challenge("Basic", {"realm": "a\r\nX: y"}),
    lambda: ac.build_challenge("Basic"),
    lambda: ac.parse_challenges("Basic realm=a", strict=True),
    lambda: ac.parse_authorization("Basic QQ==, Bearer x", strict=True),
    lambda: ac.decode_basic("Basic QWxhZGRpbg=="),
):
    try:
        call()
    except ac.AuthError as error:
        assert isinstance(error, ValueError)
    else:
        raise AssertionError("expected AuthError")
assert "QWxh" not in repr(ac.parse_authorization("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="))
assert ac.AuthError.__module__ == "authchallenge"
try:
    ac.parse_challenges(b"Basic")
except TypeError:
    pass
else:
    raise AssertionError("expected TypeError")
print("e2e ok")
"""

CONSUMER = """
from authchallenge import Challenge, parse_challenges, select_challenge

chosen: Challenge | None = select_challenge(parse_challenges('Basic realm="a"'), "basic")
realm: str = chosen.params["realm"] if chosen else ""
"""


def _run(
    *cmd: str | Path, cwd: Path | None = None, stdin: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(c) for c in cmd], cwd=cwd, input=stdin, capture_output=True, check=False
    )


def test_installed_wheel_end_to_end(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    built = _run(sys.executable, "-m", "build", "--outdir", dist, ROOT)
    assert built.returncode == 0, built.stderr
    (wheel,) = dist.glob("authchallenge-*.whl")
    (sdist,) = dist.glob("authchallenge-*.tar.gz")
    names = zipfile.ZipFile(wheel).namelist()
    assert "authchallenge/py.typed" in names and "authchallenge/__main__.py" in names
    assert not any(name.startswith(("tests/", "scripts/")) for name in names)
    entry_points = next(name for name in names if name.endswith("entry_points.txt"))
    text = zipfile.ZipFile(wheel).read(entry_points).decode()
    assert "authchallenge = authchallenge._cli:main" in text
    listing = _run(sys.executable, "-m", "tarfile", "-l", sdist).stdout.decode()
    assert "IMPROVEMENTS-round" not in listing and "httpauth.html" not in listing
    assert "CERT-1.0" not in listing and "GUIDE.md" in listing and "LICENSE" in listing
    assert "tests/upstream/MANIFEST.json" in listing
    assert ".txt" not in listing.replace("requirements-dev.txt", "")
    assert "tests/test_greenbytes.py" in listing and "scripts/fetch_upstream.py" in listing

    env_dir = tmp_path / "venv"
    venv.create(env_dir, with_pip=True)
    bindir = env_dir / ("Scripts" if sys.platform == "win32" else "bin")
    python = bindir / "python"
    if os.environ.get("AUTHCHALLENGE_E2E_PYPI") == "1":
        old = _run(python, "-m", "pip", "install", "-q", "authchallenge==0.2.0")
        assert old.returncode == 0, old.stderr
        check = "import authchallenge as a; assert a.__version__ == '0.2.0'"
        assert _run(python, "-I", "-c", check, cwd=tmp_path).returncode == 0
    installed = _run(python, "-m", "pip", "install", "-q", "--upgrade", wheel)
    assert installed.returncode == 0, installed.stderr

    # Run from an empty folder so the source tree cannot shadow the install.
    work = tmp_path / "work"
    work.mkdir()
    result = _run(python, "-I", "-c", PROGRAM, cwd=work)
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode().strip() == "e2e ok"
    consumer = work / "consumer.py"
    consumer.write_text(CONSUMER, encoding="utf-8")
    typed = _run(
        sys.executable, "-m", "mypy", "--strict", "--python-executable", python, consumer, cwd=work
    )
    assert typed.returncode == 0, typed.stdout

    head = b'HTTP/2 401\r\nwww-authenticate: Basic realm="a"\r\nX-Other: Basic\r\n\r\n'
    script = bindir / ("authchallenge.exe" if sys.platform == "win32" else "authchallenge")
    commands: list[list[str | Path]] = [[python, "-m", "authchallenge"]]
    if os.environ.get("AUTHCHALLENGE_E2E_NO_SCRIPT") != "1":
        commands.append([script])
    for command in commands:
        shown = _run(*command, cwd=work, stdin=head)
        assert shown.returncode == 0, shown.stderr
        report = json.loads(shown.stdout)
        assert report[0]["challenges"][0]["params"] == {"realm": "a"}
        failed = _run(*command, "--strict", "Basic realm=a", cwd=work)
        assert failed.returncode == 1 and b"quoted-string" in failed.stderr
