import os
import textwrap
from datetime import date, timedelta

import pytest

from secassist.scope import Scope, ScopeError
from secassist.tools import ToolContext, execute


class _Audit:
    def __init__(self):
        self.events = []

    def write(self, event, **data):
        self.events.append((event, data))


@pytest.fixture
def scope(tmp_path):
    code = tmp_path / "code"
    code.mkdir()
    (code / "app.py").write_text("password = 'x'\nprint('hi')\n")
    (tmp_path / "secret.txt").write_text("geheim")
    f = tmp_path / "scope.yaml"
    f.write_text(textwrap.dedent(f"""
        engagement: Test
        client: intern
        authorized_by: Tester
        valid_until: {date.today() + timedelta(days=1)}
        targets:
          hosts: [staging.example.com, "*.dev.example.com"]
          networks: [10.20.0.0/24]
          code_paths: [code]
        exclude:
          hosts: [pay.dev.example.com]
          networks: [10.20.0.1/32]
    """))
    return Scope.load(str(f))


@pytest.mark.parametrize("t", ["https://staging.example.com/login", "staging.example.com:8443",
                               "api.dev.example.com", "dev.example.com", "10.20.0.5"])
def test_in_scope(scope, t):
    scope.check_target(t)


@pytest.mark.parametrize("t", ["https://example.com", "https://staging.example.com.evil.net/",
                               "https://evil.net/?x=staging.example.com", "pay.dev.example.com",
                               "10.20.0.1", "10.20.1.5", "https://user@evil.net"])
def test_out_of_scope(scope, t):
    with pytest.raises(ScopeError):
        scope.check_target(t)


def test_networks(scope):
    assert scope.check_network("10.20.0.128/26")
    with pytest.raises(ScopeError):
        scope.check_network("10.20.0.0/26")  # enthält ausgeschlossenes Gateway
    with pytest.raises(ScopeError):
        scope.check_network("10.20.0.0/16")
    with pytest.raises(ScopeError):
        scope.check_network("10.20.0.0/30")  # enthält ausgeschlossenes Gateway


def test_paths(scope, tmp_path):
    scope.check_path(str(tmp_path / "code" / "app.py"))
    with pytest.raises(ScopeError):
        scope.check_path(str(tmp_path / "secret.txt"))
    with pytest.raises(ScopeError):
        scope.check_path(str(tmp_path / "code" / ".." / "secret.txt"))
    os.symlink(tmp_path / "secret.txt", tmp_path / "code" / "link.txt")
    with pytest.raises(ScopeError):
        scope.check_path(str(tmp_path / "code" / "link.txt"))


def test_expired(scope):
    scope.valid_until = date.today() - timedelta(days=1)
    with pytest.raises(ScopeError):
        scope.check_target("staging.example.com")


def test_tools_respect_scope_and_approval(scope, tmp_path):
    asked = []
    ctx = ToolContext(scope=scope, approve=lambda s, d: asked.append(s) or False, audit=_Audit())

    # Lesen im Scope: keine Freigabe nötig
    out, err = execute(ctx, "search_code", {"path": str(tmp_path / "code"), "pattern": "password"})
    assert not err and "app.py:1" in out and not asked

    # Lesen außerhalb: blockiert
    out, err = execute(ctx, "read_file", {"path": str(tmp_path / "secret.txt"), "start_line": 0, "end_line": 0})
    assert err and "SCOPE" in out

    # Netzwerk außerhalb: blockiert, ohne dass der Mensch gefragt wird
    out, err = execute(ctx, "http_request", {"method": "GET", "url": "https://evil.net", "headers": [],
                                             "body": "", "reason": "x"})
    assert err and "SCOPE" in out and not asked

    # Netzwerk im Scope: Mensch wird gefragt, lehnt ab -> nichts passiert
    out, err = execute(ctx, "run_scanner", {"profile": "nuclei_scan", "target": "https://staging.example.com",
                                            "reason": "Test"})
    assert err and "abgelehnt" in out and len(asked) == 1


def test_record_finding(scope):
    ctx = ToolContext(scope=scope, approve=lambda s, d: False, audit=_Audit())
    f = dict(title="t", severity="high", confidence="likely", location="x", category="c", description="d",
             evidence="e", remediation="r")
    out, err = execute(ctx, "record_finding", f)
    assert not err and ctx.findings == [f]
