"""Agenten-Schleife mit gefälschtem API-Client testen (keine echten API-Aufrufe)."""
from types import SimpleNamespace as NS

from secassist import agent
from tests.test_scope import scope  # noqa: F401  (Fixture)


class _Usage:
    def to_dict(self):
        return {}


def _resp(content, stop):
    return NS(content=content, stop_reason=stop, model="fake", usage=_Usage(), stop_details=None)


class FakeClient:
    def __init__(self, code_dir):
        self.calls = []
        self.code_dir = code_dir
        self.beta = NS(messages=NS(create=self.create))

    def create(self, **kw):
        self.calls.append({**kw, "messages": list(kw["messages"])})
        if len(self.calls) == 1:
            return _resp([
                NS(type="thinking", thinking="Ich suche nach Secrets."),
                NS(type="tool_use", id="t1", name="search_code",
                   input={"path": self.code_dir, "pattern": "password"}),
            ], "tool_use")
        if len(self.calls) == 2:
            return _resp([NS(type="tool_use", id="t2", name="record_finding", input=dict(
                title="Hartkodiertes Passwort", severity="high", confidence="confirmed", location="app.py:1",
                category="CWE-798", description="d", evidence="password = 'x'", remediation="Secret-Store nutzen"))],
                "tool_use")
        return _resp([NS(type="text", text="Fertig: 1 Befund.")], "end_turn")


def test_loop(scope, tmp_path, monkeypatch):  # noqa: F811
    fake = FakeClient(str(tmp_path / "code"))
    monkeypatch.setattr(agent.anthropic, "Anthropic", lambda: fake)
    events = []
    res = agent.run_assessment(scope, "code", str(tmp_path / "code"), "", approve=lambda s, d: False,
                               on_event=lambda k, d: events.append(k), log_dir=str(tmp_path / "logs"))
    assert res.stopped_reason == "done" and len(res.findings) == 1
    assert res.summary == "Fertig: 1 Befund."
    first = fake.calls[0]
    assert first["model"] == "claude-opus-5-5" and first["fallbacks"] == "default"
    # Tool-Ergebnis wurde korrekt zurückgegeben
    tool_result = fake.calls[1]["messages"][-1]["content"][0]
    assert tool_result["tool_use_id"] == "t1" and "app.py:1" in tool_result["content"]
    assert "thinking" in events and "done" in events


def test_refusal(scope, tmp_path, monkeypatch):  # noqa: F811
    fake = FakeClient("x")
    fake.beta.messages.create = lambda **kw: NS(content=[], stop_reason="refusal", model="m", usage=_Usage(),
                                                stop_details=NS(to_dict=lambda: {"category": "cyber"}))
    monkeypatch.setattr(agent.anthropic, "Anthropic", lambda: fake)
    res = agent.run_assessment(scope, "web", "https://staging.example.com", "", approve=lambda s, d: False,
                               log_dir=str(tmp_path / "logs"))
    assert res.stopped_reason == "refusal" and "cyber" in res.summary
