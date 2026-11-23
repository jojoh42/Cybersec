"""Kommandozeile: secassist run | scope-check | web"""
from __future__ import annotations

import argparse
import os
import sys

from .scope import Scope, ScopeError


def _cli_approve(summary: str, details: dict) -> bool:
    print("\n" + "=" * 70)
    print("FREIGABE ERFORDERLICH")
    print(summary)
    print("=" * 70)
    while True:
        answer = input("Ausführen? [j/n] ").strip().lower()
        if answer in ("j", "ja", "y", "yes"):
            return True
        if answer in ("n", "nein", "no"):
            return False


def _cli_event(kind: str, data: dict) -> None:
    if kind == "thinking":
        print(f"\033[2m[denkt] {data['text']}\033[0m")
    elif kind == "text":
        print(f"\n{data['text']}")
    elif kind == "tool_call":
        print(f"\n→ {data['name']} {data['input']}")
    elif kind == "tool_result":
        preview = data["result"][:600]
        print(f"← {'FEHLER ' if data['is_error'] else ''}{preview}{' …' if len(data['result']) > 600 else ''}")
    elif kind in ("info", "refusal"):
        print(f"[{kind}] {data}")


def cmd_run(a: argparse.Namespace) -> int:
    from .agent import run_assessment
    from .report import render

    scope = Scope.load(a.scope)
    print(scope.summary())
    if not a.yes and input("\nStimmt dieser Scope und liegt eine schriftliche Freigabe vor? [j/n] ").lower() not in ("j", "ja", "y"):
        print("Abgebrochen.")
        return 1
    result = run_assessment(scope, a.mode, a.target, a.instructions or "", approve=_cli_approve,
                            on_event=_cli_event, log_dir=a.log_dir, max_turns=a.max_turns, effort=a.effort)
    os.makedirs(a.report_dir, exist_ok=True)
    path = os.path.join(a.report_dir, f"bericht-{result.session_id}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render(scope, a.mode, a.target, result.findings, result.summary, result.session_id,
                       result.audit_path))
    print(f"\nFertig ({result.stopped_reason}). {len(result.findings)} Befunde. Bericht: {path}")
    return 0


def cmd_scope_check(a: argparse.Namespace) -> int:
    scope = Scope.load(a.scope)
    ok = True
    for t in a.targets:
        try:
            if os.path.exists(t):
                scope.check_path(t)
            elif "/" in t and "://" not in t:
                scope.check_network(t)
            else:
                scope.check_target(t)
            print(f"✔ {t}")
        except ScopeError as e:
            ok = False
            print(f"✘ {t}: {e}")
    return 0 if ok else 2


def cmd_web(a: argparse.Namespace) -> int:
    import uvicorn

    os.environ["SECASSIST_SCOPE"] = os.path.abspath(a.scope)
    os.environ["SECASSIST_LOG_DIR"] = os.path.abspath(a.log_dir)
    os.environ["SECASSIST_REPORT_DIR"] = os.path.abspath(a.report_dir)
    if not os.environ.get("SECASSIST_UI_TOKEN"):
        print("Bitte SECASSIST_UI_TOKEN setzen (Zugangstoken für die Web-Oberfläche).", file=sys.stderr)
        return 1
    uvicorn.run("secassist.web:app", host=a.host, port=a.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="secassist", description="KI-Sicherheits-Assistent für autorisierte Prüfungen")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="Prüfung starten")
    r.add_argument("--scope", required=True, help="Scope-Datei (YAML)")
    r.add_argument("--mode", required=True, choices=["code", "web", "infra"])
    r.add_argument("--target", required=True, help="Code-Pfad, URL, Host oder Netz")
    r.add_argument("--instructions", help="Zusätzliche Hinweise, z. B. Test-Accounts oder Fokus")
    r.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    r.add_argument("--max-turns", type=int, default=60)
    r.add_argument("--log-dir", default="logs")
    r.add_argument("--report-dir", default="reports")
    r.add_argument("--yes", action="store_true", help="Scope-Bestätigung überspringen")
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("scope-check", help="Prüfen, ob Ziele im Scope liegen")
    s.add_argument("--scope", required=True)
    s.add_argument("targets", nargs="+")
    s.set_defaults(func=cmd_scope_check)

    w = sub.add_parser("web", help="Web-Oberfläche starten")
    w.add_argument("--scope", required=True)
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8765)
    w.add_argument("--log-dir", default="logs")
    w.add_argument("--report-dir", default="reports")
    w.set_defaults(func=cmd_web)

    a = p.parse_args(argv)
    try:
        return a.func(a)
    except ScopeError as e:
        print(f"Scope-Fehler: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
