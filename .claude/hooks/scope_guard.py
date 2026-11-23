#!/usr/bin/env python3
"""PreToolUse-Hook für Claude Code: blockiert Netzwerk-Werkzeuge gegen Ziele außerhalb des Scopes.

Scope-Datei: $SECASSIST_SCOPE oder .claude/scope.yaml (Format wie secassist/scope.example.yaml).
Exit-Code 2 = Aufruf wird blockiert, stderr geht als Begründung an Claude.
"""
import ipaddress
import json
import os
import re
import shlex
import sys

PROJECT = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
sys.path.insert(0, os.path.join(PROJECT, "secassist"))

NETWORK_TOOLS = {"nmap", "nuclei", "httpx", "ffuf", "curl", "wget", "testssl.sh", "testssl", "nikto",
                 "subfinder", "dnsx", "naabu", "katana", "gobuster", "feroxbuster", "whatweb", "masscan"}
FILE_EXT = re.compile(r"\.(txt|json|jsonl|xml|ya?ml|md|html?|csv|log|gnmap|nmap|out|lst)$", re.I)
HOSTLIKE = re.compile(r"^(https?://)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+(:\d+)?(/.*)?$", re.I)


def block(msg: str) -> None:
    print(f"scope_guard: {msg}", file=sys.stderr)
    sys.exit(2)


def candidates(tokens: list[str]) -> list[str]:
    out = []
    for t in tokens:
        if t.startswith("-") or os.path.exists(t) or FILE_EXT.search(t):
            continue
        val = t.split("=", 1)[1] if t.startswith("-") and "=" in t else t
        try:
            ipaddress.ip_network(val, strict=False)
            out.append(val)
            continue
        except ValueError:
            pass
        if HOSTLIKE.match(val) or val.startswith(("http://", "https://")):
            out.append(val)
    return out


def main() -> None:
    data = json.load(sys.stdin)
    if data.get("tool_name") != "Bash":
        return
    cmd = data.get("tool_input", {}).get("command", "")
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()
    # Befehlsketten (|, &&, ;) grob auftrennen und jeden Teil prüfen
    segments, cur = [], []
    for t in tokens:
        if t in ("|", "||", "&&", ";"):
            segments.append(cur)
            cur = []
        else:
            cur.append(t)
    segments.append(cur)

    net_segments = [s for s in segments if s and os.path.basename(s[0]) in NETWORK_TOOLS]
    if not net_segments:
        return

    scope_file = os.environ.get("SECASSIST_SCOPE") or os.path.join(PROJECT, ".claude", "scope.yaml")
    if not os.path.isfile(scope_file):
        block("Netzwerk-Werkzeug erkannt, aber keine Scope-Datei gefunden "
              "(SECASSIST_SCOPE setzen oder .claude/scope.yaml anlegen).")
    try:
        from secassist.scope import Scope, ScopeError
    except ImportError:
        block("Paket 'secassist' nicht importierbar – 'pip install -e secassist' ausführen.")
    scope = Scope.load(scope_file)

    for seg in net_segments:
        targets = candidates(seg[1:])
        if not targets:
            block(f"Kein prüfbares Ziel in '{' '.join(seg)}' erkannt – Ziel bitte explizit angeben.")
        for t in targets:
            try:
                if "/" in t and "://" not in t and re.match(r"^[\d.:a-f]+/\d+$", t, re.I):
                    scope.check_network(t)
                else:
                    scope.check_target(t)
            except ScopeError as e:
                block(f"'{t}' ist nicht freigegeben: {e}")


if __name__ == "__main__":
    main()
