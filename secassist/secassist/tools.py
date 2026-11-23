"""Werkzeuge, die das Modell aufrufen darf.

Sicherheitsprinzipien:
- Kein freier Shell-Zugriff: Scanner werden mit fest definierten Argumenten gestartet.
- Jedes Ziel wird gegen den Scope geprüft, bevor irgendetwas passiert.
- Alles, was Netzwerkverkehr zum Ziel erzeugt, braucht eine menschliche Freigabe.
- Ausgaben werden gekürzt, damit keine Riesenmengen (oder unnötig viele Daten) ans Modell gehen.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from .scope import Scope, ScopeError

MAX_OUTPUT_CHARS = 20_000
MAX_FILE_BYTES = 200_000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", "target"}


# --------------------------------------------------------------------------- Scanner-Profile
# Jedes Profil: Liste von Argumenten mit Platzhaltern {target}, {rate}, {wordlist}.
# Bewusst zurückhaltende Profile (kein DoS, keine Brute-Force, Rate-Limits).
SCANNERS: dict[str, dict] = {
    "nmap_services": {
        "binary": "nmap",
        "args": ["-sV", "--top-ports", "1000", "-T3", "--max-rate", "{rate}", "-oN", "-", "{target}"],
        "kind": "host_or_network",
        "help": "Offene Ports + Dienstversionen (Top 1000 Ports)",
    },
    "httpx_probe": {
        "binary": "httpx",
        "args": ["-u", "{target}", "-status-code", "-title", "-tech-detect", "-web-server", "-silent", "-rl", "{rate}"],
        "kind": "url",
        "help": "Webserver erkennen: Status, Titel, Technologien",
    },
    "nuclei_scan": {
        "binary": "nuclei",
        "args": ["-u", "{target}", "-severity", "low,medium,high,critical", "-etags", "dos,fuzz,intrusive",
                 "-rl", "{rate}", "-silent", "-nc"],
        "kind": "url",
        "help": "Bekannte Schwachstellen & Fehlkonfigurationen (ohne DoS-/intrusive Templates)",
    },
    "ffuf_content": {
        "binary": "ffuf",
        "args": ["-u", "{target}/FUZZ", "-w", "{wordlist}", "-rate", "{rate}", "-mc", "200,204,301,302,307,401,403",
                 "-s"],
        "kind": "url",
        "help": "Versteckte Pfade/Dateien finden (Wortliste aus SECASSIST_WORDLIST)",
    },
    "testssl": {
        "binary": "testssl.sh",
        "args": ["--quiet", "--color", "0", "--sneaky", "{target}"],
        "kind": "url",
        "help": "TLS-Konfiguration prüfen",
    },
    "semgrep_code": {
        "binary": "semgrep",
        "args": ["scan", "--config", "auto", "--quiet", "--metrics", "off", "{target}"],
        "kind": "path",
        "help": "Statische Code-Analyse (SAST)",
    },
    "gitleaks_secrets": {
        "binary": "gitleaks",
        "args": ["detect", "--source", "{target}", "--no-banner", "--redact", "-v"],
        "kind": "path",
        "help": "Hartkodierte Secrets im Code/Git-Verlauf finden (Werte werden geschwärzt)",
    },
    "trivy_deps": {
        "binary": "trivy",
        "args": ["fs", "--scanners", "vuln,misconfig", "--quiet", "{target}"],
        "kind": "path",
        "help": "Verwundbare Abhängigkeiten + IaC-Fehlkonfigurationen",
    },
}

NETWORK_KINDS = {"host_or_network", "url"}


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n[... gekürzt, {len(text) - limit} weitere Zeichen ...]"


# --------------------------------------------------------------------------- Tool-Schemas
def _schema(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


TOOL_DEFINITIONS = [
    {
        "name": "list_files",
        "description": "Listet Dateien in einem freigegebenen Code-Verzeichnis (rekursiv, max. 500 Einträge). "
                       "Nur lesend, keine Freigabe nötig.",
        "strict": True,
        "input_schema": _schema({"path": {"type": "string", "description": "Verzeichnis innerhalb der Code-Pfade"}},
                                ["path"]),
    },
    {
        "name": "read_file",
        "description": "Liest eine Datei aus einem freigegebenen Code-Verzeichnis. Optional Zeilenbereich. "
                       "Nur lesend, keine Freigabe nötig.",
        "strict": True,
        "input_schema": _schema({
            "path": {"type": "string"},
            "start_line": {"type": "integer", "description": "1-basiert, 0 = Anfang"},
            "end_line": {"type": "integer", "description": "inklusive, 0 = Ende"},
        }, ["path", "start_line", "end_line"]),
    },
    {
        "name": "search_code",
        "description": "Durchsucht freigegebenen Code mit einem regulären Ausdruck (wie grep). "
                       "Gibt Datei:Zeile:Inhalt zurück, max. 200 Treffer. Nur lesend.",
        "strict": True,
        "input_schema": _schema({
            "path": {"type": "string"},
            "pattern": {"type": "string", "description": "Python-Regex"},
        }, ["path", "pattern"]),
    },
    {
        "name": "run_scanner",
        "description": "Startet ein vordefiniertes Prüfwerkzeug gegen ein Ziel im Scope. Verfügbare Profile:\n"
                       + "\n".join(f"- {k} ({v['kind']}): {v['help']}" for k, v in SCANNERS.items())
                       + "\nNetzwerk-Scans brauchen eine Freigabe durch den Menschen; Ziele außerhalb des "
                         "Scopes werden abgelehnt.",
        "strict": True,
        "input_schema": _schema({
            "profile": {"type": "string", "enum": list(SCANNERS)},
            "target": {"type": "string", "description": "URL, Host, IP, CIDR oder Code-Pfad – je nach Profil"},
            "reason": {"type": "string", "description": "Warum dieser Scan? (wird dem Menschen angezeigt)"},
        }, ["profile", "target", "reason"]),
    },
    {
        "name": "http_request",
        "description": "Sendet eine einzelne HTTP-Anfrage (GET/HEAD/OPTIONS/POST) an ein Ziel im Scope, z. B. um "
                       "Security-Header, Fehlermeldungen oder Zugriffskontrollen zu verifizieren. Braucht Freigabe. "
                       "Gibt Status, Header und den Anfang des Bodys zurück.",
        "strict": True,
        "input_schema": _schema({
            "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS", "POST"]},
            "url": {"type": "string"},
            "headers": {"type": "array", "description": "Zusätzliche Header, z. B. Cookie eines Test-Accounts",
                        "items": _schema({"name": {"type": "string"}, "value": {"type": "string"}},
                                         ["name", "value"])},
            "body": {"type": "string", "description": "Nur bei POST, sonst leer"},
            "reason": {"type": "string"},
        }, ["method", "url", "headers", "body", "reason"]),
    },
    {
        "name": "record_finding",
        "description": "Hält einen bestätigten oder wahrscheinlichen Befund für den Bericht fest. "
                       "Nur Befunde aufnehmen, für die es konkrete Belege gibt.",
        "strict": True,
        "input_schema": _schema({
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
            "confidence": {"type": "string", "enum": ["confirmed", "likely", "needs_manual_review"]},
            "location": {"type": "string", "description": "URL, Host:Port oder Datei:Zeile"},
            "category": {"type": "string", "description": "z. B. OWASP-Kategorie oder CWE"},
            "description": {"type": "string"},
            "evidence": {"type": "string", "description": "Belege: Request/Response-Auszug, Codezeilen, Scanner-Ausgabe"},
            "remediation": {"type": "string", "description": "Konkrete Empfehlung zur Behebung"},
        }, ["title", "severity", "confidence", "location", "category", "description", "evidence", "remediation"]),
    },
]


# --------------------------------------------------------------------------- Ausführung
@dataclass
class ToolContext:
    scope: Scope
    approve: Callable[[str, dict], bool]          # (zusammenfassung, details) -> True/False
    audit: "object"
    findings: list[dict] = field(default_factory=list)


def needs_approval(name: str, args: dict) -> bool:
    if name == "http_request":
        return True
    if name == "run_scanner":
        return SCANNERS.get(args.get("profile", ""), {}).get("kind") in NETWORK_KINDS
    return False


def _validate_scanner_target(scope: Scope, kind: str, target: str) -> str:
    if kind == "path":
        return scope.check_path(target)
    if kind == "url":
        scope.check_target(target)
        if not re.match(r"^https?://", target):
            raise ScopeError("Für dieses Profil wird eine URL mit http:// oder https:// erwartet")
        return target.rstrip("/")
    # host_or_network
    if "/" in target and "://" not in target:
        return scope.check_network(target)
    return scope.check_target(target)


def _run_scanner(ctx: ToolContext, args: dict) -> str:
    profile = SCANNERS[args["profile"]]
    target = _validate_scanner_target(ctx.scope, profile["kind"], args["target"])
    binary = shutil.which(profile["binary"])
    if not binary:
        return f"Fehler: '{profile['binary']}' ist nicht installiert. Bitte installieren oder anderes Profil wählen."
    wordlist = os.environ.get("SECASSIST_WORDLIST", "")
    if "{wordlist}" in " ".join(profile["args"]) and not os.path.isfile(wordlist):
        return "Fehler: Umgebungsvariable SECASSIST_WORDLIST zeigt auf keine Wortliste."
    argv = [binary] + [
        a.format(target=target, rate=ctx.scope.max_requests_per_second, wordlist=wordlist) for a in profile["args"]
    ]
    ctx.audit.write("command", argv=argv)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        return "Fehler: Zeitüberschreitung nach 30 Minuten."
    out = proc.stdout + ("\n[stderr]\n" + proc.stderr if proc.stderr.strip() else "")
    return _truncate(f"Exit-Code {proc.returncode}\n{out}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):  # Redirects nicht folgen – könnten aus dem Scope führen
        return None


def _http_request(ctx: ToolContext, args: dict) -> str:
    ctx.scope.check_target(args["url"])
    if not re.match(r"^https?://", args["url"]):
        raise ScopeError("Nur http:// und https:// sind erlaubt")
    data = args["body"].encode() if args["method"] == "POST" and args["body"] else None
    req = urllib.request.Request(args["url"], data=data, method=args["method"], headers={
        "User-Agent": "secassist/0.1 (autorisierte Sicherheitspruefung)",
        **{h["name"]: h["value"] for h in args["headers"]}})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(req, timeout=30)
        status, headers, body = resp.status, dict(resp.headers), resp.read(8000)
    except urllib.error.HTTPError as e:
        status, headers, body = e.code, dict(e.headers), e.read(8000)
    except urllib.error.URLError as e:
        return f"Fehler: {e.reason}"
    header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    return f"HTTP {status}\n{header_text}\n\n{body.decode(errors='replace')}"


def _list_files(ctx: ToolContext, args: dict) -> str:
    root = ctx.scope.check_path(args["path"])
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            out.append(os.path.relpath(os.path.join(dirpath, fn), root))
            if len(out) >= 500:
                return "\n".join(out) + "\n[... mehr als 500 Dateien, Unterverzeichnis angeben ...]"
    return "\n".join(out) or "(leer)"


def _read_file(ctx: ToolContext, args: dict) -> str:
    path = ctx.scope.check_path(args["path"])
    if os.path.getsize(path) > MAX_FILE_BYTES and not args["end_line"]:
        return f"Datei ist größer als {MAX_FILE_BYTES} Bytes – bitte Zeilenbereich angeben."
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    start = max(args["start_line"], 1)
    end = args["end_line"] or len(lines)
    numbered = [f"{i}: {line.rstrip()}" for i, line in enumerate(lines[start - 1:end], start)]
    return _truncate("\n".join(numbered))


def _search_code(ctx: ToolContext, args: dict) -> str:
    root = ctx.scope.check_path(args["path"])
    try:
        rx = re.compile(args["pattern"])
    except re.error as e:
        return f"Ungültiger Regex: {e}"
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) > MAX_FILE_BYTES:
                    continue
                with open(p, encoding="utf-8", errors="ignore") as f:
                    for no, line in enumerate(f, 1):
                        if rx.search(line):
                            hits.append(f"{os.path.relpath(p, root)}:{no}: {line.strip()[:300]}")
                            if len(hits) >= 200:
                                return "\n".join(hits) + "\n[... mehr als 200 Treffer ...]"
            except OSError:
                continue
    return "\n".join(hits) or "Keine Treffer."


def _record_finding(ctx: ToolContext, args: dict) -> str:
    ctx.findings.append(dict(args))
    ctx.audit.write("finding", **args)
    return f"Befund #{len(ctx.findings)} gespeichert."


HANDLERS = {
    "list_files": _list_files,
    "read_file": _read_file,
    "search_code": _search_code,
    "run_scanner": _run_scanner,
    "http_request": _http_request,
    "record_finding": _record_finding,
}


def describe_call(name: str, args: dict) -> str:
    if name == "run_scanner":
        return f"Scanner '{args['profile']}' gegen {args['target']}\nGrund: {args['reason']}"
    if name == "http_request":
        extra = f"\nHeader: {[h['name'] for h in args['headers']]}" if args["headers"] else ""
        return f"HTTP {args['method']} {args['url']}{extra}\nGrund: {args['reason']}"
    return f"{name}({args})"


def execute(ctx: ToolContext, name: str, args: dict) -> tuple[str, bool]:
    """Führt ein Tool aus. Rückgabe: (Ergebnistext, is_error)."""
    handler = HANDLERS.get(name)
    if handler is None:
        return f"Unbekanntes Werkzeug: {name}", True
    try:
        # Scope VOR der Freigabe prüfen, damit der Mensch gar nicht erst Out-of-Scope-Aktionen sieht
        if name == "run_scanner":
            _validate_scanner_target(ctx.scope, SCANNERS[args["profile"]]["kind"], args["target"])
        elif name == "http_request":
            ctx.scope.check_target(args["url"])
        if needs_approval(name, args):
            approved = ctx.approve(describe_call(name, args), {"tool": name, "input": args})
            ctx.audit.write("approval", tool=name, input=args, approved=approved)
            if not approved:
                return "Vom Menschen abgelehnt. Schlage eine Alternative vor oder fahre ohne diesen Schritt fort.", True
        result = handler(ctx, args)
        ctx.audit.write("tool_result", tool=name, input=args, chars=len(result))
        return result, result.startswith("Fehler")
    except ScopeError as e:
        ctx.audit.write("scope_denied", tool=name, input=args, reason=str(e))
        return f"AUSSERHALB DES SCOPES – nicht ausgeführt: {e}", True
    except (OSError, KeyError, ValueError) as e:
        return f"Fehler: {e}", True
