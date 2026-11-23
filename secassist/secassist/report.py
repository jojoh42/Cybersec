"""Markdown-Bericht aus den Befunden erzeugen."""
from __future__ import annotations

from datetime import datetime

from .scope import Scope

ORDER = ["critical", "high", "medium", "low", "info"]
LABEL = {"critical": "Kritisch", "high": "Hoch", "medium": "Mittel", "low": "Niedrig", "info": "Info"}
CONF = {"confirmed": "bestätigt", "likely": "wahrscheinlich", "needs_manual_review": "manuell prüfen"}


def render(scope: Scope, mode: str, target: str, findings: list[dict], summary: str, session_id: str,
           audit_path: str) -> str:
    findings = sorted(findings, key=lambda f: ORDER.index(f["severity"]))
    counts = {s: sum(f["severity"] == s for f in findings) for s in ORDER}
    lines = [
        f"# Sicherheitsbericht – {scope.engagement}",
        "",
        f"- **Kunde:** {scope.client}",
        f"- **Freigegeben von:** {scope.authorized_by}",
        f"- **Modus / Ziel:** {mode} / `{target}`",
        f"- **Datum:** {datetime.now():%Y-%m-%d %H:%M}",
        f"- **Sitzung:** {session_id} (Audit-Log: `{audit_path}`)",
        "",
        "> Automatisiert unterstützte Prüfung. Befunde mit Status „manuell prüfen“ vor Weitergabe verifizieren.",
        "",
        "## Übersicht",
        "",
        "| " + " | ".join(LABEL[s] for s in ORDER) + " |",
        "|" + "---|" * len(ORDER),
        "| " + " | ".join(str(counts[s]) for s in ORDER) + " |",
        "",
        "## Zusammenfassung",
        "",
        summary or "_(keine Zusammenfassung)_",
        "",
        "## Befunde",
        "",
    ]
    if not findings:
        lines.append("_Keine Befunde festgehalten._")
    for i, f in enumerate(findings, 1):
        lines += [
            f"### {i}. [{LABEL[f['severity']]}] {f['title']}",
            "",
            f"- **Ort:** `{f['location']}`",
            f"- **Kategorie:** {f['category']}",
            f"- **Sicherheit der Aussage:** {CONF.get(f['confidence'], f['confidence'])}",
            "",
            "**Beschreibung**",
            "",
            f["description"],
            "",
            "**Belege**",
            "",
            "```",
            f["evidence"],
            "```",
            "",
            "**Empfehlung**",
            "",
            f["remediation"],
            "",
        ]
    return "\n".join(lines)
