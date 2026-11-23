# Hinweise für Claude Code in diesem Repo

Dieses Repo enthält einen Lernpfad (Markdown-Dateien im Hauptverzeichnis) und das Werkzeug `secassist/`
für autorisierte Sicherheitsprüfungen eigener Entwicklungen, interner Systeme und von Kundensystemen.

Regeln für Sicherheitsprüfungen:
- Nur Ziele aus der Scope-Datei (`$SECASSIST_SCOPE` oder `.claude/scope.yaml`) testen. Der Hook
  `.claude/hooks/scope_guard.py` blockiert Netzwerk-Werkzeuge gegen andere Ziele – nicht umgehen,
  Scope-Datei und Hook nicht verändern.
- Zurückhaltend testen: kein DoS, keine Brute-Force, keine destruktiven Aktionen, Rate-Limit beachten.
- Kundendaten, Berichte und Logs nie committen (siehe `.gitignore`).
- Für Code-Reviews den Subagenten `security-code-reviewer` nutzen, für Web/API `web-assessor`.

Entwicklung von secassist: `cd secassist && pip install -e . pytest && pytest -q`
