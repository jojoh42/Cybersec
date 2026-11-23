# secassist – KI-Sicherheits-Assistent

Ein Assistent auf Basis von Claude (Claude Opus 5.5 über die Claude API) für **autorisierte** Sicherheitsprüfungen:

| Modus | Prüft | Werkzeuge |
|---|---|---|
| `code` | Quellcode eigener Projekte / freigegebener Kunden-Repos | Code lesen & durchsuchen, semgrep, gitleaks, trivy |
| `web` | Laufende Web-Apps & APIs (Staging/Produktion im Scope) | httpx, nuclei, ffuf, testssl.sh, einzelne HTTP-Anfragen |
| `infra` | Interne Netze & Server | nmap (Dienste/Versionen), nuclei |

Bedienung: **Kommandozeile**, **Web-Oberfläche** oder direkt in **Claude Code** (Subagenten + Scope-Hook, siehe unten).

## Sicherheitskonzept

1. **Scope-Datei (Default-Deny):** Nur Hosts, Netze und Code-Pfade aus der YAML-Datei sind erlaubt; Ausschlüsse haben Vorrang; nach `valid_until` verweigert das Tool jede Aktion. Pflichtfeld `authorized_by` dokumentiert die Freigabe.
2. **Menschliche Freigabe:** Jede Aktion mit Netzwerkverkehr zum Ziel (Scanner, HTTP-Anfrage) muss bestätigt werden. Lesen von freigegebenem Code läuft ohne Rückfrage.
3. **Kein freier Shell-Zugriff:** Das Modell kann nur feste Scanner-Profile mit zurückhaltenden Einstellungen starten (Rate-Limit, keine DoS-/intrusiven nuclei-Templates). HTTP-Redirects werden nicht verfolgt.
4. **Audit-Log:** Jeder Schritt (Modellantwort, Freigabe, Befehl, Ergebnis, Scope-Verstoß) landet in `logs/<sitzung>.jsonl` und dient als Nachweis gegenüber Kunden.
5. **Prompt-Injection:** Inhalte vom Ziel (Webseiten, Banner, Code-Kommentare) sind für das Modell als Daten markiert. Die Scope-Prüfung im Code greift unabhängig davon, was das Modell „will“.

## Installation

```bash
cd secassist
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
export ANTHROPIC_API_KEY=...        # oder: ant auth login
```

Optionale Scanner (nur die, die du brauchst): `nmap`, `httpx` und `nuclei` (ProjectDiscovery), `ffuf`, `testssl.sh`, `semgrep`, `gitleaks`, `trivy`.
Für `ffuf_content`: `export SECASSIST_WORDLIST=/pfad/zu/SecLists/Discovery/Web-Content/common.txt`

## Nutzung

### 1. Scope anlegen

```bash
mkdir -p scopes && cp scope.example.yaml scopes/kunde-a.yaml   # anpassen!
secassist scope-check --scope scopes/kunde-a.yaml https://staging.kunde-a.de 10.20.0.0/24
```

### 2a. Kommandozeile

```bash
# Eigenen Code prüfen
secassist run --scope scopes/intern.yaml --mode code --target ../mein-projekt

# Web-App prüfen, mit Test-Accounts
secassist run --scope scopes/kunde-a.yaml --mode web --target https://staging.kunde-a.de \
  --instructions "Test-Accounts: alice/… (User), bob/… (Admin). Fokus: API unter /api/v2"

# Internes Netz
secassist run --scope scopes/intern.yaml --mode infra --target 10.20.0.0/24
```

Bei jeder Netzwerk-Aktion fragt das Tool `Ausführen? [j/n]`. Am Ende liegt der Bericht in `reports/bericht-<id>.md`.

### 2b. Web-Oberfläche

```bash
export SECASSIST_UI_TOKEN=$(python3 -c "import secrets;print(secrets.token_urlsafe(24))")
echo $SECASSIST_UI_TOKEN
secassist web --scope scopes/kunde-a.yaml        # → http://127.0.0.1:8765
```

Token eingeben, Scope laden, Prüfung starten, Freigaben per Knopf erteilen, Bericht anzeigen.
Die Oberfläche läuft nur lokal. Für Kollegen: hinter einen Reverse-Proxy mit TLS und Firmen-Login (SSO) stellen, nicht direkt öffnen.

### 2c. Claude Code direkt

Im Repo-Hauptverzeichnis ist Claude Code vorkonfiguriert (`.claude/`):

- **Subagenten** `security-code-reviewer` und `web-assessor`. Aufruf z. B.: *„Nutze den security-code-reviewer für ../mein-projekt“*
- **Hook `scope_guard.py`:** blockiert nmap, nuclei, curl, ffuf & Co. gegen Ziele außerhalb von `$SECASSIST_SCOPE` bzw. `.claude/scope.yaml`
- **Rückfrage** vor jedem Netzwerk-Werkzeug, Scope-Datei und Hook sind gegen Änderungen durch Claude gesperrt

```bash
cp secassist/scope.example.yaml .claude/scope.yaml   # anpassen; wird nicht committet
pip install -e secassist                              # der Hook nutzt die Scope-Logik
claude
```

## Tests

```bash
pip install pytest && pytest -q
```

Die Tests prüfen Scope-Logik (inkl. Tricks wie `staging.example.com.evil.net`, Symlinks, `../`), Freigabe-Pflicht und die Agenten-Schleife mit einem gefälschten API-Client.

## Grenzen & Hinweise

- **Kein Ersatz für manuelles Pentesting.** Der Assistent findet vor allem Bekanntes, Fehlkonfigurationen und Code-Muster. Logikfehler und komplexe Zugriffskontrollen brauchen einen Menschen.
- **Befunde verifizieren** – vor allem „wahrscheinlich“ und „manuell prüfen“ – bevor sie an Kunden gehen.
- **Datenschutz:** Code, Scanner-Ausgaben und HTTP-Antworten werden an die Claude API geschickt. Für Kundenprojekte im Vertrag festhalten und einen AV-Vertrag (DPA) mit Anthropic abschließen. Keine Produktions-Secrets in Prompts geben.
- **Ablehnungen:** Die Sicherheitsfilter von Claude können legitime Sicherheitsarbeit gelegentlich ablehnen. Das Tool fängt das ab, nutzt automatisch ein Ausweichmodell (`fallbacks: "default"`) und protokolliert den Fall. Für regelmäßige Sicherheitsarbeit lohnt sich Anthropics *Cyber Verification Program*.
- **Scope-Hook (Claude Code):** Der Hook ist ein Sicherheitsnetz, keine Sandbox. Er erkennt Netzwerk-Werkzeuge nur am Anfang eines Befehls bzw. nach `|`, `&&`, `;`. Aufrufe wie `sudo nmap …`, `timeout 60 curl …` oder Skripte, die selbst Verbindungen aufbauen, erkennt er nicht. Die Rückfrage-Regeln in `.claude/settings.json` bleiben trotzdem aktiv.
- **Kosten:** Abrechnung pro Token (Claude Opus 5.5: 4 $ pro Mio. Eingabe-, 20 $ pro Mio. Ausgabe-Tokens). Große Code-Basen und lange Scans kosten entsprechend mehr; `--effort medium` und kleinere Ziele senken die Kosten. Verbrauch steht im Audit-Log (`usage`).
- **Rechtliches:** Nur mit schriftlicher Freigabe testen (§ 202a ff. StGB). `authorized_by` in der Scope-Datei immer ausfüllen.
