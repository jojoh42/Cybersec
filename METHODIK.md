# Methodik-Checkliste für ein Bug-Bounty-Ziel

Kopiere diese Datei pro Ziel nach `notizen/<programm>.md` und arbeite sie ab.

## 0. Vorbereitung
- [ ] Programm-Policy komplett gelesen
- [ ] In-Scope-Domains/Apps notiert
- [ ] Out-of-Scope & verbotene Testarten notiert (DoS, Social Engineering, Rate-Limits …)
- [ ] Eigene Test-Accounts angelegt (mind. 2 pro Rolle – für IDOR/Access-Control-Tests)
- [ ] Ggf. vorgeschriebener Header/User-Agent in Burp konfiguriert

## 1. Recon (Aufklärung)
- [ ] Subdomains: `subfinder -d ziel.de`, crt.sh
- [ ] Lebende Hosts: `httpx`
- [ ] Historische URLs: `gau` / `waybackurls`
- [ ] Inhalte/Verzeichnisse: `ffuf` mit SecLists (Rate-Limits beachten!)
- [ ] JavaScript-Dateien nach API-Endpunkten, Parametern, Keys durchsuchen
- [ ] Technologie-Stack erkennen (Wappalyzer, Header)

## 2. Die App verstehen (wichtigster Schritt!)
- [ ] Jede Funktion als normaler Nutzer durchklicken – Burp läuft mit
- [ ] Rollen & Rechte aufschreiben (Gast, User, Admin, Org-Owner …)
- [ ] Wo werden IDs übergeben? Wo werden Dateien hochgeladen? Wo werden URLs abgerufen?
- [ ] Neue/selten genutzte Features finden (Changelog, Blog des Unternehmens)

## 3. Gezielt testen
| Feature | Denk an |
|---|---|
| IDs in URL/Body/API | IDOR, Access Control |
| Login/Registrierung/Passwort-Reset | Auth-Bypass, Account-Takeover, Token-Leaks |
| Eingaben, die wieder angezeigt werden | XSS, SSTI |
| Suche/Filter/Sortierung | SQLi, NoSQLi |
| "URL importieren", Webhooks, PDF-Generatoren | SSRF |
| Datei-Upload | File Upload, XSS via SVG, Path Traversal |
| Zahlungen, Gutscheine, Limits | Business Logic, Race Conditions |
| Zustandsändernde Aktionen | CSRF |
| API (REST/GraphQL) | Mass Assignment, Introspection, fehlende Auth |
| KI-Chatbots | Prompt Injection, Datenabfluss |

## 4. Bevor du reportest
- [ ] Ist es reproduzierbar? (Schritt für Schritt)
- [ ] Was ist der **konkrete Impact**? (Welche Daten/Aktionen eines *anderen* Nutzers?)
- [ ] In Scope? Nicht in der Liste ausgeschlossener Bug-Typen?
- [ ] VRT-Kategorie bestimmt
- [ ] Keine echten Nutzerdaten unnötig abgerufen – nur eigene Test-Accounts
- [ ] Report mit `vorlagen/bug-report.md` geschrieben
