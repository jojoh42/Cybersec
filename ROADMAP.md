# Roadmap: Von 0 zum ersten Bug-Bounty-Report

Richtwert: 5–10 Std./Woche → ca. 4–6 Monate bis zur ersten ernsthaften Jagd.
Nicht hetzen: Verstehen schlägt Tempo. Zu jedem Lab eine kurze Notiz in `notizen/` schreiben.

---

## Phase 0 – Grundlagen (2–4 Wochen)

Ohne diese Basis bleibt Web-Hacking Auswendiglernen.

- [ ] **Linux-Kommandozeile**: OverTheWire *Bandit* Level 0–20
- [ ] **Netzwerk**: TCP/IP, DNS, Ports, was passiert bei `https://example.com` im Browser?
- [ ] **HTTP im Detail**: Methoden, Statuscodes, Header, Cookies, Sessions, CORS, Same-Origin-Policy
- [ ] **Web-Technik**: HTML, JavaScript-Grundlagen, wie arbeiten Frontend ↔ API ↔ Datenbank
- [ ] **Etwas Programmieren**: Python-Grundlagen (Skripte, `requests`), etwas SQL
- [ ] TryHackMe: *Pre Security* Pfad

## Phase 1 – Werkzeuge (1–2 Wochen, parallel)

- [ ] Burp Suite Community: Proxy, Repeater, Intruder, Decoder, Comparer
- [ ] Browser-DevTools: Network-Tab, Storage, Console
- [ ] Kommandozeile: `curl`, `ffuf`, `nmap` (nur gegen erlaubte Ziele!)
- [ ] Recon-Tools kennenlernen: `subfinder`, `httpx`, `amass`, `waybackurls`/`gau`
- [ ] Notizsystem festlegen (dieses Repo, Obsidian o. Ä.)

## Phase 2 – Die wichtigsten Schwachstellen (6–10 Wochen)

Hauptquelle: **PortSwigger Web Security Academy** – pro Thema erst Theorie, dann Apprentice-, dann Practitioner-Labs.
Begleitend: OWASP Top 10 lesen, Juice Shop lokal (`labs/`).

| # | Thema | Theorie | Apprentice-Labs | Practitioner-Labs |
|---|---|---|---|---|
| 1 | SQL Injection | [ ] | [ ] | [ ] |
| 2 | Cross-Site Scripting (XSS) | [ ] | [ ] | [ ] |
| 3 | Zugriffskontrolle / **IDOR** (Bounty-Klassiker!) | [ ] | [ ] | [ ] |
| 4 | Authentifizierung | [ ] | [ ] | [ ] |
| 5 | CSRF | [ ] | [ ] | [ ] |
| 6 | SSRF | [ ] | [ ] | [ ] |
| 7 | Path Traversal | [ ] | [ ] | [ ] |
| 8 | Information Disclosure | [ ] | [ ] | [ ] |
| 9 | Business-Logic-Fehler | [ ] | [ ] | [ ] |
| 10 | File Upload | [ ] | [ ] | [ ] |
| 11 | OS Command Injection | [ ] | [ ] | [ ] |
| 12 | XXE | [ ] | [ ] | [ ] |
| 13 | CORS-Fehlkonfiguration | [ ] | [ ] | [ ] |
| 14 | API-Testing (REST/GraphQL) | [ ] | [ ] | [ ] |
| 15 | JWT / OAuth | [ ] | [ ] | [ ] |
| 16 | Race Conditions | [ ] | [ ] | [ ] |
| 17 | SSTI (Server-Side Template Injection) | [ ] | [ ] | [ ] |
| 18 | Web-LLM-Angriffe / Prompt Injection | [ ] | [ ] | [ ] |

Tipp: IDOR, Access Control, Business Logic und Info Disclosure bringen Einsteigern in echten Programmen am häufigsten Funde – Scanner finden sie nicht.

## Phase 3 – Von echten Funden lernen (laufend, ab Phase 2)

- [ ] Täglich 1–2 Writeups lesen (Pentester Land, HackerOne Hacktivity, Bugcrowd Blog)
- [ ] Bugcrowd **VRT** lesen: Welche Bugs zählen, welche Priorität (P1–P5)?
- [ ] Bugcrowd University / LevelUp-Talks + "How to hack"-Playlist anschauen
- [ ] Buch: *Real-World Bug Hunting* (Yaworski) oder *Bug Bounty Bootcamp* (Vickie Li)
- [ ] Für jedes Writeup notieren: Ziel-Feature → Idee → Testschritt → Impact

## Phase 4 – Recon & Methodik (2–4 Wochen)

- [ ] [`METHODIK.md`](METHODIK.md) durcharbeiten und an dich anpassen
- [ ] Subdomain-Enumeration, Inhaltssuche, JS-Dateien nach Endpunkten durchsuchen
- [ ] App wie ein Nutzer komplett durchklicken, alle Rollen/Features kartieren
- [ ] 2–3 "Retired"-Maschinen/Challenges auf HTB oder TryHackMe ohne Hilfe lösen

## Phase 5 – Erste Bug-Bounty-Jagd

- [ ] Programm wählen: **breiter Scope**, viele Features, gern VDP (ohne Geld, weniger Konkurrenz) für den Start
- [ ] Policy komplett lesen, Scope notieren
- [ ] Ein Ziel **mehrere Wochen** tief testen statt viele oberflächlich
- [ ] Report mit [`vorlagen/bug-report.md`](vorlagen/bug-report.md) schreiben – klarer Impact, reproduzierbar
- [ ] Duplikate und "Informational" nicht persönlich nehmen – gehört dazu

## Phase 6 – Vertiefen & Spezialisieren

Wähle 1–2 Schwerpunkte: API-Security, Mobile (Android), Cloud (AWS/Azure-Fehlkonfiguration), AI/LLM-Security, Hardware/IoT.
Optional Zertifikate: **PortSwigger BSCP**, **HTB CBBH/CWES**, OSCP (eher Pentest).
