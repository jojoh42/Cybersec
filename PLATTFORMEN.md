# Trainingsplattformen: konkreter Lernplan

Ergänzt die [`ROADMAP.md`](ROADMAP.md). Hier steht, **auf welcher Plattform du was machst**.
Prinzip: *Lernen* auf PortSwigger/TryHackMe/HTB Academy → *Anwenden* auf HTB-Maschinen & CTFs → *Echt* auf Bugcrowd.

## 1. Welche Plattform wofür?

| Plattform | Stärke | Kosten (grob) | Wann |
|---|---|---|---|
| [TryHackMe](https://tryhackme.com) | Geführte Räume, sehr einsteigerfreundlich, Browser-VM (AttackBox) | Viele Räume gratis, Premium ~14 $/Monat | Phase 0–2 |
| [PortSwigger Academy](https://portswigger.net/web-security) | Tiefste Web-Inhalte, 250+ Labs | Gratis | Phase 2 (Hauptquelle) |
| [HTB Academy](https://academy.hackthebox.com) | Strukturierte Module mit Prüfungen, Pfad *Web Penetration Tester* | Fundamental-Module teils gratis, sonst Cubes/Abo (Studenten-Abo günstig) | Phase 2–4 |
| [Hack The Box Labs](https://app.hackthebox.com) | Realistische Maschinen ohne Anleitung | Starting Point + aktive Maschinen gratis, Retired = VIP (~14 $/Monat) | Ab Phase 3 |
| [HTB Challenges](https://app.hackthebox.com/challenges) | Kurze Aufgaben, Kategorie *Web* | wie oben | Ab Phase 2 |
| [Hacker101 CTF](https://ctf.hacker101.com) | Web-CTF von HackerOne, kann Einladungen zu privaten Programmen bringen | Gratis | Phase 2–3 |
| [picoCTF](https://picoctf.org) | Einsteiger-CTF, ganzjährig | Gratis | Phase 0–2 |
| [Root-Me](https://www.root-me.org) | Hunderte Web-Challenges | Gratis | Phase 2–4 |
| [PentesterLab](https://pentesterlab.com) | Code-Review, JWT/OAuth sehr gut | Abo | Phase 4–6 |

Empfehlung zum Geldsparen: Erst die Gratis-Teile nutzen. Wenn du Geld ausgibst, dann **ein** Abo: entweder TryHackMe Premium (Einstieg) **oder** HTB Academy (Tiefe + Zertifikat).

---

## 2. Kombinierter Wochenplan (≈ 24 Wochen, 5–10 Std./Woche)

| Woche | Hauptaufgabe | Plattform | Nebenbei |
|---|---|---|---|
| 1–2 | Linux, Netzwerk, HTTP | THM *Pre Security* · OverTheWire *Bandit* 0–15 | – |
| 3–4 | Web-Grundlagen & Burp | HTB Academy: *Web Requests*, *Intro to Web Applications*, *Using Web Proxies* | THM-Raum *Burp Suite: The Basics* |
| 5 | Erste Maschinen | HTB *Starting Point* Tier 0–1 | picoCTF Web-Aufgaben |
| 6–7 | Recon & Fuzzing | HTB Academy: *Information Gathering – Web Edition*, *Web Fuzzing* | THM *Content Discovery*, *Subdomain Enumeration* |
| 8–9 | SQL Injection | PortSwigger SQLi-Labs · HTB Academy *SQL Injection Fundamentals*, *SQLMap Essentials* | Juice Shop (lokal) |
| 10–11 | XSS | PortSwigger XSS-Labs · HTB Academy *Cross-Site Scripting* | Hacker101 CTF starten |
| 12–13 | Access Control / IDOR / Auth | PortSwigger *Access control* + *Authentication* · HTB Academy *Broken Authentication* | HTB Starting Point Tier 2 |
| 14–15 | Command Injection, File Upload, File Inclusion | PortSwigger · HTB Academy (gleichnamige Module) | 1 Easy-Maschine (s. u.) |
| 16–17 | SSRF, SSTI, XXE | PortSwigger · HTB Academy *Server-side Attacks*, *Web Attacks* | HTB Web-Challenges (Easy) |
| 18–19 | APIs & GraphQL | PortSwigger *API testing* · HTB Academy *API Attacks*, *Attacking GraphQL* | lokal: crAPI |
| 20 | Methodik | HTB Academy *Bug Bounty Hunting Process* | Bugcrowd VRT + Hacker Docs |
| 21–22 | Ohne Anleitung | 3–4 Easy-HTB-Maschinen **ohne Writeup** | Writeups erst danach lesen |
| 23–24 | Erste echte Jagd | Bugcrowd: ein VDP/Programm mit breitem Scope | Weiter 1 Lab/Woche |

---

## 3. HTB Academy – Pfad „Web Penetration Tester“ (Checkliste)

Früher „Bug Bounty Hunter“, seit 10/2025 umbenannt. Der komplette Pfad (100 %) ist Voraussetzung für die Zertifizierung **HTB CWES** (Nachfolger von CBBH).
Link: <https://academy.hackthebox.com/path/preview/bug-bounty-hunter>

- [ ] 1. Web Requests *(Fundamental)*
- [ ] 2. Introduction to Web Applications *(Fundamental)*
- [ ] 3. Using Web Proxies
- [ ] 4. Information Gathering – Web Edition
- [ ] 5. Web Fuzzing
- [ ] 6. JavaScript Deobfuscation
- [ ] 7. Cross-Site Scripting (XSS)
- [ ] 8. SQL Injection Fundamentals
- [ ] 9. SQLMap Essentials
- [ ] 10. Command Injections
- [ ] 11. File Upload Attacks
- [ ] 12. Server-side Attacks
- [ ] 13. Login Brute Forcing
- [ ] 14. Broken Authentication
- [ ] 15. Web Attacks
- [ ] 16. File Inclusion
- [ ] 17. Attacking GraphQL
- [ ] 18. API Attacks
- [ ] 19. Attacking Common Applications
- [ ] 20. Bug Bounty Hunting Process

Jedes Modul endet mit einem *Skills Assessment* – das ist der eigentliche Test, ob du es verstanden hast.

Weitere nützliche HTB-Academy-Pfade: *Cracking into Hack the Box* (Einstieg in die Plattform), *Information Security Foundations*, später *Penetration Tester* (eher Netzwerk/AD, Richtung CPTS).

---

## 4. TryHackMe – Pfade (Checkliste)

Übersicht: <https://tryhackme.com/paths>

- [ ] **Pre Security** – Netzwerk, Web, Linux, Windows (Phase 0)
- [ ] **Cyber Security 101** – Werkzeuge & Grundlagen breit
- [ ] **Jr Penetration Tester** – 2026 neu aufgebaut: Web-Security-Modul (SQLi, XSS, CSRF, SSRF, IDOR, Auth, Traversal, Command Injection, API), dazu Netzwerk & Active Directory. Vorbereitung auf das THM-Zertifikat *PT1*
- [ ] **Web Application Pentesting** – vertieft, OWASP Top 10, Burp, sqlmap
- [ ] **Web Application Red Teaming** – fortgeschrittene Fortsetzung (später)

Gute Einzelräume (Suche auf THM): *HTTP in Detail*, *Walking An Application*, *Burp Suite: The Basics*, *OWASP Top 10*, *OWASP Juice Shop*, *IDOR*, *SSRF*, *File Inclusion*, *Authentication Bypass*, *OWASP API Security Top 10*.

---

## 5. Hack The Box Labs – Maschinen

**Vorgehen pro Maschine**
1. Mindestens 1–2 Stunden selbst versuchen, Notizen mit [`vorlagen/lab-writeup.md`](vorlagen/lab-writeup.md).
2. Festgefahren? Nur einen *Hinweis* holen (HTB-Forum, Discord), nicht die Lösung.
3. Danach **immer** ein Writeup/Video ansehen – man lernt dort die Abkürzungen:
   [IppSec (YouTube)](https://www.youtube.com/@ippsec) · Suche über [ippsec.rocks](https://ippsec.rocks) · [0xdf Writeups](https://0xdf.gitlab.io)

**Reihenfolge**
- [ ] *Starting Point* Tier 0 (gratis, mit Anleitung)
- [ ] *Starting Point* Tier 1
- [ ] *Starting Point* Tier 2
- [ ] Aktuelle Easy-Maschinen (gratis, wöchentlich neu) – Filter: Difficulty *Easy*
- [ ] Retired Easy-Maschinen mit Web-Einstieg (VIP), z. B.: *Precious*, *Busqueda*, *Sau*, *Keeper*, *Analytics*, *Codify*, *PermX*, *Editorial*, *Titanic*
- [ ] HTB *Challenges* → Kategorie **Web**, Easy

Hinweis: HTB-Maschinen enden meist mit Root-Rechten (Privilege Escalation). Für Bug Bounty ist vor allem der **Web-Einstieg** (Foothold) relevant – den Rest mitzunehmen schadet aber nicht.

---

## 6. CTFs & Wettbewerbe

- [CTFtime](https://ctftime.org) – Kalender aller CTFs; such dir Events mit Schwierigkeit „beginner“
- **HTB Cyber Apocalypse** – jährlicher großer, einsteigerfreundlicher CTF
- [picoCTF](https://picoctf.org) – jährlicher Wettbewerb + Übungs-Archiv
- [Cyber Security Challenge Germany (CSCG)](https://www.cscg.de) 🇩🇪 – für junge Leute/Studierende, mit Qualifikation für die European Cyber Security Challenge
- [Hacky Easter](https://hackyeaster.com) – jährlich zu Ostern, gut für Einsteiger
- Bugcrowd Events / Bug Bashes (siehe [`RESSOURCEN.md`](RESSOURCEN.md))

Tipp: CTFs im Team spielen (z. B. Discord-Teams oder CCC-Gruppe vor Ort) – man lernt viel schneller.

---

## 7. Fortschritt festhalten

| Plattform | Profil / Rang | Stand (Datum) |
|---|---|---|
| PortSwigger | Labs gelöst: | |
| TryHackMe | Rang / Räume: | |
| HTB Academy | Module: /20 | |
| HTB Labs | Maschinen: | |
| Bugcrowd | Reports / Punkte: | |
