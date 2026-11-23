# Cybersec – Lernpfad Bug Bounty & Web-Hacking

Dieses Repo ist dein Lern-Logbuch: Roadmap, kuratierte Quellen, eigene Labs und Notizen.

## So benutzt du das Repo

| Datei / Ordner | Wofür |
|---|---|
| [`ROADMAP.md`](ROADMAP.md) | Lernpfad in 6 Phasen mit Checkboxen – hake ab, was du geschafft hast |
| [`PLATTFORMEN.md`](PLATTFORMEN.md) | Wochenplan & Checklisten für TryHackMe, HTB Academy, Hack The Box, CTFs |
| [`RESSOURCEN.md`](RESSOURCEN.md) | Die besten Seiten, Kurse, Bücher, Kanäle (inkl. Bugcrowd) |
| [`METHODIK.md`](METHODIK.md) | Checkliste: Wie gehe ich an ein Bug-Bounty-Ziel heran? |
| [`labs/`](labs/) | Absichtlich verwundbare Apps lokal per Docker starten – legal üben |
| [`vorlagen/`](vorlagen/) | Vorlagen für Bug-Reports und Lab-Writeups |
| [`notizen/`](notizen/) | Deine eigenen Notizen (eine Datei pro Thema oder Lab) |

## Wichtigste Regel ⚖️

Teste **nur**, was du testen darfst:
- eigene Labs (`labs/`), Trainingsplattformen (PortSwigger, TryHackMe, HTB …)
- Bug-Bounty-Programme **innerhalb des Scopes** und nach deren Regeln

Alles andere ist in Deutschland strafbar (§ 202a–c, § 303a/b StGB) – auch "nur mal schauen".
Lies vor jedem Programm die Policy (Scope, Out-of-Scope, verbotene Tests wie DoS/Social Engineering).

## Empfohlener Start (diese Woche)

1. Account bei [PortSwigger Web Security Academy](https://portswigger.net/web-security) anlegen (kostenlos).
2. Burp Suite Community installieren, Browser-Proxy einrichten.
3. Erste Lerneinheit: **SQL Injection – Apprentice-Labs**.
4. `labs/` starten und OWASP Juice Shop öffnen.
5. Bugcrowd-Account anlegen, [Hacker Docs](https://docs.bugcrowd.com/researchers/onboarding/welcome/) und die [VRT](https://bugcrowd.com/vulnerability-rating-taxonomy) lesen.
