# Lokale Übungs-Labs

Hier übst du **legal** an absichtlich verwundbaren Apps.

## Voraussetzung
[Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/Mac) oder Docker Engine (Linux).

## Starten
```bash
cd labs
docker compose up -d
```

| App | URL | Hinweis |
|---|---|---|
| OWASP Juice Shop | http://localhost:3000 | Score-Board finden ist die erste Challenge 😉 |
| DVWA | http://localhost:8080 | Login `admin` / `password`, dann "Create / Reset Database"; unter "DVWA Security" den Level einstellen |

Die Ports sind nur an `127.0.0.1` gebunden – die Apps sind von außen nicht erreichbar. So soll es bleiben.

## Stoppen
```bash
docker compose down
```

## Weitere gute Übungsziele
- [OWASP crAPI](https://github.com/OWASP/crAPI) – verwundbare API (ideal für IDOR/BOLA)
- [OWASP WebGoat](https://github.com/WebGoat/WebGoat) – geführte Lektionen
- [VAmPI](https://github.com/erev0s/VAmPI) – kleine verwundbare REST-API

## Arbeitsweise
1. Burp Suite starten, Browser über Burp-Proxy leiten.
2. Eine Schwachstelle nach der anderen angehen (passend zur Phase in der Roadmap).
3. Writeup mit `../vorlagen/lab-writeup.md` in `../notizen/` speichern.
