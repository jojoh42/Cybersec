# [Bug-Typ] in [Feature] ermöglicht [Impact]

> Beispiel-Titel: *IDOR in /api/v2/invoices/{id} ermöglicht das Lesen fremder Rechnungen*

## Zusammenfassung
Ein bis drei Sätze: Was ist kaputt, wo, und was kann ein Angreifer damit tun?

## Betroffenes Ziel
- URL / Endpunkt:
- Parameter:
- VRT-Kategorie (Bugcrowd):

## Schritte zur Reproduktion
1. Account A (`angreifer@…`) und Account B (`opfer@…`) anlegen.
2. …
3. …

## Proof of Concept
Request/Response (sensible Daten schwärzen), Screenshots oder kurzes Video.

```http
GET /api/v2/invoices/1337 HTTP/2
Host: ziel.example
Cookie: session=<Account A>
```

## Impact
Was genau kann ein Angreifer erreichen? Wie viele Nutzer betroffen? Welche Daten?
(Realistisch bleiben – Übertreibung kostet Glaubwürdigkeit.)

## Empfehlung zur Behebung
z. B. serverseitig prüfen, ob die angefragte Ressource dem eingeloggten Nutzer gehört.
