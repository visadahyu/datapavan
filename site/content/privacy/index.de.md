---
title: "Hinweise zum Datenschutz"
---

Dies ist eine Übersetzung. Maßgeblich ist der [englische Text](https://datapavan.org/privacy/index.html).

- **Gültig ab:** 2026-11-07
- **Verantwortlich:** der Maintainer von Datapavan (mehdashti), bis die Visadahyu-Stiftung gegründet ist

**Datapavan sammelt keine Daten über Sie.**

## Was das in der Praxis bedeutet

- **Keine Nutzungsanalyse, keine Absturzberichte, keine Telemetrie.** Die App enthält keine SDKs von Dritten, die Daten senden könnten.
- **Keine Konten.** Sie registrieren sich nie und geben uns nie etwas.
- **Keine Server, die Nutzerdaten empfangen.** Die App kontaktiert keine. Die Website des Projekts, datapavan.org, ist statisch und führt kein Zugriffsprotokoll. Auch über die Downloads, die sie anbietet, führt sie keine Aufzeichnungen. Downloads von GitHub und aus App-Stores unterliegen deren eigenen Richtlinien.
- **Alles bleibt auf Ihrem Telefon.** Die gesamte Analyse findet auf dem Gerät statt. Die eigenen Daten von Datapavan liegen im privaten Speicher der App.
- **Keine Sicherungen verlassen das Telefon.** Die Cloud-Sicherung von Android und die Übertragung von Gerät zu Gerät sind für die Daten von Datapavan deaktiviert.
- **Die Deinstallation löscht die Daten von Datapavan.**

## Was Datapavan auf Ihrem Telefon behält

- **Das Protokoll des Plans.** Für jede Änderung, die Sie über den Plan vornehmen: der Paketname der App,
  der Zeitpunkt, der geöffnete Bildschirm und was die App vorher und nachher hatte (ihre sensiblen
  Berechtigungen, ihre speziellen Zugriffe und die VPN-Berechtigung sowie ob sie aktiviert und installiert war).
  So können Sie eine Änderung rückgängig machen und sehen, ob eine zurückgekehrt ist. Auf dem Bildschirm des
  Protokolls lässt es sich mit einem Tippen löschen.
- **Die strenge Prüfung der Sensoren:** welchen Zugriff jede App hatte, als Sie sie geprüft haben.
- **Ihre Einstellungen:** die Darstellung und vor Android 13 die von Ihnen gewählte Sprache.
- **Die Ergebnisse der Tracker-Suche,** damit unveränderte Apps nicht erneut durchsucht werden, und von Ihnen
  importierte **Datenpakete**.

All das bleibt im privaten Speicher der App und wird nie gesichert oder gesendet. Wer Datapavan auf Ihrem
entsperrten Telefon öffnen kann, kann es sehen, genau wie den Rest der App.

## Version 0.1 kann keine Netzwerkverbindungen öffnen

Version 0.1 („Audit“) fordert die Berechtigung INTERNET nicht an, daher verhindert Android selbst, dass sie
Netzwerkverbindungen öffnet. Der Build schlägt fehl, wenn eine Komponente versucht, diese Berechtigung hinzuzufügen.
Wie jede App kann sie trotzdem Informationen an eine andere App übergeben, wenn Sie sie darum bitten, zum Beispiel
wenn Sie einen Link öffnen.

Was Android selbst tut, liegt außerhalb der Kontrolle von Datapavan. Auf Telefonen mit Googles Diensten kann Play Protect Google Informationen über die Apps geben, die Sie aus beliebigen Quellen installieren, auch über Datapavan, und ihm eine unbekannte App zur Prüfung senden. Einen Teil davon können Sie in den Einstellungen von Play Protect im Play Store ausschalten.

## Berechtigungen und wofür sie nötig sind

| Berechtigung | Wofür | Ab |
|---|---|---|
| Installierte Apps sehen | Apps und ihre Berechtigungen auflisten | v0.1 |
| Zugriff auf Nutzungsdaten (von Ihnen in den Einstellungen erteilt; optional) | Zeigen, wie viele Daten jede App gesendet und empfangen hat und welche Apps Sie lange nicht geöffnet haben. Datapavan liest nur Summen und das Datum, an dem jede App zuletzt genutzt wurde, nie welche App Sie wann geöffnet haben, und behält nichts davon. Wenn Sie eine einzelne Aktivität in einer App prüfen, liest es außerdem die Gesamtzähler des Datenverkehrs des Telefons, für die keine Berechtigung nötig ist, um zu sehen, ob die Zählung von Android aktuell ist; diese Zahlen bleiben im Arbeitsspeicher, solange die Prüfung auf dem Bildschirm ist | v0.1 |
| Netzwerkstatus | Erkennen, ob ein VPN aktiv ist. Diese Berechtigung erlaubt keine Verbindung | v0.1 |
| VPN (von Ihnen erteilt) | Die **lokale** Firewall. Der Datenverkehr wird auf dem Telefon gefiltert und nie an uns gesendet | Datapavan Watch, eine eigene App, ab v0.2 |
| Internet | Den Datenverkehr anderer Apps durch die lokale Firewall weiterleiten. Datapavan selbst fragt nie danach | Datapavan Watch, eine eigene App, ab v0.2 |

## Optionale Aktualisierungen der Tracker-Listen (geplant)

Datapavan selbst importiert nur signierte Listendateien. Falls optionale Downloads kommen, wird Datapavan Watch sie
von einem öffentlichen Spiegelserver laden, und nur, wenn Sie das einschalten. Wie bei jedem Download:

- sieht der Betreiber des Spiegelservers Ihre IP-Adresse und den Zeitpunkt der Anfrage;
- können der Betreiber und jeder, der Ihr Netzwerk beobachtet, erkennen, dass das Gerät Datapavan nutzt.

Die Anfrage enthält nichts über Ihr Telefon, Ihre Apps oder Ihre Aktivität. Aktualisierungen sind signiert, und ältere
Listen werden nie anstelle neuerer akzeptiert. Sie können Aktualisierungen ausschalten und Listendateien
manuell importieren. Sobald es Spiegelserver gibt, werden diese Hinweise jeden Betreiber nennen und angeben, was er
protokolliert und wie lange.

## Kontakt

Fragen zu diesen Hinweisen: Eröffnen Sie ein Issue auf GitHub. Für alles Vertrauliche nutzen Sie das private
Meldeformular, das in [SECURITY.md](https://github.com/visadahyu/datapavan/blob/main/SECURITY.md) genannt wird.
