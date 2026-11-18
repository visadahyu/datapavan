---
title: "Hinweise zum Datenschutz"
---

Dies ist eine Übersetzung. Maßgeblich ist der [englische Text](https://datapavan.org/privacy/index.html).

- **Gültig ab:** 2026-11-07
- **Aktualisiert:** 2026-11-18, mit den Zeilen zu Datapavan Advanced für Version 0.2.0, die noch nicht veröffentlicht ist
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

**Datapavan Advanced behält ab 0.2.0 außerdem:**

- **Ein Verbindungsprotokoll, nur wenn Sie sich entscheiden, eines zu führen.** Sie wählen: nichts behalten, 1, 7 oder
  30 Tage; bis Sie wählen, behält es nichts. Jeder Eintrag enthält die App, wohin sie eine Verbindung aufgebaut hat (die
  Adresse, den Port und den Namen, mit der Angabe, woher Datapavan den Namen kennt), die Bytes in jede Richtung, den
  Zeitpunkt und ob Sie die App in dem Moment benutzt haben, sie mit ihrer Benachrichtigung lief oder keines von beiden.
  Jeder Eintrag ist mit einem Schlüssel für seinen Tag verschlüsselt, den der Keystore von Android schützt; auf einem
  Telefon mit Displaysperre lassen sich frühere Tage nur lesen, solange es entsperrt ist. Tage, die über Ihre Wahl
  hinausgehen, werden mit ihren Schlüsseln gelöscht, und ein Tippen löscht alles. Für Apps, die Sie durch Ihr Tool zum
  Umgehen von Netzsperren senden, behält das Protokoll kein Ziel, es sei denn, Sie schalten das ein.
- **Der jüngste Datenverkehr jeder App, für die Ansicht „Now“,** nur im Arbeitsspeicher. Er verschwindet, wenn die
  Firewall beendet wird.
- **Die Einstellungen Ihres Tools zum Umgehen von Netzsperren:** ob Apps durch das Tool gehen und welche, Host und Port
  des Tools sowie das Passwort, das Datapavan dafür erstellt hat und das mit einem Schlüssel verschlüsselt ist, den der
  Keystore von Android schützt.
- **Die Apps, die Sie von der Firewall ausschließen,** die dann ohne die Firewall ins Internet gehen: ihre Namen,
  bis Sie sie wieder einbeziehen.

## Version 0.1 kann keine Netzwerkverbindungen öffnen

Datapavan Basic 0.1 fordert die Berechtigung INTERNET nicht an, daher verhindert Android selbst, dass sie
Netzwerkverbindungen öffnet. Der Build schlägt fehl, wenn eine Komponente versucht, diese Berechtigung hinzuzufügen.
Wie jede App kann sie trotzdem Informationen an eine andere App übergeben, wenn Sie sie darum bitten, zum Beispiel
wenn Sie einen Link öffnen.

Was Android selbst tut, liegt außerhalb der Kontrolle von Datapavan. Auf Telefonen mit Googles Diensten kann Play Protect Google Informationen über die Apps geben, die Sie aus beliebigen Quellen installieren, auch über Datapavan, und ihm eine unbekannte App zur Prüfung senden. Einen Teil davon können Sie in den Einstellungen von Play Protect im Play Store ausschalten. Auch die Hardware-Prüfung von Datapavan kann Android dazu bringen, Google zu kontaktieren: Auf Telefonen, die ihre Attestierungsschlüssel vom Provisioning-Server von Google beziehen, bittet eine Prüfung, die keine mehr vorfindet, Android um weitere (Android 13 benachrichtigt den Provisioning-Dienst, und ab Android 14 wendet sich der Keystore an ihn), und Android lädt sie über seine eigene Verbindung. Datapavan selbst sendet nichts.

## Womit sich Datapavan Advanced verbindet

Datapavan Advanced leitet ab 0.2.0 den Datenverkehr Ihrer Apps dorthin weiter, wohin sie ihn senden, durch die
Firewall auf dem Telefon; nichts davon geht an uns. Von sich aus fragt es den DNS-Resolver Ihres Netzwerks nach den
Namen, die Apps nachschlagen, wie es das Telefon ohne Datapavan Advanced täte, über eine verschlüsselte Verbindung,
wo das Telefon eine solche nutzte. Wenn Sie Apps durch Ihr Tool zum Umgehen von Netzsperren senden, gehen ihre
Namensabfragen an das Tool, und ihre übrigen DNS-Anfragen gehen durch das Tool an Quad9, eine Schweizer Stiftung,
die keine Adressen protokolliert, sodass Quad9 die Adresse des Tools sieht, nicht Ihre.

## Berechtigungen und wofür sie nötig sind

| Berechtigung | Wofür | Ab |
|---|---|---|
| Installierte Apps sehen | Apps und ihre Berechtigungen auflisten | v0.1 |
| Zugriff auf Nutzungsdaten (von Ihnen in den Einstellungen erteilt; optional) | Zeigen, wie viele Daten jede App gesendet und empfangen hat und welche Apps Sie lange nicht geöffnet haben. Dafür liest Datapavan nur Summen und das Datum, an dem jede App zuletzt genutzt wurde, und behält nichts davon; Datapavan Basic liest nie, welche App Sie wann geöffnet haben. Wenn Sie eine einzelne Aktivität in einer App prüfen, liest es außerdem die Gesamtzähler des Datenverkehrs des Telefons, für die keine Berechtigung nötig ist, um zu sehen, ob die Zählung von Android aktuell ist; diese Zahlen bleiben im Arbeitsspeicher, solange die Prüfung auf dem Bildschirm ist | v0.1 |
| Zugriff auf Nutzungsdaten, in Datapavan Advanced | Für jede Verbindung erkennen, ob Sie ihre App in dem Moment benutzt haben, sie mit einer Benachrichtigung lief, die Android anzeigte (Musik, Navigation), oder keines von beiden. Dafür liest Advanced außerdem die Aufzeichnung von Android seit dem Start des Telefons darüber, welche App wann auf dem Bildschirm war, welche Apps einen Vordergrunddienst ausführten, welche Sie auf andere Weise benutzt haben (etwa durch Tippen auf ihre Benachrichtigung) und wann sich der Bildschirm ein- oder ausschaltete und der Sperrbildschirm erschien; und ob jede App Benachrichtigungen anzeigen darf. Was es dabei erfährt, behält es nur an zwei Stellen: im Arbeitsspeicher für die Ansicht „Now“ und, wenn Sie ein Verbindungsprotokoll führen, als Zustand jedes Eintrags, für die von Ihnen gewählten Tage | Datapavan Advanced, ab 0.2.0 |
| Netzwerkstatus | Erkennen, ob ein VPN aktiv ist. Diese Berechtigung erlaubt keine Verbindung | v0.1 |
| Überlagerungen anderer Apps ausblenden | Ab Android 12: Solange Datapavan auf dem Bildschirm ist, können andere Apps nichts darüber anzeigen. Diese Berechtigung erlaubt keine Verbindung | Datapavan Basic ab der Version nach 0.1.2 und Datapavan Advanced |
| VPN (von Ihnen erteilt) | Die **lokale** Firewall. Der Datenverkehr wird auf dem Telefon gefiltert und nie an uns gesendet | Datapavan Advanced, ab 0.2.0 |
| Internet | Den Datenverkehr anderer Apps durch die lokale Firewall weiterleiten. Datapavan Basic fragt nie danach | Datapavan Advanced, ab 0.2.0 |

## Optionale Aktualisierungen der Tracker-Listen (geplant)

Datapavan selbst importiert nur signierte Listendateien. Falls optionale Downloads kommen, werden sie
von einem öffentlichen Spiegelserver geladen, und nur, wenn Sie das einschalten. Wie bei jedem Download:

- sieht der Betreiber des Spiegelservers Ihre IP-Adresse und den Zeitpunkt der Anfrage;
- können der Betreiber und jeder, der Ihr Netzwerk beobachtet, erkennen, dass das Gerät Datapavan nutzt.

Die Anfrage enthält nichts über Ihr Telefon, Ihre Apps oder Ihre Aktivität. Aktualisierungen sind signiert, und ältere
Listen werden nie anstelle neuerer akzeptiert. Sie können Aktualisierungen ausschalten und Listendateien
manuell importieren. Sobald es Spiegelserver gibt, werden diese Hinweise jeden Betreiber nennen und angeben, was er
protokolliert und wie lange.

## Kontakt

Fragen zu diesen Hinweisen: Eröffnen Sie ein Issue auf GitHub. Für alles Vertrauliche nutzen Sie das private
Meldeformular, das in [SECURITY.md](https://github.com/visadahyu/datapavan/blob/main/SECURITY.md) genannt wird.
