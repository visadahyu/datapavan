---
title: "Was ein Bot oder eine Mini-App sehen kann"
---

Chat-Apps lassen Bots und kleine Apps anderer Leute in sich laufen. Android sieht nur die Chat-App, daher sagt Ihnen
nichts auf Ihrem Telefon, was ein Bot oder eine Mini-App bekommt, wenn Sie sie nutzen. Diese Seite sagt, was sie
bekommen und was die echten Gefahren sind. Sie beginnt mit Telegram und endet mit anderen Apps.

Geprüft am 13. November 2026. Diese Apps ändern sich alle paar Monate; wenn hier etwas falsch oder veraltet ist,
[sagen Sie es uns](https://github.com/visadahyu/datapavan/issues).

## Wenn Sie bei einem Telegram-Bot auf „Starten“ tippen

Der Betreiber des Bots bekommt Ihre Telegram-ID-Nummer, Ihren Namen, Ihren Benutzernamen, falls Sie einen haben, die
Sprache Ihrer App und ob Sie für Premium bezahlen ([Telegram Bot API](https://core.telegram.org/bots/api);
[Datenschutzerklärung von Telegram](https://telegram.org/privacy)). Der Betreiber kann außerdem Ihre Profilbilder, Ihre
Bio, Ihren Geburtstag und die Beiträge des persönlichen Kanals in Ihrem Profil abrufen
([Bot API](https://core.telegram.org/bots/api)). Die Datenschutzerklärung von Telegram bezeichnet Ihre Fotos als
öffentlich; für den Rest sagen die Seiten von Telegram nicht, ob Ihre Datenschutzeinstellungen diese Abfragen
einschränken.

Ihre Telefonnummer, Ihre Kontakte, Ihre anderen Chats, Ihren Standort und Ihre Dateien bekommt der Bot nicht.
Ihre Nummer, Ihren Standort oder Ihre Adresse bekommt er nur, wenn Sie sie teilen: mit einer Schaltfläche, die dafür
gemacht ist, indem Sie sie selbst senden, indem Sie sie eingeben, wenn Sie über den Bot bezahlen, oder, beim Standort,
indem Sie ihn erlauben, wenn Sie den Bot inline nutzen ([Bot API](https://core.telegram.org/bots/api);
[Datenschutzerklärung von Telegram](https://telegram.org/privacy)).

Ihr Telefon verbindet sich nie mit dem Computer des Bots. Telegram transportiert die Nachrichten und Dateien in beide
Richtungen und erstellt Linkvorschauen auf seinen eigenen Servern, daher sieht der Bot Ihre IP-Adresse nicht
([Bot API](https://core.telegram.org/bots/api);
[Telegram für Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/res/values/strings.xml)).
Telegram sagt das nicht ausdrücklich; es ergibt sich daraus, wie Bots funktionieren, und als einzigen Weg, auf dem ein
Bot Ihre IP-Adresse bekommt, nennt die Datenschutzerklärung von Telegram einen Link oder eine Schaltfläche zu einer
Website, die sein Betreiber kontrolliert ([Datenschutzerklärung von Telegram](https://telegram.org/privacy)).

Alles, was Sie dem Bot senden, geht an seinen Betreiber, der es lesen kann. Ein Bot kann keinen Chat mit Ihnen
beginnen, aber sobald Sie auf „Starten“ getippt haben, kann er Ihnen jederzeit schreiben, bis Sie ihn blockieren
([Telegram-Bots](https://core.telegram.org/bots); [Bot-FAQ](https://core.telegram.org/bots/faq)). Wenn Sie einem
Business-Konto schreiben, kann das auch heißen, dass Sie seinem Bot schreiben, der dann dieselben Angaben über Sie
bekommt ([Datenschutzerklärung von Telegram](https://telegram.org/privacy)).

## Was daran etwas ändert

**Kontakt oder Standort teilen.** Wenn Sie auf eine Schaltfläche tippen, um Ihren Kontakt oder Ihren Standort zu
teilen, bekommt der Bot Ihre Telefonnummer oder Ihren Aufenthaltsort.

**Die Mini-App des Bots öffnen.** Eine Mini-App ist die Website des Betreibers, geöffnet in Telegram. Die Website sieht
Ihre IP-Adresse und damit ungefähr, wo Sie sind ([Mini-App-Bedingungen von Telegram](https://telegram.org/tos/mini-apps)).
Unter Android sieht sie außerdem Hersteller, Modell und Android-Version Ihres Telefons
([Quellcode von Telegram für Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java)).
Je nachdem, wie Sie sie geöffnet haben, gibt Telegram ihr außerdem eine signierte Kopie Ihrer Telegram-Identität und
manchmal Angaben zu dem Chat, aus dem Sie sie geöffnet haben ([Telegram-Mini-Apps](https://core.telegram.org/bots/webapps);
[Mini-App-Bedingungen](https://telegram.org/tos/mini-apps)). Jeder Tracker, den die Seite lädt, sieht Ihre IP-Adresse
ebenfalls. Eine Studie, die noch nicht von anderen Fachleuten begutachtet wurde, testete 278 Mini-Apps aus einem
Katalog: 59 % sendeten Daten an mindestens ein externes Unternehmen, meist für Analyse oder Werbung, das ihre
Datenschutzerklärung nicht abdeckte, und die meisten hatten keine eigene Datenschutzerklärung, nur die
Standard-Datenschutzerklärung von Telegram ([TeleGapper, 2026](https://arxiv.org/html/2608.13390)).

Unter Android fragt Telegram Sie in einem eigenen Fenster, das den Bot nennt, bevor eine Mini-App Ihre Telefonnummer,
Ihren Standort, Ihre Kamera oder Ihr Mikrofon bekommt, und Sie können ablehnen. Die einzige Ausnahme im Code ist
Telegrams eigene Altersprüfung, die Kamera und Mikrofon ohne dieses Fenster bekommt
([Telegram-Mini-Apps](https://core.telegram.org/bots/webapps);
[Quellcode von Telegram für Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java)).
Die Dokumentation von Telegram beschreibt keine Abfrage, bevor eine Mini-App die Bewegungssensoren Ihres Telefons
nutzt, bis zu 5 MB Daten auf Ihrem Telefon speichert oder den ganzen Bildschirm füllt
([Telegram-Mini-Apps](https://core.telegram.org/bots/webapps)). Eine Vollbildseite kann genau wie Telegram aussehen;
behandeln Sie ein Anmeldeformular in einer Mini-App also als Warnzeichen
([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/)).

**Auf einen Link tippen.** Die Website dahinter sieht Ihre IP-Adresse
([Datenschutzerklärung von Telegram](https://telegram.org/privacy)).

**Eine Wallet verbinden oder eine Transaktion signieren.** Sie können Geld verlieren
([Cointelegraph](https://cointelegraph.com/magazine/ethereum-phishing-drainers-ton-bitcoin/)).

## Die echten Gefahren

Die meisten brauchen keinen Programmfehler: Jemand verleitet Sie dazu, etwas herauszugeben.

1. **Jemand gelangt in Ihr Konto.** Ein Bot oder ein Fremder schickt Sie zu einer Mini-App oder einer Seite: ein
   Gratisgeschenk, eine „Stimm für mich“-Seite, eine gefälschte Sicherheitsprüfung. Die Mini-App oder Seite fragt nach
   Ihrer Telefonnummer und Ihrem Anmeldecode, zeigt einen QR-Code zum Scannen oder bringt Telegram dazu, Ihnen eine
   echte Anmeldeanfrage zur Bestätigung zu zeigen
   ([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/);
   [Kaspersky](https://www.kaspersky.com/blog/telegram-takeover-contest/47195/);
   [CYFIRMA](https://www.cyfirma.com/research/re-emerging-telegram-phishing-campaign-targeting-user-authorization-prompts/)).
   Geben Sie Ihren Anmeldecode nur in der Telegram-App selbst ein oder auf Telegrams eigener Anmeldeseite, die Sie
   selbst geöffnet haben, und geben Sie ihn nie weiter ([Telegram-FAQ](https://telegram.org/faq)). Scannen Sie einen
   Anmelde-QR-Code nur, wenn Telegram ihn auf Ihrem eigenen Computer anzeigt, nie von einer Seite, die Ihnen jemand
   geschickt hat. Tippen Sie nie auf „Ja, ich bin das“ bei einer Anmeldeanfrage, die Sie nicht selbst
   ausgelöst haben. Legen Sie ein Passwort für die zweistufige Bestätigung fest und geben Sie es nirgends ein außer in
   Telegram. Wenn Sie etwas davon schon getan haben, gehen Sie zu Einstellungen > Geräte, beenden Sie alle anderen
   Sitzungen und ändern Sie dieses Passwort.
2. **Eine Seite, die wie ein echter Dienst aussieht,** fordert Sie auf, sich anzumelden, eine „Einzahlung“ zu leisten,
   bevor Sie Einnahmen abheben können, die es nicht gibt, oder eine App zu installieren
   ([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/);
   [BleepingComputer](https://www.bleepingcomputer.com/news/security/telegram-mini-apps-abused-for-crypto-scams-android-malware-delivery/)).
3. **Ein falscher „Verifizierungs“-Bot** fordert Sie auf, einen Befehl in Ihren Computer einzufügen, und der Befehl
   installiert Schadsoftware
   ([Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/criminals-exploit-telegram-captcha-to-trick-victims-into-installing-malware);
   [Cointelegraph](https://cointelegraph.com/news/telegram-verification-bots-carry-crypto-stealing-malware)).
4. **Eine Mini-App sendet Ihre Daten unbemerkt an Tracker** ([TeleGapper, 2026](https://arxiv.org/html/2608.13390)).
5. **Selten ein Fehler in Telegram selbst.**
   - 2024 erlaubte eine Schwachstelle einem Angreifer, eine Android-App zu senden, die in einem Chat wie ein Video
     aussah; installiert wurde nichts, es sei denn, Sie tippten darauf und stimmten der Installation zu. Telegram behob
     sie in Version 10.14.5
     ([ESET](https://www.welivesecurity.com/en/eset-research/cursed-tapes-exploiting-evilvideo-vulnerability-telegram-android/)).
   - Im Oktober 2026 wurde eine Schwachstelle bei Sprachanrufen in Telegram für Android offengelegt, behoben in
     Version 12.10.4 ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)).
   - Im November 2026 führte Telegram Widgets ein, kleine Programme in einer Nachricht
     ([Änderungen der Bot API](https://core.telegram.org/bots/api-changelog)). Zwei Tage nach ihrer Ankündigung
     veröffentlichte die Sicherheitsfirma V12 ein Video, in dem die Antwort eines Bots auf „Starten“ ein
     Android-Telefon dazu brachte, von selbst seinen Taschenrechner zu öffnen, was darauf hindeutet, dass die Nachricht
     Code auf dem Telefon ausführte. V12 veröffentlichte keine Einzelheiten. Berichten zufolge bestätigte Telegram die
     Schwachstelle und sagte, die Korrektur sei „an alle Nutzer ausgeliefert“ worden; Angriffe waren nicht gemeldet
     worden ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)). Seit Version 13.2.2 führt
     Telegram für Android Widgets in einem eigenen Prozess ohne Berechtigungen, Dateien oder Netzwerk aus
     ([Quellcode von Telegram für Android](https://github.com/DrKLO/Telegram/commit/21f7d10)).
   - Der Gründer von Telegram schrieb, das Problem „existiert nicht“: „niemand konnte allein durch den Empfang einer
     Nachricht gehackt werden“, man „musste zuerst aktiv einen Dienst eines Dritten starten“, und „selbst das ist
     serverseitig vollständig behoben“ ([sein Beitrag](https://t.me/durov/560)). Was auch immer sich auf den Servern
     geändert hat: Den eigenen Prozess für Widgets bringt nur das Update der App.

   Was Fehler in der App selbst behebt, ist ein Update von Telegram. Telegram hat nicht gesagt, ob seine Apps für iPhone
   und Computer betroffen waren; aktualisieren Sie es also auf jedem Gerät, auf dem Sie es nutzen
   ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)).

## Zwei Einstellungen sind wichtiger als jeder Bot

**Ein Business-Bot, der mit Ihrem eigenen Konto verbunden ist,** kann die Chats lesen, die Sie auswählen, und mit den
Rechten, die Sie ihm geben, darauf antworten, Nachrichten löschen, Ihren Namen, Ihre Bio und Ihr Foto ändern und Ihre
Geschenke und Sterne übertragen. Behandeln Sie das, als würden Sie jemandem Ihr Telefon geben, und prüfen Sie
Einstellungen > Telegram Business > Chat-Automatisierung
([Datenschutzerklärung von Telegram](https://telegram.org/privacy); [Telegram Bot API](https://core.telegram.org/bots/api)).

**In einer Gruppe** sieht ein Bot normalerweise nur Befehle, die für ihn bestimmt sind, Antworten auf ihn und
Nachrichten, die über ihn gesendet wurden. Er sieht alles, wenn er Admin ist oder sein Betreiber seinen
Datenschutzmodus ausgeschaltet hat, und die Mitgliederliste zeigt, was davon zutrifft
([Funktionen von Telegram-Bots](https://core.telegram.org/bots/features)).

## Andere Apps funktionieren ganz ähnlich

**WhatsApp, Messenger, Instagram, Viber, Slack und X:** Ein Bot ist ein Computer eines Unternehmens. Ihr Telefon
spricht nur mit der Plattform, es sei denn, der Bot öffnet eine Webseite, aber das Unternehmen liest, was Sie senden,
und möglicherweise auch seine Dienstleister.
- **WhatsApp:** Wenn ein Unternehmen Metas eigenen Dienst nutzt, entschlüsselt Meta seine Nachrichten und bewahrt sie
  bis zu 30 Tage auf, und das Unternehmen kann das, was Sie senden, für sein eigenes Marketing nutzen, auch für Werbung
  ([Meta](https://developers.facebook.com/documentation/business-messaging/whatsapp/data-privacy-and-security)).
  WhatsApp sagt, dass es im Chat anzeigt, wenn ein Unternehmen den Dienst von Meta nutzt, und zählt diese Chats nicht
  als Ende-zu-Ende-verschlüsselt ([WhatsApp](https://faq.whatsapp.com/general/28030015)).
- **Messenger:** Ein Unternehmen kann Webseiten in Messenger öffnen, und diese können eine ID zu Ihnen erfahren und aus
  welchem Chat Sie kamen, ganz ähnlich wie eine Telegram-Mini-App
  ([Meta](https://developers.facebook.com/documentation/business-messaging/messenger-platform/webview);
  [Meta](https://developers.facebook.com/documentation/business-messaging/messenger-platform/webview/context)).
- **Instagram:** Der Bot eines Unternehmens kann Ihnen erst schreiben, nachdem Sie ihm geschrieben haben
  ([Meta](https://developers.facebook.com/documentation/instagram-platform/instagram-api-with-instagram-login/messaging-api)).
- **Viber:** Ein Bot kann Ihr Land, Ihre Sprache, Ihr Gerät und Ihr Mobilfunknetz sehen
  ([Viber](https://creators.viber.com/docs/bots-api/resources/subscribers/get-subscriber-details)).
- **Slack:** Eine App liest die Kanäle und Chats, zu denen sie hinzugefügt wurde, soweit ihre Berechtigungen es erlauben
  ([Slack](https://docs.slack.dev/reference/scopes/)).
- **X:** In einem verschlüsselten Chat mit einem Bot hält die eigene Software des Bots die Schlüssel und entschlüsselt
  Ihre Nachrichten, sodass sein Betreiber sie lesen kann ([X](https://docs.x.com/xchat/introduction); [X](https://docs.x.com/xchat/bots)).

**Discord:** Ein Bot liest, was seine Berechtigungen erlauben. Die Aktivitäten in der Discord-App sind Web-Apps anderer
Leute, aber sie erreichen ihre Betreiber über Discord, das nach eigenen Angaben Ihre IP-Adresse vor ihnen verbirgt
([Discord](https://github.com/discord/discord-api-docs/blob/main/developers/activities/development-guides/networking.mdx)).

**WeChat, Alipay, LINE, TikTok und ähnliche Apps:** Deren Mini-Apps sind wie die von Telegram, Programme anderer Leute
innerhalb der App. Diese Mini-Apps können Sie ohne Nachfrage anhand einer ID erkennen
([WeChat](https://developers.weixin.qq.com/miniprogram/en/dev/framework/open-ability/union-id.html);
[Alipay](https://miniprogram.alipay.com/docs/miniprogram/mpdev/api_openapi_getauthcode);
[TikTok](https://developers.tiktok.com/docs/en/tiktok-minis-silent-login);
[LINE](https://developers.line.biz/en/docs/line-mini-app/develop/channel-consent-simplification/), bei verifizierten
Mini-Apps), und Ihr Telefon verbindet sich meist mit den Servern ihrer Betreiber
([WeChat](https://developers.weixin.qq.com/miniprogram/en/dev/framework/ability/network.html)). Eine Studie aus dem Jahr
2023 ergab, dass WeChat selbst ausführliche Aufzeichnungen darüber erhält, was Sie in seinen Mini-Programmen tun
([Citizen Lab](https://citizenlab.ca/2023/06/privacy-in-the-wechat-ecosystem-full-report/)).

**Signal** hat keine Bot-Plattform und keine Mini-Apps. Ein Bot ist dort ein gewöhnliches Konto, das von einem Programm
betrieben wird ([signal-cli](https://github.com/AsamK/signal-cli)), und er liest, was Sie ihm senden.

## Kurz gesagt

Ein Tippen auf „Starten“ zeigt dem Bot, wer Sie auf Telegram sind, und erlaubt ihm, Ihnen zu schreiben. Das Öffnen
einer Mini-App zeigt ihrem Betreiber, und oft auch Trackern, außerdem, von wo aus Sie sich verbinden. Der meiste
Schaden beginnt, wenn Sie etwas herausgeben (einen Code, eine Anmeldebestätigung, eine Telefonnummer, eine Zahlung,
eine Signatur, eine App zum Installieren), oder, selten, durch einen Fehler in der App selbst. Halten Sie die App
aktuell, legen Sie ein Passwort für die zweistufige Bestätigung fest, geben Sie nie einen Code heraus, bestätigen Sie
keine Anmeldung, die Sie nicht selbst ausgelöst haben, und blockieren Sie die Bots, die Sie nicht mehr nutzen.
