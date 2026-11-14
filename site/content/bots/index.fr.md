---
title: "Ce qu’un bot ou une mini-application peut voir"
---

Les applis de messagerie permettent à des bots et à de petites applis créés par d’autres personnes de fonctionner à
l’intérieur. Android ne voit que l’appli de messagerie : rien sur votre téléphone ne vous dit donc ce qu’un bot ou une
mini-application reçoit quand vous l’utilisez. Cette page dit ce qu’ils reçoivent, et quels sont les vrais dangers. Elle
commence par Telegram et finit par les autres applis.

Vérifié le 13 novembre 2026. Ces applis changent à quelques mois d’intervalle ; si quelque chose ici est faux ou
dépassé, [dites-le-nous](https://github.com/visadahyu/datapavan/issues).

## Quand vous appuyez sur Démarrer dans un bot Telegram

Le propriétaire du bot reçoit votre numéro d’identifiant Telegram, votre nom, votre nom d’utilisateur si vous en avez
un, la langue de votre appli, et si vous payez l’abonnement Premium ([Bot API de Telegram](https://core.telegram.org/bots/api) ;
[Politique de confidentialité de Telegram](https://telegram.org/privacy)). Le propriétaire peut aussi consulter vos
photos de profil, votre bio, votre date de naissance et les publications du canal personnel affiché sur votre
profil ([Bot API](https://core.telegram.org/bots/api)). La politique de confidentialité de Telegram qualifie vos
photos de publiques ; pour le reste, les pages de Telegram ne disent pas si vos paramètres de confidentialité limitent
ces consultations.

Le bot ne reçoit pas votre numéro de téléphone, vos contacts, vos autres discussions, votre position ni vos fichiers.
Il ne reçoit votre numéro, votre position ou votre adresse que si vous les partagez : avec un bouton prévu pour cela,
en les envoyant vous-même, en les saisissant quand vous payez par le bot, ou, pour votre position, en l’autorisant
quand vous utilisez le bot en mode inline ([Bot API](https://core.telegram.org/bots/api) ;
[Politique de confidentialité de Telegram](https://telegram.org/privacy)).

Votre téléphone ne se connecte jamais à l’ordinateur du bot. Telegram transporte les messages et les fichiers dans les
deux sens et crée les aperçus de liens sur ses propres serveurs : le bot ne voit donc pas votre adresse Internet
([Bot API](https://core.telegram.org/bots/api) ;
[Telegram pour Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/res/values/strings.xml)).
Telegram ne le dit pas en toutes lettres ; cela découle du fonctionnement des bots, et le seul moyen que la politique
de confidentialité de Telegram cite pour qu’un bot obtienne votre adresse est un lien ou un bouton vers un site web
contrôlé par son propriétaire ([Politique de confidentialité de Telegram](https://telegram.org/privacy)).

Tout ce que vous envoyez au bot va à son propriétaire, qui peut le lire. Un bot ne peut pas commencer une discussion
avec vous, mais une fois que vous avez appuyé sur Démarrer, il peut vous écrire quand il veut, jusqu’à ce que vous le
bloquiez ([Bots Telegram](https://core.telegram.org/bots) ; [FAQ des bots](https://core.telegram.org/bots/faq)).
Écrire à un compte professionnel peut aussi revenir à écrire à son bot, qui reçoit alors les mêmes informations sur
vous ([Politique de confidentialité de Telegram](https://telegram.org/privacy)).

## Ce qui change cela

**Partager votre contact ou votre position.** Si vous appuyez sur un bouton pour partager votre contact ou votre
position, le bot reçoit votre numéro de téléphone ou l’endroit où vous êtes.

**Ouvrir la mini-application du bot.** Une mini-application est le site web du propriétaire, ouvert dans Telegram. Le site voit votre
adresse Internet, et donc à peu près où vous êtes ([Conditions des mini-applications de Telegram](https://telegram.org/tos/mini-apps)).
Sur Android, il voit aussi la marque, le modèle et la version d’Android de votre téléphone
([Code source de Telegram pour Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java)).
Selon la façon dont vous l’avez ouverte, Telegram lui donne aussi une copie signée de votre identité Telegram, et
parfois des détails sur la discussion depuis laquelle vous l’avez ouverte ([Mini-applications Telegram](https://core.telegram.org/bots/webapps) ;
[Conditions des mini-applications](https://telegram.org/tos/mini-apps)). Chaque traceur chargé par la page voit lui aussi
votre adresse. Une étude pas encore évaluée par des pairs a testé 278 mini-applications d’un même catalogue : 59 % envoyaient
des données à au moins une entreprise extérieure, le plus souvent de mesure d’audience ou de publicité, que leur
politique de confidentialité ne couvrait pas, et la plupart n’avaient pas de politique propre, seulement celle, standard,
de Telegram ([TeleGapper, 2026](https://arxiv.org/html/2608.13390)).

Sur Android, avant qu’une mini-application obtienne votre numéro de téléphone, votre position, votre appareil photo ou votre
micro, Telegram vous le demande dans sa propre fenêtre, qui nomme le bot, et vous pouvez refuser. La seule exception
dans le code est la vérification d’âge de Telegram lui-même, qui obtient l’appareil photo et le micro sans cette
fenêtre ([Mini-applications Telegram](https://core.telegram.org/bots/webapps) ;
[Code source de Telegram pour Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java)).
La documentation de Telegram ne décrit aucune demande avant qu’une mini-application utilise les capteurs de mouvement de votre
téléphone, garde jusqu’à 5 Mo de données sur votre téléphone ou occupe tout l’écran
([Mini-applications Telegram](https://core.telegram.org/bots/webapps)). Une page en plein écran peut ressembler exactement à
Telegram : considérez donc un formulaire de connexion dans une mini-application comme un signe d’alerte
([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/)).

**Appuyer sur un lien.** Le site derrière ce lien voit votre adresse Internet
([Politique de confidentialité de Telegram](https://telegram.org/privacy)).

**Connecter un portefeuille ou signer une transaction.** Vous pouvez perdre de l’argent
([Cointelegraph](https://cointelegraph.com/magazine/ethereum-phishing-drainers-ton-bitcoin/)).

## Les vrais dangers

La plupart n’ont besoin d’aucun bug : quelqu’un vous amène par la ruse à lui remettre quelque chose.

1. **Quelqu’un s’introduit dans votre compte.** Un bot ou un inconnu vous envoie vers une mini-application ou une page : un
   cadeau gratuit, une page « votez pour moi », une fausse vérification de sécurité. Elle vous demande votre numéro de
   téléphone et votre code de connexion, affiche un QR code à scanner, ou amène Telegram à vous montrer une vraie
   demande de connexion à approuver
   ([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/) ;
   [Kaspersky](https://www.kaspersky.com/blog/telegram-takeover-contest/47195/) ;
   [CYFIRMA](https://www.cyfirma.com/research/re-emerging-telegram-phishing-campaign-targeting-user-authorization-prompts/)).
   Saisissez votre code de connexion uniquement dans l’appli Telegram elle-même, ou dans la page de connexion de
   Telegram que vous avez ouverte vous-même, et ne le transmettez jamais ([FAQ de Telegram](https://telegram.org/faq)).
   Ne scannez un QR code de connexion que s’il est affiché par Telegram sur votre propre ordinateur, jamais sur une page
   que quelqu’un vous a envoyée. N’appuyez jamais sur « Oui, c’est moi » pour une demande de connexion que vous
   n’avez pas lancée. Définissez un mot de passe de double authentification et ne le saisissez nulle part ailleurs
   que dans Telegram. Si vous avez déjà fait l’une de ces choses, allez dans Paramètres > Appareils, fermez toutes
   les autres sessions et changez ce mot de passe.
2. **Une page qui ressemble à un vrai service** vous demande de vous connecter, de payer un « dépôt » avant de pouvoir
   retirer des gains qui n’existent pas, ou d’installer une appli
   ([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/) ;
   [BleepingComputer](https://www.bleepingcomputer.com/news/security/telegram-mini-apps-abused-for-crypto-scams-android-malware-delivery/)).
3. **Un faux bot de « vérification »** vous demande de coller une commande dans votre ordinateur, et la commande
   installe un logiciel malveillant
   ([Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/criminals-exploit-telegram-captcha-to-trick-victims-into-installing-malware) ;
   [Cointelegraph](https://cointelegraph.com/news/telegram-verification-bots-carry-crypto-stealing-malware)).
4. **Une mini-application envoie discrètement vos données à des traceurs** ([TeleGapper, 2026](https://arxiv.org/html/2608.13390)).
5. **Rarement, un bug dans Telegram lui-même.**
   - En 2024, une faille permettait à un attaquant d’envoyer dans une discussion une appli Android qui ressemblait à
     une vidéo ; rien n’était installé sauf si vous appuyiez dessus et acceptiez l’installation. Telegram l’a corrigée
     dans la version 10.14.5
     ([ESET](https://www.welivesecurity.com/en/eset-research/cursed-tapes-exploiting-evilvideo-vulnerability-telegram-android/)).
   - En octobre 2026, une faille des appels vocaux de Telegram pour Android a été rendue publique ; elle est corrigée
     dans la version 12.10.4 ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)).
   - En novembre 2026, Telegram a ajouté les widgets, de petits programmes à l’intérieur d’un message
     ([Modifications de la Bot API](https://core.telegram.org/bots/api-changelog)). Deux jours après leur annonce, la
     société de sécurité V12 a publié une vidéo dans laquelle la réponse d’un bot à Démarrer amenait un téléphone
     Android à ouvrir sa calculatrice tout seul, ce qui laisse penser que le message a exécuté du code sur le
     téléphone. V12 n’a publié aucun détail. Telegram aurait confirmé la faille et déclaré que le correctif « a été
     déployé pour tous les utilisateurs » ; aucune attaque n’avait été signalée
     ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)). Depuis la version 13.2.2, Telegram pour
     Android exécute les widgets dans un processus séparé, sans autorisations, sans fichiers et sans réseau
     ([Code source de Telegram pour Android](https://github.com/DrKLO/Telegram/commit/21f7d10)).
   - Le fondateur de Telegram a écrit que le problème « n’existe pas » : « personne ne pouvait être piraté simplement
     en recevant un message », il « fallait d’abord lancer activement un service tiers », et « même cela est
     entièrement corrigé côté serveur » ([son message](https://t.me/durov/560)). Quels que soient les changements
     faits sur les serveurs, le processus séparé pour les widgets n’arrive qu’avec la mise à jour de l’appli.

   C’est la mise à jour de Telegram qui corrige les bugs de l’appli. Telegram n’a pas dit si ses applis pour iPhone et
   pour ordinateur étaient touchées : mettez-le donc à jour sur chaque appareil où vous l’utilisez
   ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)).

## Deux paramètres comptent plus que n’importe quel bot

**Un bot professionnel connecté à votre propre compte** peut lire les discussions que vous choisissez et, avec les
droits que vous lui donnez, y répondre, supprimer des messages, changer votre nom, votre bio et votre photo, et
transférer vos cadeaux et vos étoiles. Traitez cela comme si vous confiiez votre téléphone à quelqu’un, et vérifiez
Paramètres > Telegram Professionnel > Automatisation d’échanges
([Politique de confidentialité de Telegram](https://telegram.org/privacy) ; [Bot API de Telegram](https://core.telegram.org/bots/api)).

**Dans un groupe,** un bot ne voit normalement que les commandes qui lui sont destinées, les réponses à ses messages
et les messages envoyés par son intermédiaire. Il voit tout s’il est administrateur ou si son propriétaire a désactivé
son mode confidentialité, et la liste des membres l’indique
([Fonctions des bots Telegram](https://core.telegram.org/bots/features)).

## Les autres applis fonctionnent à peu près de la même façon

**WhatsApp, Messenger, Instagram, Viber, Slack et X :** un bot est l’ordinateur d’une entreprise. Votre téléphone ne
parle qu’à la plateforme, sauf si le bot ouvre une page web, mais l’entreprise lit ce que vous envoyez, et ses
prestataires peuvent le lire aussi.
- **WhatsApp :** quand une entreprise utilise le service de Meta lui-même, Meta déchiffre ses messages et les garde
  jusqu’à 30 jours, et l’entreprise peut utiliser ce que vous envoyez pour son propre marketing, publicités comprises
  ([Meta](https://developers.facebook.com/documentation/business-messaging/whatsapp/data-privacy-and-security)).
  WhatsApp dit l’indiquer dans la discussion quand une entreprise utilise le service de Meta, et ne considère pas ces
  discussions comme chiffrées de bout en bout ([WhatsApp](https://faq.whatsapp.com/general/28030015)).
- **Messenger :** une entreprise peut ouvrir des pages web dans Messenger, et celles-ci peuvent connaître un
  identifiant qui vous désigne et la discussion d’où vous venez, un peu comme une mini-application Telegram
  ([Meta](https://developers.facebook.com/documentation/business-messaging/messenger-platform/webview) ;
  [Meta](https://developers.facebook.com/documentation/business-messaging/messenger-platform/webview/context)).
- **Instagram :** le bot d’une entreprise ne peut vous écrire qu’après que vous lui avez écrit
  ([Meta](https://developers.facebook.com/documentation/instagram-platform/instagram-api-with-instagram-login/messaging-api)).
- **Viber :** un bot peut voir votre pays, votre langue, votre appareil et votre opérateur mobile
  ([Viber](https://creators.viber.com/docs/bots-api/resources/subscribers/get-subscriber-details)).
- **Slack :** une appli lit les canaux et les discussions où elle a été ajoutée, dans la limite de ses autorisations
  ([Slack](https://docs.slack.dev/reference/scopes/)).
- **X :** dans une discussion chiffrée avec un bot, c’est le logiciel du bot lui-même qui détient les clés et
  déchiffre vos messages : son propriétaire peut donc les lire ([X](https://docs.x.com/xchat/introduction) ;
  [X](https://docs.x.com/xchat/bots)).

**Discord :** un bot lit ce que ses autorisations lui permettent. Les activités intégrées à Discord sont des applis
web d’autres personnes, mais elles atteignent leurs propriétaires en passant par Discord, ce qui, selon Discord, leur
cache votre adresse Internet
([Discord](https://github.com/discord/discord-api-docs/blob/main/developers/activities/development-guides/networking.mdx)).

**WeChat, Alipay, LINE, TikTok et les applis similaires :** leurs mini-applications sont comme celles de Telegram, des
programmes d’autres personnes à l’intérieur de l’appli. Elles peuvent vous reconnaître grâce à un identifiant sans
vous le demander
([WeChat](https://developers.weixin.qq.com/miniprogram/en/dev/framework/open-ability/union-id.html) ;
[Alipay](https://miniprogram.alipay.com/docs/miniprogram/mpdev/api_openapi_getauthcode) ;
[TikTok](https://developers.tiktok.com/docs/en/tiktok-minis-silent-login) ;
[LINE](https://developers.line.biz/en/docs/line-mini-app/develop/channel-consent-simplification/), pour les mini-applications
vérifiées), et votre téléphone se connecte généralement aux serveurs de leurs propriétaires
([WeChat](https://developers.weixin.qq.com/miniprogram/en/dev/framework/ability/network.html)). Une étude de 2023 a
constaté que WeChat lui-même reçoit des relevés détaillés de ce que vous faites dans ses mini-programmes
([Citizen Lab](https://citizenlab.ca/2023/06/privacy-in-the-wechat-ecosystem-full-report/)).

**Signal** n’a ni plateforme de bots ni mini-applications. Un bot y est un compte ordinaire géré par un programme
([signal-cli](https://github.com/AsamK/signal-cli)), et il lit ce que vous lui envoyez.

## En bref

Appuyer sur Démarrer montre au bot qui vous êtes sur Telegram et lui permet de vous écrire. Ouvrir une mini-application montre
aussi à son propriétaire, et souvent à des traceurs, d’où vous vous connectez. La plupart des dégâts commencent quand
vous remettez quelque chose (un code, une approbation de connexion, un numéro de téléphone, un paiement, une
signature, une appli à installer), ou, rarement, par un bug dans l’appli elle-même. Gardez l’appli à jour, définissez
un mot de passe de double authentification, ne remettez jamais un code et n’approuvez jamais une connexion que vous
n’avez pas lancée, et bloquez les bots que vous n’utilisez plus.
