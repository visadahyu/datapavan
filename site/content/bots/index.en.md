---
title: "What a bot or mini app can see"
---

Messaging apps let other people's bots and small apps run inside them. Android sees only the messaging app, so
nothing on your phone tells you what a bot or a mini app gets when you use it. This page says what it gets, and what
the real dangers are. It starts with Telegram and ends with other apps.

Checked on 13 November 2026. These apps change every few months; if something here is wrong or out of date,
[tell us](https://github.com/visadahyu/datapavan/issues).

## When you press Start on a Telegram bot

The bot's owner gets your Telegram ID number, your name, your username if you have one, the language your app uses,
and whether you pay for Premium ([Telegram Bot API](https://core.telegram.org/bots/api);
[Telegram Privacy Policy](https://telegram.org/privacy)). The owner can also look up your profile photos, your bio,
your birthday and the posts of the personal channel on your profile ([Bot API](https://core.telegram.org/bots/api)).
Telegram's privacy policy calls your photos public; for the rest, Telegram's pages do not say whether your privacy
settings limit these lookups.

The bot does not get your phone number, your contacts, your other chats, your location or your files. It gets your
number, your location or your address only when you share them: with a button made for that, by sending them
yourself, by typing them in when you pay through the bot, or, for your location, by allowing it when you use the bot
inline ([Bot API](https://core.telegram.org/bots/api); [Telegram Privacy Policy](https://telegram.org/privacy)).

Your phone never connects to the bot's computer. Telegram carries the messages and files both ways and makes link
previews on its own servers, so the bot does not see your internet address
([Bot API](https://core.telegram.org/bots/api);
[Telegram for Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/res/values/strings.xml)).
Telegram does not say this in so many words; it follows from how bots work, and the only way Telegram's privacy
policy names for a bot to get your address is a link or button to a website its owner controls
([Telegram Privacy Policy](https://telegram.org/privacy)).

Everything you send the bot goes to its owner, who can read it. A bot cannot start a chat with you, but once you
press Start it can write to you whenever it likes, until you block it
([Telegram Bots](https://core.telegram.org/bots); [Bot FAQ](https://core.telegram.org/bots/faq)). Writing to a
business account can also mean writing to its bot, which then gets the same details about you
([Telegram Privacy Policy](https://telegram.org/privacy)).

## What changes that

**Sharing your contact or location.** If you tap a button to share your contact or your location, the bot gets your
phone number or where you are.

**Opening the bot's mini app.** A mini app is the owner's website, opened inside Telegram. The site sees your
internet address, and so roughly where you are ([Telegram's Mini App terms](https://telegram.org/tos/mini-apps)).
On Android it also sees your phone's make, model and Android version
([Telegram for Android source](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java)).
Depending on how you opened it, Telegram also gives it a signed copy of your Telegram identity, and sometimes details
of the chat you opened it from ([Telegram Mini Apps](https://core.telegram.org/bots/webapps);
[Mini App terms](https://telegram.org/tos/mini-apps)). Every tracker the page loads sees your address too. A study
not yet peer reviewed tested 278 mini apps from one catalogue: 59 % sent data to at least one outside company, mostly
analytics or advertising, that their privacy policy did not cover, and most had no policy of their own, only
Telegram's standard one ([TeleGapper, 2026](https://arxiv.org/html/2608.13390)).

On Android, before a mini app gets your phone number, location, camera or microphone, Telegram asks you in its own
window that names the bot, and you can say no. The one exception in the code is Telegram's own age check, which gets
the camera and microphone without that window ([Telegram Mini Apps](https://core.telegram.org/bots/webapps);
[Telegram for Android source](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java)).
Telegram's documentation describes no prompt before a mini app uses your phone's motion sensors, keeps up to 5 MB of
data on your phone or fills the whole screen ([Telegram Mini Apps](https://core.telegram.org/bots/webapps)). A
full-screen page can look exactly like Telegram, so treat a login form inside a mini app as a warning sign
([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/)).

**Tapping a link.** The site behind it sees your internet address
([Telegram Privacy Policy](https://telegram.org/privacy)).

**Connecting a wallet or signing a transaction.** You can lose money
([Cointelegraph](https://cointelegraph.com/magazine/ethereum-phishing-drainers-ton-bitcoin/)).

## The real dangers

Most of them need no bug: someone tricks you into handing something over.

1. **Someone gets into your account.** A bot or a stranger sends you to a mini app or a page: a free gift, a "vote
   for me" page, a fake security check. It asks for your phone number and login code, shows a QR code to scan, or
   makes Telegram show you a real login request to approve
   ([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/);
   [Kaspersky](https://www.kaspersky.com/blog/telegram-takeover-contest/47195/);
   [CYFIRMA](https://www.cyfirma.com/research/re-emerging-telegram-phishing-campaign-targeting-user-authorization-prompts/)).
   Type your login code only into the Telegram app itself, or into Telegram's own login page that you opened
   yourself, and never pass it on ([Telegram FAQ](https://telegram.org/faq)). Scan a login QR code only from Telegram
   on your own computer, never from a page someone sent you. Never tap "This is me" or "Yes" on a login request you
   did not start. Set a two-step verification password and type it nowhere but in Telegram. If you already did one of
   these, go to Settings > Devices, end all other sessions and change that password.
2. **A page that looks like a real service** asks you to log in, to pay a "deposit" before you can withdraw earnings
   that do not exist, or to install an app
   ([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/);
   [BleepingComputer](https://www.bleepingcomputer.com/news/security/telegram-mini-apps-abused-for-crypto-scams-android-malware-delivery/)).
3. **A fake "verification" bot** asks you to paste a command into your computer, and the command installs malware
   ([Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/criminals-exploit-telegram-captcha-to-trick-victims-into-installing-malware);
   [Cointelegraph](https://cointelegraph.com/news/telegram-verification-bots-carry-crypto-stealing-malware)).
4. **A mini app quietly sends your data to trackers** ([TeleGapper, 2026](https://arxiv.org/html/2608.13390)).
5. **Rarely, a bug in Telegram itself.**
   - In 2024, a flaw let an attacker send an Android app that looked like a video in a chat; nothing was installed
     unless you tapped it and agreed to the install. Telegram fixed it in version 10.14.5
     ([ESET](https://www.welivesecurity.com/en/eset-research/cursed-tapes-exploiting-evilvideo-vulnerability-telegram-android/)).
   - In October 2026, a voice-call flaw in Telegram for Android was disclosed, fixed in version 12.10.4
     ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)).
   - In November 2026 Telegram added widgets, small programs inside a message
     ([Bot API changes](https://core.telegram.org/bots/api-changelog)). Two days after they were announced, the
     security firm V12 posted a video in which a bot's reply to Start made an Android phone open its calculator by
     itself, which suggests the message ran code on the phone. V12 published no details. Telegram was reported to
     have confirmed the flaw and to have said the fix "was deployed to all users"; no attacks had been reported
     ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)). Since version 13.2.2, Telegram for
     Android runs widgets in a separate process with no permissions, files or network
     ([Telegram for Android source](https://github.com/DrKLO/Telegram/commit/21f7d10)).
   - Telegram's founder wrote that the issue "doesn't exist": "no one could be hacked just by receiving a message",
     you "had to actively start a third-party service first", and "even that is fully patched server-side"
     ([his post](https://t.me/durov/560)). Whatever changed on the servers, the separate widget process comes only
     with the app update.

   Updating Telegram is what closes bugs in the app. Telegram has not said whether its iPhone and computer apps were
   affected, so update it on every device you use it on
   ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)).

## Two settings matter more than any bot

**A business bot connected to your own account** can read the chats you choose and, with the rights you give it,
answer them, delete messages, change your name, bio and photo, and move your gifts and Stars. Treat that like handing
someone your phone, and check Settings > Telegram Business > Chatbots
([Telegram Privacy Policy](https://telegram.org/privacy); [Telegram Bot API](https://core.telegram.org/bots/api)).

**In a group,** a bot normally sees only commands meant for it, replies to it and messages sent through it. It sees
everything if it is an admin or its owner turned its privacy mode off, and the member list shows which
([Telegram bot features](https://core.telegram.org/bots/features)).

## Other apps work much the same way

**WhatsApp, Messenger, Instagram, Viber, Slack and X:** a bot is a company's computer. Your phone talks only to the
platform unless the bot opens a web page, but the business reads what you send, and so may its service providers.
- **WhatsApp:** when a business uses Meta's own service, Meta decrypts its messages and keeps them for up to 30 days,
  and the business may use what you send for its own marketing, including ads
  ([Meta](https://developers.facebook.com/documentation/business-messaging/whatsapp/data-privacy-and-security)).
  WhatsApp says it shows in the chat when a business uses Meta's service, and does not count those chats as
  end-to-end encrypted ([WhatsApp](https://faq.whatsapp.com/general/28030015)).
- **Messenger:** a business can open web pages inside Messenger, and they can learn an ID for you and which chat you
  came from, much like a Telegram mini app
  ([Meta](https://developers.facebook.com/documentation/business-messaging/messenger-platform/webview);
  [Meta](https://developers.facebook.com/documentation/business-messaging/messenger-platform/webview/context)).
- **Instagram:** a business's bot can write to you only after you write to it
  ([Meta](https://developers.facebook.com/documentation/instagram-platform/instagram-api-with-instagram-login/messaging-api)).
- **Viber:** a bot can see your country, your language, your device and your mobile network
  ([Viber](https://creators.viber.com/docs/bots-api/resources/subscribers/get-subscriber-details)).
- **Slack:** an app reads the channels and chats it has been added to, as far as its permissions allow
  ([Slack](https://docs.slack.dev/reference/scopes/)).
- **X:** in an encrypted chat with a bot, the bot's own software holds the keys and decrypts your messages, so its
  owner can read them ([X](https://docs.x.com/xchat/introduction); [X](https://docs.x.com/xchat/bots)).

**Discord:** a bot reads what its permissions allow. Discord's in-app activities are other people's web apps, but
they reach their owners through Discord, which Discord says keeps your internet address from them
([Discord](https://github.com/discord/discord-api-docs/blob/main/developers/activities/development-guides/networking.mdx)).

**WeChat, Alipay, LINE, TikTok and similar apps:** their mini apps are like Telegram's, other people's programs
inside the app. They can recognise you with an ID without asking
([WeChat](https://developers.weixin.qq.com/miniprogram/en/dev/framework/open-ability/union-id.html);
[Alipay](https://miniprogram.alipay.com/docs/miniprogram/mpdev/api_openapi_getauthcode);
[TikTok](https://developers.tiktok.com/docs/en/tiktok-minis-silent-login);
[LINE](https://developers.line.biz/en/docs/line-mini-app/develop/channel-consent-simplification/), for verified mini
apps), and your phone usually connects to their owners' servers
([WeChat](https://developers.weixin.qq.com/miniprogram/en/dev/framework/ability/network.html)). A 2023 study found
that WeChat itself receives detailed records of what you do in its mini programs
([Citizen Lab](https://citizenlab.ca/2023/06/privacy-in-the-wechat-ecosystem-full-report/)).

**Signal** has no bot platform or mini apps. A bot there is an ordinary account run by a program
([signal-cli](https://github.com/AsamK/signal-cli)), and it reads what you send it.

## In short

Pressing Start shows the bot who you are on Telegram and lets it write to you. Opening a mini app also shows its
owner, and often trackers, where you connect from. Most harm starts when you hand something over (a code, a login
approval, a phone number, a payment, a signature, an app to install), or, rarely, through a bug in the app itself.
Keep the app updated, set a two-step verification password, never hand over a code or approve a login you did not
start, and block the bots you no longer use.
