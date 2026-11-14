---
title: "机器人或小程序能看到什么"
---

聊天应用允许别人的机器人和小型应用在其中运行。Android 只看得到聊天应用本身，所以当您使用机器人或小程序时，手机上没有任何地方会告诉您它得到了什么。本页说明它会得到什么，以及真正的危险是什么。先讲 Telegram，最后讲其他应用。

2026 年 11 月 13 日核对。这些应用每隔几个月就会变化；如果这里有内容错误或已过时，请[告诉我们](https://github.com/visadahyu/datapavan/issues)。

## 当您在 Telegram 机器人中按下“开始”

机器人的所有者会得到您的 Telegram 数字 ID、您的名字、您的用户名（如果有）、您的应用所用的语言，以及您是否付费订阅了 Telegram 高级版（[Telegram Bot API](https://core.telegram.org/bots/api)；[Telegram 隐私政策](https://telegram.org/privacy)）。所有者还可以查询您的头像、个人简介、生日，以及您资料中个人频道的帖子（[Bot API](https://core.telegram.org/bots/api)）。Telegram 的隐私政策称您的照片是公开的；至于其余内容，Telegram 的页面没有说明您的隐私设置是否会限制这些查询。

机器人得不到您的电话号码、通讯录、其他聊天、位置或文件。只有在您分享时，它才会得到您的号码、位置或地址：通过专门用于分享的按钮、由您自己发送、在通过机器人付款时由您输入，或者（就位置而言）在您以内联模式使用机器人时由您允许（[Bot API](https://core.telegram.org/bots/api)；[Telegram 隐私政策](https://telegram.org/privacy)）。

您的手机从不连接机器人的计算机。Telegram 在双方之间传递消息和文件，并在自己的服务器上生成链接预览，所以机器人看不到您的 IP 地址（[Bot API](https://core.telegram.org/bots/api)；[Telegram Android 版](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/res/values/strings.xml)）。Telegram 并没有明确这样说；这是从机器人的工作方式得出的。Telegram 隐私政策中提到的机器人获取您 IP 地址的唯一途径，是指向其所有者所控制网站的链接或按钮（[Telegram 隐私政策](https://telegram.org/privacy)）。

您发给机器人的一切都会到达其所有者那里，所有者可以阅读。机器人不能主动与您开始聊天，但一旦您按下“开始”，它就可以随时给您发消息，直到您屏蔽它（[Telegram 机器人](https://core.telegram.org/bots)；[机器人常见问题](https://core.telegram.org/bots/faq)）。给企业账号发消息，也可能意味着是在给它的机器人发消息，这个机器人随后会得到关于您的同样信息（[Telegram 隐私政策](https://telegram.org/privacy)）。

## 哪些情况会改变这一点

**分享您的联系方式或位置。** 如果您点按按钮分享您的联系方式或位置，机器人就会得到您的电话号码或您所在的位置。

**打开机器人的小程序。** 小程序就是所有者的网站，在 Telegram 内打开。该网站能看到您的 IP 地址，因此也能大致知道您在哪里（[Telegram 小程序条款](https://telegram.org/tos/mini-apps)）。在 Android 上，它还能看到您手机的品牌、型号和 Android 版本（[Telegram Android 版源代码](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java)）。根据您打开它的方式，Telegram 还会给它一份带签名的 Telegram 身份信息，有时还有您从中打开它的那个聊天的详情（[Telegram 小程序](https://core.telegram.org/bots/webapps)；[小程序条款](https://telegram.org/tos/mini-apps)）。页面加载的每个跟踪器也都能看到您的 IP 地址。一项尚未经过同行评审的研究测试了某个目录中的 278 个小程序：59% 把数据发给了至少一家其隐私政策未涵盖的外部公司，大多是分析或广告公司；大多数小程序没有自己的隐私政策，只有 Telegram 的标准政策（[TeleGapper, 2026](https://arxiv.org/html/2608.13390)）。

在 Android 上，小程序获取您的电话号码、位置、相机或麦克风之前，Telegram 会在自己的窗口中询问您，窗口会写明是哪个机器人，您可以拒绝。代码中唯一的例外是 Telegram 自己的年龄验证，它无需经过那个窗口就能使用相机和麦克风（[Telegram 小程序](https://core.telegram.org/bots/webapps)；[Telegram Android 版源代码](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java)）。Telegram 的文档没有描述小程序在使用您手机的运动传感器、在手机上保存最多 5 MB 数据或占满整个屏幕之前会有任何提示（[Telegram 小程序](https://core.telegram.org/bots/webapps)）。全屏页面可以看起来和 Telegram 一模一样，所以如果小程序里出现登录表单，请把它当作警示信号（[卡巴斯基](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/)）。

**点按链接。** 链接背后的网站能看到您的 IP 地址（[Telegram 隐私政策](https://telegram.org/privacy)）。

**连接钱包或签署交易。** 您可能会损失资金（[Cointelegraph](https://cointelegraph.com/magazine/ethereum-phishing-drainers-ton-bitcoin/)）。

## 真正的危险

大多数危险都不需要漏洞：有人骗您交出某样东西。

1. **有人进入您的账号。** 机器人或陌生人把您引到一个小程序或网页：免费礼物、“给我投票”页面、假的安全检查。它会索要您的电话号码和登录验证码，显示一个让您扫描的二维码，或者让 Telegram 向您显示一个真实的登录请求让您批准（[卡巴斯基](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/)；[卡巴斯基](https://www.kaspersky.com/blog/telegram-takeover-contest/47195/)；[CYFIRMA](https://www.cyfirma.com/research/re-emerging-telegram-phishing-campaign-targeting-user-authorization-prompts/)）。登录验证码只输入到 Telegram 应用本身，或您自己打开的 Telegram 官方登录页面中，绝不要转给别人（[Telegram 常见问题](https://telegram.org/faq)）。只扫描您自己电脑上的 Telegram 显示的登录二维码，绝不要扫描别人发给您的页面上的二维码。对于不是您自己发起的登录请求，绝不要点按“是的，这是我”。设置两步验证密码，除了 Telegram 不要在任何地方输入它。如果您已经做了其中某件事，请前往“设置 > 设备”，注销所有其它设备上的会话，并更改该密码。
2. **看起来像真实服务的页面** 要求您登录、在提取根本不存在的收益之前先支付“保证金”，或安装某个应用（[卡巴斯基](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/)；[BleepingComputer](https://www.bleepingcomputer.com/news/security/telegram-mini-apps-abused-for-crypto-scams-android-malware-delivery/)）。
3. **假的“验证”机器人** 要求您把一条命令粘贴到电脑中，而这条命令会安装恶意软件（[Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/criminals-exploit-telegram-captcha-to-trick-victims-into-installing-malware)；[Cointelegraph](https://cointelegraph.com/news/telegram-verification-bots-carry-crypto-stealing-malware)）。
4. **小程序悄悄把您的数据发给跟踪器**（[TeleGapper, 2026](https://arxiv.org/html/2608.13390)）。
5. **少数情况下，是 Telegram 本身的漏洞。**
   - 2024 年，一个漏洞让攻击者可以在聊天中发送一个看起来像视频的 Android 应用；除非您点按它并同意安装，否则什么都不会被安装。Telegram 在 10.14.5 版中修复了它（[ESET](https://www.welivesecurity.com/en/eset-research/cursed-tapes-exploiting-evilvideo-vulnerability-telegram-android/)）。
   - 2026 年 10 月，Telegram Android 版的一个语音通话漏洞被披露，已在 12.10.4 版中修复（[SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)）。
   - 2026 年 11 月，Telegram 增加了小组件，即消息内的小型程序（[Bot API 更新日志](https://core.telegram.org/bots/api-changelog)）。在小组件公布两天后，安全公司 V12 发布了一段视频：一个机器人对“开始”的回复让一部 Android 手机自己打开了计算器，由此看来，这条消息在手机上运行了代码。V12 没有公布细节。据报道，Telegram 确认了该漏洞，并表示修复“已部署给所有用户”；当时尚无攻击报告（[SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)）。从 13.2.2 版起，Telegram Android 版在一个独立的进程中运行小组件，该进程没有任何权限、文件或网络（[Telegram Android 版源代码](https://github.com/DrKLO/Telegram/commit/21f7d10)）。
   - Telegram 的创始人写道，这个问题“不存在”：“没有人会仅仅因为收到一条消息就被入侵”，您“必须先主动启动第三方服务”，而且“就连这一点也已在服务器端完全修补”（[他的帖子](https://t.me/durov/560)）。无论服务器端改了什么，独立的小组件进程只会随应用更新而来。

   应用中的漏洞要靠更新 Telegram 来修复。Telegram 没有说明其 iPhone 版和电脑版应用是否受到影响，所以请在您使用它的每台设备上都更新它（[SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)）。

## 有两项设置比任何机器人都重要

**连接到您自己账号的企业机器人** 可以读取您选择的聊天，并在您授予的权限范围内回复这些聊天、删除消息、更改您的名字、简介和头像，以及转移您的礼物和星星。请把这看作把手机交给别人，并检查“设置 > Telegram 企业版 > 聊天自动化”（[Telegram 隐私政策](https://telegram.org/privacy)；[Telegram Bot API](https://core.telegram.org/bots/api)）。

**在群组中，** 机器人通常只能看到发给它的命令、对它的回复以及通过它发送的消息。如果它是管理员，或者其所有者关闭了它的隐私模式，它就能看到所有内容；成员列表会显示是哪种情况（[Telegram 机器人功能](https://core.telegram.org/bots/features)）。

## 其他应用的工作方式大致相同

**WhatsApp、Messenger、Instagram、Viber、Slack 和 X：** 机器人就是一家公司的计算机。除非机器人打开网页，否则您的手机只与平台通信，但企业会读取您发送的内容，其服务提供商也可能会读取。
- **WhatsApp：** 当企业使用 Meta 自己的服务时，Meta 会解密其消息并保留最多 30 天，企业还可能把您发送的内容用于自己的营销，包括广告（[Meta](https://developers.facebook.com/documentation/business-messaging/whatsapp/data-privacy-and-security)）。WhatsApp 表示，企业使用 Meta 的服务时会在聊天中显示出来，而且它不把这些聊天算作端到端加密（[WhatsApp](https://faq.whatsapp.com/general/28030015)）。
- **Messenger：** 企业可以在 Messenger 中打开网页，这些网页可以得知您的一个 ID 以及您来自哪个聊天，这和 Telegram 小程序很像（[Meta](https://developers.facebook.com/documentation/business-messaging/messenger-platform/webview)；[Meta](https://developers.facebook.com/documentation/business-messaging/messenger-platform/webview/context)）。
- **Instagram：** 企业的机器人只有在您先给它发消息之后才能给您发消息（[Meta](https://developers.facebook.com/documentation/instagram-platform/instagram-api-with-instagram-login/messaging-api)）。
- **Viber：** 机器人可以看到您的国家、语言、设备和移动网络（[Viber](https://creators.viber.com/docs/bots-api/resources/subscribers/get-subscriber-details)）。
- **Slack：** 应用会在其权限允许的范围内读取它被添加到的频道和聊天（[Slack](https://docs.slack.dev/reference/scopes/)）。
- **X：** 在与机器人的加密聊天中，机器人自己的软件持有密钥并解密您的消息，所以其所有者可以读取这些消息（[X](https://docs.x.com/xchat/introduction)；[X](https://docs.x.com/xchat/bots)）。

**Discord：** 机器人读取其权限允许的内容。Discord 的应用内活动是别人的网页应用，但它们经由 Discord 与其所有者通信，Discord 表示这样可以不让所有者看到您的 IP 地址（[Discord](https://github.com/discord/discord-api-docs/blob/main/developers/activities/development-guides/networking.mdx)）。

**微信、支付宝、LINE、TikTok 及类似应用：** 它们的小程序和 Telegram 的类似，是应用内别人的程序。它们无需询问就能通过一个 ID 识别您（[微信](https://developers.weixin.qq.com/miniprogram/en/dev/framework/open-ability/union-id.html)；[支付宝](https://miniprogram.alipay.com/docs/miniprogram/mpdev/api_openapi_getauthcode)；[TikTok](https://developers.tiktok.com/docs/en/tiktok-minis-silent-login)；[LINE](https://developers.line.biz/en/docs/line-mini-app/develop/channel-consent-simplification/)，针对已认证的小程序），而且您的手机通常会连接到其所有者的服务器（[微信](https://developers.weixin.qq.com/miniprogram/en/dev/framework/ability/network.html)）。2023 年的一项研究发现，微信本身会收到您在其小程序中所做操作的详细记录（[公民实验室](https://citizenlab.ca/2023/06/privacy-in-the-wechat-ecosystem-full-report/)）。

**Signal** 没有机器人平台，也没有小程序。那里的机器人是由程序运行的普通账号（[signal-cli](https://github.com/AsamK/signal-cli)），它会读取您发给它的内容。

## 简而言之

按下“开始”会让机器人看到您在 Telegram 上的身份，并让它可以给您发消息。打开小程序还会让其所有者（而且往往还有跟踪器）看到您从哪里连接。大多数危害始于您交出某样东西（验证码、登录批准、电话号码、付款、签名、要安装的应用），或者在少数情况下，源于应用本身的漏洞。请保持应用更新，设置两步验证密码，绝不交出验证码，也绝不批准不是您自己发起的登录，并屏蔽您不再使用的机器人。
