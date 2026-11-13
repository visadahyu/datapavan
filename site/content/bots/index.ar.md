---
title: "ما يمكن للبوت أو التطبيق المصغّر رؤيته"
---

تتيح تطبيقات المراسلة تشغيل بوتات وتطبيقات صغيرة يملكها آخرون داخلها. لا يرى Android سوى تطبيق المراسلة، لذا لا شيء
على هاتفك يخبرك بما يحصل عليه البوت أو التطبيق المصغّر عندما تستخدمه. تشرح هذه الصفحة ما يحصل عليه، وما المخاطر
الحقيقية. تبدأ بـ Telegram وتنتهي بتطبيقات أخرى.

جرى التحقق في ١٣ نوفمبر ٢٠٢٦. تتغير هذه التطبيقات كل بضعة أشهر؛ فإذا كان شيء هنا خاطئًا أو قديمًا،
[أخبرنا](https://github.com/visadahyu/datapavan/issues).

## عندما تضغط «ابدأ» في بوت على Telegram

يحصل مالك البوت على رقم معرّفك في Telegram، واسمك، واسم المستخدم إن كان لديك واحد، واللغة التي يستخدمها تطبيقك،
وما إذا كنت تدفع اشتراك Premium ([Telegram Bot API](https://core.telegram.org/bots/api)؛
[سياسة الخصوصية في Telegram](https://telegram.org/privacy)). ويمكن للمالك أيضًا الاطلاع على صور ملفك الشخصي، ونبذتك
التعريفية، وتاريخ ميلادك، ومنشورات القناة الشخصية المعروضة في ملفك الشخصي ([Bot API](https://core.telegram.org/bots/api)).
تصف سياسة الخصوصية في Telegram صورك بأنها علنية؛ أما الباقي، فلا تذكر صفحات Telegram ما إذا كانت إعدادات الخصوصية
لديك تحدّ من هذا الاطلاع.

لا يحصل البوت على رقم هاتفك، ولا جهات اتصالك، ولا محادثاتك الأخرى، ولا موقعك، ولا ملفاتك. فهو لا يحصل على رقمك أو
موقعك أو عنوانك إلا عندما تشاركها: بزر مخصّص لذلك، أو بإرسالها بنفسك، أو بكتابتها عند الدفع عبر البوت، أو، بالنسبة
إلى موقعك، بالسماح بذلك عندما تستخدم البوت بالوضع المضمَّن (inline)
([Bot API](https://core.telegram.org/bots/api)؛ [سياسة الخصوصية في Telegram](https://telegram.org/privacy)).

لا يتصل هاتفك أبدًا بكمبيوتر البوت. ينقل Telegram الرسائل والملفات في الاتجاهين، ويُنشئ معاينات الروابط على خوادمه،
لذا لا يرى البوت عنوان IP الخاص بك
([Bot API](https://core.telegram.org/bots/api)؛
[Telegram لنظام Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/res/values/strings.xml)).
لا يقول Telegram ذلك صراحةً؛ لكنه يُستنتج من طريقة عمل البوتات، والطريقة الوحيدة التي تذكرها سياسة الخصوصية في
Telegram لحصول البوت على عنوان IP الخاص بك هي رابط أو زر يقود إلى موقع ويب يتحكم فيه مالك البوت
([سياسة الخصوصية في Telegram](https://telegram.org/privacy)).

كل ما ترسله إلى البوت يصل إلى مالكه، ويمكنه قراءته. لا يستطيع البوت أن يبدأ محادثة معك، لكن بمجرد أن تضغط «ابدأ»
يمكنه أن يراسلك متى شاء، إلى أن تحظره
([بوتات Telegram](https://core.telegram.org/bots)؛ [الأسئلة الشائعة عن البوتات](https://core.telegram.org/bots/faq)).
وقد تعني مراسلة حساب تجاري أيضًا مراسلة البوت الخاص به، فيحصل عندئذ على التفاصيل نفسها عنك
([سياسة الخصوصية في Telegram](https://telegram.org/privacy)).

## ما الذي يغيّر ذلك

**مشاركة بيانات اتصالك أو موقعك.** إذا نقرت على زر لمشاركة بيانات اتصالك أو موقعك، يحصل البوت على رقم هاتفك أو على
مكان وجودك.

**فتح التطبيق المصغّر للبوت.** التطبيق المصغّر هو موقع الويب الخاص بالمالك، يُفتح داخل Telegram. يرى الموقع عنوان IP
الخاص بك، ومن ثَمّ مكان وجودك تقريبًا ([شروط التطبيقات المصغّرة في Telegram](https://telegram.org/tos/mini-apps)).
وعلى Android يرى أيضًا الشركة المصنّعة لهاتفك وطرازه وإصدار Android
([الرمز المصدري لـ Telegram لنظام Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java)).
وبحسب طريقة فتحك له، يعطيه Telegram أيضًا نسخة موقَّعة من هويتك على Telegram، وأحيانًا تفاصيل عن المحادثة التي فتحته
منها ([التطبيقات المصغّرة في Telegram](https://core.telegram.org/bots/webapps)؛
[شروط التطبيقات المصغّرة](https://telegram.org/tos/mini-apps)). وكل أداة تتبّع تحمّلها الصفحة ترى عنوانك أيضًا. اختبرت
دراسة لم تخضع بعد لمراجعة الأقران ٢٧٨ تطبيقًا مصغّرًا من كتالوج واحد: أرسل ٥٩٪ منها بيانات إلى شركة خارجية واحدة على
الأقل لا تشملها سياسة خصوصية التطبيق، وهي في الغالب شركات تحليلات أو إعلانات، ولم يكن لمعظم التطبيقات سياسة خاصة بها، بل
سياسة Telegram القياسية فقط ([TeleGapper، ٢٠٢٦](https://arxiv.org/html/2608.13390)).

على Android، قبل أن يحصل تطبيق مصغّر على رقم هاتفك أو موقعك أو الكاميرا أو الميكروفون، يسألك Telegram في نافذة خاصة
به تذكر اسم البوت، ويمكنك الرفض. والاستثناء الوحيد في الرمز البرمجي هو فحص العمر الخاص بـ Telegram نفسه، الذي يحصل
على الكاميرا والميكروفون دون تلك النافذة ([التطبيقات المصغّرة في Telegram](https://core.telegram.org/bots/webapps)؛
[الرمز المصدري لـ Telegram لنظام Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java)).
لا تصف وثائق Telegram أي طلب موافقة قبل أن يستخدم تطبيق مصغّر مستشعرات الحركة في هاتفك، أو يحفظ ما يصل إلى ٥ ميغابايت
من البيانات على هاتفك، أو يملأ الشاشة كلها ([التطبيقات المصغّرة في Telegram](https://core.telegram.org/bots/webapps)).
يمكن لصفحة بملء الشاشة أن تبدو تمامًا مثل Telegram، لذا اعتبر نموذج تسجيل الدخول داخل تطبيق مصغّر علامة تحذير
([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/)).

**النقر على رابط.** يرى الموقع الذي يقود إليه الرابط عنوان IP الخاص بك
([سياسة الخصوصية في Telegram](https://telegram.org/privacy)).

**ربط محفظة أو توقيع معاملة.** يمكن أن تخسر مالًا
([Cointelegraph](https://cointelegraph.com/magazine/ethereum-phishing-drainers-ton-bitcoin/)).

## المخاطر الحقيقية

معظمها لا يحتاج إلى أي خلل برمجي: شخص ما يخدعك لتسلّمه شيئًا.

1. **يدخل شخص ما إلى حسابك.** يرسلك بوت أو شخص غريب إلى تطبيق مصغّر أو صفحة: هدية مجانية، أو صفحة «صوِّت لي»، أو
   فحص أمني مزيّف. فتطلب منك رقم هاتفك ورمز تسجيل الدخول، أو تعرض رمز QR لتمسحه، أو تجعل Telegram يعرض عليك طلب
   تسجيل دخول حقيقيًا لتوافق عليه
   ([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/)؛
   [Kaspersky](https://www.kaspersky.com/blog/telegram-takeover-contest/47195/)؛
   [CYFIRMA](https://www.cyfirma.com/research/re-emerging-telegram-phishing-campaign-targeting-user-authorization-prompts/)).
   لا تكتب رمز تسجيل الدخول إلا في تطبيق Telegram نفسه، أو في صفحة تسجيل الدخول الخاصة بـ Telegram التي فتحتها
   بنفسك، ولا تعطه لأحد أبدًا ([الأسئلة الشائعة في Telegram](https://telegram.org/faq)). لا تمسح رمز QR لتسجيل
   الدخول إلا من شاشة Telegram على كمبيوترك أنت، وليس أبدًا من صفحة أرسلها إليك أحد. لا تنقر أبدًا على «نعم، أنا»
   في طلب تسجيل دخول لم تبدأه أنت. عيّن كلمة مرور للتحقق بخطوتين، ولا تكتبها في أي مكان سوى Telegram. وإذا كنت
   قد فعلت أحد هذه الأمور بالفعل، فانتقل إلى الإعدادات > الأجهزة، وأنهِ جميع الجلسات الأخرى، وغيّر كلمة المرور تلك.
2. **صفحة تبدو مثل خدمة حقيقية** تطلب منك تسجيل الدخول، أو أن تدفع مبلغ «إيداع» قبل أن تتمكن من سحب أرباح لا وجود
   لها، أو أن تثبّت تطبيقًا
   ([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/)؛
   [BleepingComputer](https://www.bleepingcomputer.com/news/security/telegram-mini-apps-abused-for-crypto-scams-android-malware-delivery/)).
3. **بوت «تحقّق» مزيّف** يطلب منك لصق أمر في كمبيوترك، فيثبّت الأمر برامج ضارة
   ([Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/criminals-exploit-telegram-captcha-to-trick-victims-into-installing-malware)؛
   [Cointelegraph](https://cointelegraph.com/news/telegram-verification-bots-carry-crypto-stealing-malware)).
4. **تطبيق مصغّر يرسل بياناتك بصمت إلى أدوات التتبّع** ([TeleGapper، ٢٠٢٦](https://arxiv.org/html/2608.13390)).
5. **ونادرًا، خلل برمجي في Telegram نفسه.**
   - في عام ٢٠٢٤، سمحت ثغرة لمهاجم بإرسال تطبيق Android يبدو كأنه مقطع فيديو في محادثة؛ ولم يكن يُثبَّت شيء إلا إذا
     نقرت عليه ووافقت على التثبيت. أصلحها Telegram في الإصدار 10.14.5
     ([ESET](https://www.welivesecurity.com/en/eset-research/cursed-tapes-exploiting-evilvideo-vulnerability-telegram-android/)).
   - في أكتوبر ٢٠٢٦، كُشف عن ثغرة في المكالمات الصوتية في Telegram لنظام Android، وقد أُصلحت في الإصدار 12.10.4
     ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)).
   - في نوفمبر ٢٠٢٦ أضاف Telegram الودجات (widgets)، وهي برامج صغيرة داخل الرسالة
     ([تغييرات Bot API](https://core.telegram.org/bots/api-changelog)). وبعد يومين من الإعلان عنها، نشرت شركة الأمن
     V12 مقطع فيديو جعل فيه ردُّ بوت على «ابدأ» هاتفَ Android يفتح الآلة الحاسبة من تلقاء نفسه، ما يوحي بأن الرسالة
     شغّلت رمزًا برمجيًا على الهاتف. لم تنشر V12 أي تفاصيل. وأُفيد بأن Telegram أكّد الثغرة وقال إن الإصلاح «نُشر
     لجميع المستخدمين»؛ ولم تكن قد وردت تقارير عن أي هجمات
     ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)). ومنذ الإصدار 13.2.2، يشغّل Telegram
     لنظام Android الودجات في عملية منفصلة بلا أذونات ولا ملفات ولا شبكة
     ([الرمز المصدري لـ Telegram لنظام Android](https://github.com/DrKLO/Telegram/commit/21f7d10)).
   - كتب مؤسس Telegram أن المشكلة «غير موجودة»: «لم يكن من الممكن اختراق أي شخص لمجرد تلقّيه رسالة»، وأنه «كان عليك
     أولًا أن تشغّل بنفسك خدمة تابعة لجهة خارجية»، و«حتى هذا أُصلح بالكامل من جهة الخادم»
     ([منشوره](https://t.me/durov/560)). وأيًّا كان ما تغيّر على الخوادم، فإن العملية المنفصلة للودجات لا تأتي إلا
     مع تحديث التطبيق.

   تحديث Telegram هو ما يُصلح أخطاء التطبيق. لم يذكر Telegram ما إذا كانت تطبيقاته على iPhone والكمبيوتر قد تأثرت،
   لذا حدّثه على كل جهاز تستخدمه عليه
   ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)).

## إعدادان أهم من أي بوت

**بوت أعمال مربوط بحسابك أنت** يمكنه قراءة المحادثات التي تختارها، ويمكنه، بالصلاحيات التي تمنحها له، الرد عليها،
وحذف الرسائل، وتغيير اسمك ونبذتك التعريفية وصورتك، ونقل هداياك ونجومك (Stars). تعامل مع ذلك كأنك تسلّم هاتفك لشخص
آخر، وتحقّق من الإعدادات > تيليجرام الأعمال > المحادثة الآلية
([سياسة الخصوصية في Telegram](https://telegram.org/privacy)؛ [Telegram Bot API](https://core.telegram.org/bots/api)).

**في المجموعة،** لا يرى البوت عادةً إلا الأوامر الموجّهة إليه، والردود عليه، والرسائل المرسلة عبره. ويرى كل شيء إذا
كان مشرفًا أو إذا أوقف مالكه وضع الخصوصية الخاص به، وتُظهر قائمة الأعضاء أيّ البوتات كذلك
([ميزات بوتات Telegram](https://core.telegram.org/bots/features)).

## التطبيقات الأخرى تعمل بطريقة مشابهة إلى حد كبير

**WhatsApp وMessenger وInstagram وViber وSlack وX:** البوت هو كمبيوتر تابع لشركة. لا يتصل هاتفك إلا بالمنصة ما لم
يفتح البوت صفحة ويب، لكن الشركة تقرأ ما ترسله، وقد يقرؤه أيضًا مزوّدو الخدمات لديها.
- **WhatsApp:** عندما تستخدم شركة خدمة Meta نفسها، تفك Meta تشفير رسائلها وتحتفظ بها لمدة تصل إلى ٣٠ يومًا، وقد
  تستخدم الشركة ما ترسله لأغراض التسويق الخاصة بها، بما في ذلك الإعلانات
  ([Meta](https://developers.facebook.com/documentation/business-messaging/whatsapp/data-privacy-and-security)).
  ويقول WhatsApp إنه يُظهر في المحادثة متى تستخدم الشركة خدمة Meta، ولا يَعُدّ تلك المحادثات مشفّرة تشفيرًا تامًّا بين
  الطرفين ([WhatsApp](https://faq.whatsapp.com/general/28030015)).
- **Messenger:** يمكن للشركة فتح صفحات ويب داخل Messenger، ويمكن لهذه الصفحات معرفة معرّف خاص بك والمحادثة التي جئت
  منها، على نحو يشبه كثيرًا التطبيق المصغّر في Telegram
  ([Meta](https://developers.facebook.com/documentation/business-messaging/messenger-platform/webview)؛
  [Meta](https://developers.facebook.com/documentation/business-messaging/messenger-platform/webview/context)).
- **Instagram:** لا يستطيع بوت الشركة مراسلتك إلا بعد أن تراسله أنت
  ([Meta](https://developers.facebook.com/documentation/instagram-platform/instagram-api-with-instagram-login/messaging-api)).
- **Viber:** يمكن للبوت أن يرى بلدك ولغتك وجهازك وشبكة الجوّال التي تستخدمها
  ([Viber](https://creators.viber.com/docs/bots-api/resources/subscribers/get-subscriber-details)).
- **Slack:** يقرأ التطبيق القنوات والمحادثات التي أُضيف إليها، في حدود ما تسمح به أذوناته
  ([Slack](https://docs.slack.dev/reference/scopes/)).
- **X:** في المحادثة المشفّرة مع بوت، يحتفظ برنامج البوت نفسه بالمفاتيح ويفك تشفير رسائلك، لذا يستطيع مالكه قراءتها
  ([X](https://docs.x.com/xchat/introduction)؛ [X](https://docs.x.com/xchat/bots)).

**Discord:** يقرأ البوت ما تسمح به أذوناته. والأنشطة داخل تطبيق Discord هي تطبيقات ويب يملكها آخرون، لكنها تتصل
بمالكيها عبر Discord، ويقول Discord إن ذلك يُخفي عنهم عنوان IP الخاص بك
([Discord](https://github.com/discord/discord-api-docs/blob/main/developers/activities/development-guides/networking.mdx)).

**WeChat وAlipay وLINE وTikTok والتطبيقات المشابهة:** تطبيقاتها المصغّرة تشبه تطبيقات Telegram، فهي برامج يملكها
آخرون داخل التطبيق. ويمكنها التعرّف عليك بمعرّف دون أن تسألك
([WeChat](https://developers.weixin.qq.com/miniprogram/en/dev/framework/open-ability/union-id.html)؛
[Alipay](https://miniprogram.alipay.com/docs/miniprogram/mpdev/api_openapi_getauthcode)؛
[TikTok](https://developers.tiktok.com/docs/en/tiktok-minis-silent-login)؛
[LINE](https://developers.line.biz/en/docs/line-mini-app/develop/channel-consent-simplification/)، للتطبيقات المصغّرة
الموثَّقة)، وعادةً ما يتصل هاتفك بخوادم مالكيها
([WeChat](https://developers.weixin.qq.com/miniprogram/en/dev/framework/ability/network.html)). ووجدت دراسة صدرت
عام ٢٠٢٣ أن WeChat نفسه يتلقى سجلات مفصّلة عمّا تفعله في برامجه المصغّرة
([Citizen Lab](https://citizenlab.ca/2023/06/privacy-in-the-wechat-ecosystem-full-report/)).

**Signal** لا توجد فيه منصة بوتات ولا تطبيقات مصغّرة. البوت هناك حساب عادي يديره برنامج
([signal-cli](https://github.com/AsamK/signal-cli))، ويقرأ ما ترسله إليه.

## باختصار

الضغط على «ابدأ» يُطلع البوت على هويتك في Telegram ويتيح له مراسلتك. وفتح تطبيق مصغّر يُطلع مالكه أيضًا، وكثيرًا ما
يُطلع أدوات التتبّع، على المكان الذي تتصل منه. يبدأ معظم الضرر عندما تسلّم شيئًا (رمزًا، أو موافقة على تسجيل دخول،
أو رقم هاتف، أو دفعة مالية، أو توقيعًا، أو تطبيقًا لتثبيته)، أو، نادرًا، بسبب خلل برمجي في التطبيق نفسه. حدّث التطبيق
باستمرار، وعيّن كلمة مرور للتحقق بخطوتين، ولا تسلّم أبدًا رمزًا ولا توافق على تسجيل دخول لم تبدأه أنت، واحظر البوتات
التي لم تعد تستخدمها.
