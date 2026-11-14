---
title: "Qué puede ver un bot o una miniapp"
---

Las apps de mensajería dejan que bots y pequeñas apps de otras personas funcionen dentro de ellas. Android solo ve la
app de mensajería, así que nada en tu teléfono te dice qué recibe un bot o una miniapp cuando lo usas. Esta página
dice qué recibe y cuáles son los peligros reales. Empieza por Telegram y termina con otras apps.

Comprobado el 13 de noviembre de 2026. Estas apps cambian cada pocos meses; si algo de aquí es incorrecto o está
desactualizado, [avísanos](https://github.com/visadahyu/datapavan/issues).

## Cuando pulsas Iniciar en un bot de Telegram

El dueño del bot recibe tu número de ID de Telegram, tu nombre, tu nombre de usuario si tienes uno, el idioma de tu
app y si pagas Premium ([Telegram Bot API](https://core.telegram.org/bots/api);
[Política de privacidad de Telegram](https://telegram.org/privacy)). El dueño también puede consultar tus fotos de
perfil, tu biografía, tu cumpleaños y las publicaciones del canal personal de tu perfil
([Bot API](https://core.telegram.org/bots/api)). La política de privacidad de Telegram considera públicas tus fotos;
para lo demás, las páginas de Telegram no dicen si tus ajustes de privacidad limitan estas consultas.

El bot no recibe tu número de teléfono, tus contactos, tus otros chats, tu ubicación ni tus archivos. Recibe tu
número, tu ubicación o tu dirección postal solo cuando los compartes: con un botón hecho para eso, enviándolos tú
mismo, escribiéndolos al pagar a través del bot o, en el caso de tu ubicación, permitiéndolo cuando usas el bot en
modo inline ([Bot API](https://core.telegram.org/bots/api); [Política de privacidad de Telegram](https://telegram.org/privacy)).

Tu teléfono nunca se conecta a la computadora del bot. Telegram lleva los mensajes y los archivos en ambos sentidos y
genera las vistas previas de los enlaces en sus propios servidores, así que el bot no ve tu dirección IP
([Bot API](https://core.telegram.org/bots/api);
[Telegram para Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/res/values/strings.xml)).
Telegram no lo dice con estas palabras; se deduce de cómo funcionan los bots, y la única forma que nombra la política
de privacidad de Telegram para que un bot obtenga tu dirección IP es un enlace o un botón a un sitio web que controla
su dueño ([Política de privacidad de Telegram](https://telegram.org/privacy)).

Todo lo que envías al bot llega a su dueño, que puede leerlo. Un bot no puede iniciar un chat contigo, pero una vez
que pulsas Iniciar puede escribirte cuando quiera, hasta que lo bloquees
([Bots de Telegram](https://core.telegram.org/bots); [Preguntas frecuentes sobre bots](https://core.telegram.org/bots/faq)).
Escribir a una cuenta de empresa también puede significar escribir a su bot, que entonces recibe los mismos datos
sobre ti ([Política de privacidad de Telegram](https://telegram.org/privacy)).

## Qué lo cambia

**Compartir tu contacto o tu ubicación.** Si tocas un botón para compartir tu contacto o tu ubicación, el bot recibe
tu número de teléfono o dónde estás.

**Abrir la miniapp del bot.** Una miniapp es el sitio web del dueño, abierto dentro de Telegram. El sitio ve tu
dirección IP y, por tanto, aproximadamente dónde estás
([Condiciones de las miniapps de Telegram](https://telegram.org/tos/mini-apps)).
En Android también ve la marca, el modelo y la versión de Android de tu teléfono
([Código fuente de Telegram para Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java)).
Según cómo la abras, Telegram también le da una copia firmada de tu identidad de Telegram y, a veces, datos del chat
desde el que la abriste ([Miniapps de Telegram](https://core.telegram.org/bots/webapps);
[Condiciones de las miniapps](https://telegram.org/tos/mini-apps)). Cada rastreador que la página carga también ve
tu dirección IP. Un estudio aún no revisado por pares probó 278 miniapps de un catálogo: el 59 % envió datos a al
menos una empresa externa, sobre todo de analítica o publicidad, que su política de privacidad no cubría, y la
mayoría no tenía política propia, solo la estándar de Telegram ([TeleGapper, 2026](https://arxiv.org/html/2608.13390)).

En Android, antes de que una miniapp obtenga tu número de teléfono, tu ubicación, la cámara o el micrófono, Telegram
te pregunta en su propia ventana, que nombra al bot, y puedes decir que no. La única excepción en el código es la
propia verificación de edad de Telegram, que obtiene la cámara y el micrófono sin esa ventana
([Miniapps de Telegram](https://core.telegram.org/bots/webapps);
[Código fuente de Telegram para Android](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/web/BotWebViewContainer.java)).
La documentación de Telegram no describe ningún aviso antes de que una miniapp use los sensores de movimiento de tu
teléfono, guarde hasta 5 MB de datos en tu teléfono u ocupe toda la pantalla
([Miniapps de Telegram](https://core.telegram.org/bots/webapps)). Una página a pantalla completa puede verse
exactamente como Telegram, así que toma un formulario de inicio de sesión dentro de una miniapp como señal de alerta
([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/)).

**Tocar un enlace.** El sitio que hay detrás ve tu dirección IP
([Política de privacidad de Telegram](https://telegram.org/privacy)).

**Conectar una billetera o firmar una transacción.** Puedes perder dinero
([Cointelegraph](https://cointelegraph.com/magazine/ethereum-phishing-drainers-ton-bitcoin/)).

## Los peligros reales

La mayoría no necesita ningún fallo: alguien te engaña para que entregues algo.

1. **Alguien entra en tu cuenta.** Un bot o un desconocido te lleva a una miniapp o a una página: un regalo gratis,
   una página de «vota por mí», una falsa comprobación de seguridad. Te pide tu número de teléfono y tu código de
   inicio de sesión, te muestra un código QR para escanear o hace que Telegram te muestre una solicitud de inicio de
   sesión real para que la apruebes
   ([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/);
   [Kaspersky](https://www.kaspersky.com/blog/telegram-takeover-contest/47195/);
   [CYFIRMA](https://www.cyfirma.com/research/re-emerging-telegram-phishing-campaign-targeting-user-authorization-prompts/)).
   Escribe tu código de inicio de sesión solo en la propia app de Telegram, o en la página de inicio de sesión de
   Telegram que abriste tú mismo, y nunca se lo pases a nadie ([Preguntas frecuentes de Telegram](https://telegram.org/faq)).
   Escanea un código QR de inicio de sesión solo si lo muestra Telegram en tu propia computadora, nunca uno de una
   página que alguien te envió. Nunca toques «Sí, soy yo» en una solicitud de inicio de sesión que no iniciaste
   tú. Configura una contraseña de verificación en dos pasos y no la escribas en ninguna parte salvo en Telegram. Si
   ya hiciste alguna de estas cosas, ve a Ajustes > Dispositivos, cierra todas las demás sesiones y cambia esa
   contraseña.
2. **Una página que parece un servicio real** te pide iniciar sesión, pagar un «depósito» antes de poder retirar
   unas ganancias que no existen o instalar una app
   ([Kaspersky](https://www.kaspersky.com/blog/telegram-mini-app-phishing/55041/);
   [BleepingComputer](https://www.bleepingcomputer.com/news/security/telegram-mini-apps-abused-for-crypto-scams-android-malware-delivery/)).
3. **Un bot de «verificación» falso** te pide pegar un comando en tu computadora, y el comando instala malware
   ([Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/criminals-exploit-telegram-captcha-to-trick-victims-into-installing-malware);
   [Cointelegraph](https://cointelegraph.com/news/telegram-verification-bots-carry-crypto-stealing-malware)).
4. **Una miniapp envía en silencio tus datos a rastreadores** ([TeleGapper, 2026](https://arxiv.org/html/2608.13390)).
5. **En raras ocasiones, un fallo del propio Telegram.**
   - En 2024, un fallo permitía a un atacante enviar en un chat una app de Android que parecía un video; no se
     instalaba nada salvo que la tocaras y aceptaras la instalación. Telegram lo corrigió en la versión 10.14.5
     ([ESET](https://www.welivesecurity.com/en/eset-research/cursed-tapes-exploiting-evilvideo-vulnerability-telegram-android/)).
   - En octubre de 2026 se dio a conocer un fallo en las llamadas de voz de Telegram para Android, corregido en la
     versión 12.10.4 ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)).
   - En noviembre de 2026, Telegram añadió los widgets, pequeños programas dentro de un mensaje
     ([Cambios de la Bot API](https://core.telegram.org/bots/api-changelog)). Dos días después de su anuncio, la
     empresa de seguridad V12 publicó un video en el que la respuesta de un bot a Iniciar hacía que un teléfono
     Android abriera su calculadora por sí solo, lo que sugiere que el mensaje ejecutó código en el teléfono. V12 no
     publicó detalles. Según se informó, Telegram confirmó el fallo y dijo que la corrección «se había desplegado
     para todos los usuarios»; no se había informado de ningún ataque
     ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)). Desde la versión 13.2.2, Telegram
     para Android ejecuta los widgets en un proceso aparte sin permisos, archivos ni red
     ([Código fuente de Telegram para Android](https://github.com/DrKLO/Telegram/commit/21f7d10)).
   - El fundador de Telegram escribió que el problema «no existe»: «nadie podía ser hackeado solo por recibir un
     mensaje», «tenías que iniciar activamente primero un servicio de terceros» e «incluso eso está totalmente
     corregido en el servidor» ([su publicación](https://t.me/durov/560)). Cambie lo que cambie en los servidores,
     el proceso aparte de los widgets solo llega con la actualización de la app.

   Actualizar Telegram es lo que cierra los fallos de la app. Telegram no ha dicho si sus apps para iPhone y para
   computadora se vieron afectadas, así que actualízalo en cada dispositivo en el que lo uses
   ([SecurityOnline](https://securityonline.info/telegram-android-rce-v12/)).

## Dos ajustes importan más que cualquier bot

**Un bot de empresa conectado a tu propia cuenta** puede leer los chats que elijas y, con los permisos que le des,
responderlos, borrar mensajes, cambiar tu nombre, tu biografía y tu foto, y mover tus regalos y tus Estrellas.
Trátalo como si le dieras tu teléfono a alguien, y revisa Ajustes > Telegram Business > Automatización de chats
([Política de privacidad de Telegram](https://telegram.org/privacy); [Telegram Bot API](https://core.telegram.org/bots/api)).

**En un grupo,** un bot normalmente solo ve los comandos dirigidos a él, las respuestas a sus mensajes y los
mensajes enviados a través de él. Lo ve todo si es administrador o si su dueño desactivó su modo de privacidad, y la
lista de miembros indica cuál es el caso
([Funciones de los bots de Telegram](https://core.telegram.org/bots/features)).

## Otras apps funcionan de forma muy parecida

**WhatsApp, Messenger, Instagram, Viber, Slack y X:** un bot es la computadora de una empresa. Tu teléfono solo
habla con la plataforma, salvo que el bot abra una página web, pero la empresa lee lo que envías, y puede que
también sus proveedores de servicios.
- **WhatsApp:** cuando una empresa usa el servicio propio de Meta, Meta descifra sus mensajes y los guarda hasta 30
  días, y la empresa puede usar lo que envías para su propio marketing, incluida la publicidad
  ([Meta](https://developers.facebook.com/documentation/business-messaging/whatsapp/data-privacy-and-security)).
  WhatsApp dice que indica en el chat cuando una empresa usa el servicio de Meta, y no considera esos chats cifrados
  de extremo a extremo ([WhatsApp](https://faq.whatsapp.com/general/28030015)).
- **Messenger:** una empresa puede abrir páginas web dentro de Messenger, y estas pueden conocer un ID tuyo y desde
  qué chat llegaste, de forma muy parecida a una miniapp de Telegram
  ([Meta](https://developers.facebook.com/documentation/business-messaging/messenger-platform/webview);
  [Meta](https://developers.facebook.com/documentation/business-messaging/messenger-platform/webview/context)).
- **Instagram:** el bot de una empresa solo puede escribirte después de que tú le escribas
  ([Meta](https://developers.facebook.com/documentation/instagram-platform/instagram-api-with-instagram-login/messaging-api)).
- **Viber:** un bot puede ver tu país, tu idioma, tu dispositivo y tu red móvil
  ([Viber](https://creators.viber.com/docs/bots-api/resources/subscribers/get-subscriber-details)).
- **Slack:** una app lee los canales y chats a los que se ha añadido, hasta donde se lo permiten sus permisos
  ([Slack](https://docs.slack.dev/reference/scopes/)).
- **X:** en un chat cifrado con un bot, el propio software del bot tiene las claves y descifra tus mensajes, así que
  su dueño puede leerlos ([X](https://docs.x.com/xchat/introduction); [X](https://docs.x.com/xchat/bots)).

**Discord:** un bot lee lo que sus permisos le dejan leer. Las actividades dentro de Discord son apps web de otras
personas, pero llegan a sus dueños a través de Discord, que, según dice Discord, les oculta tu dirección IP
([Discord](https://github.com/discord/discord-api-docs/blob/main/developers/activities/development-guides/networking.mdx)).

**WeChat, Alipay, LINE, TikTok y apps similares:** sus miniapps son como las de Telegram, programas de otras personas
dentro de la app. Pueden reconocerte con un ID sin preguntarte
([WeChat](https://developers.weixin.qq.com/miniprogram/en/dev/framework/open-ability/union-id.html);
[Alipay](https://miniprogram.alipay.com/docs/miniprogram/mpdev/api_openapi_getauthcode);
[TikTok](https://developers.tiktok.com/docs/en/tiktok-minis-silent-login);
[LINE](https://developers.line.biz/en/docs/line-mini-app/develop/channel-consent-simplification/), en las miniapps
verificadas), y tu teléfono suele conectarse a los servidores de sus dueños
([WeChat](https://developers.weixin.qq.com/miniprogram/en/dev/framework/ability/network.html)). Un estudio de 2023
encontró que el propio WeChat recibe registros detallados de lo que haces en sus miniprogramas
([Citizen Lab](https://citizenlab.ca/2023/06/privacy-in-the-wechat-ecosystem-full-report/)).

**Signal** no tiene plataforma de bots ni miniapps. Allí un bot es una cuenta normal manejada por un programa
([signal-cli](https://github.com/AsamK/signal-cli)), y lee lo que le envías.

## En resumen

Pulsar Iniciar muestra al bot quién eres en Telegram y le permite escribirte. Abrir una miniapp también muestra a su
dueño, y a menudo a rastreadores, desde dónde te conectas. La mayor parte del daño empieza cuando entregas algo (un
código, una aprobación de inicio de sesión, un número de teléfono, un pago, una firma, una app para instalar) o, en
raras ocasiones, por un fallo de la propia app. Mantén la app actualizada, configura una contraseña de verificación
en dos pasos, nunca entregues un código ni apruebes un inicio de sesión que no iniciaste tú, y bloquea los bots que
ya no uses.
