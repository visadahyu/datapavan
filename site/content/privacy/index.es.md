---
title: "Política de privacidad"
---

Esta es una traducción. El [texto en inglés](https://datapavan.org/privacy/index.html) es el que se aplica.

- **Vigente desde:** 2026-11-07
- **Actualización:** 2026-11-18, con las líneas de Datapavan Advanced para la 0.2.0, que aún no se ha publicado
- **Responsable:** el mantenedor de Datapavan (mehdashti), hasta que se constituya la Fundación Visadahyu

**Datapavan no recopila ningún dato sobre ti.**

## Qué significa esto en la práctica

- **Sin analítica, sin informes de errores, sin telemetría.** La app no contiene SDK de terceros que puedan enviar datos.
- **Sin cuentas.** Nunca te registras ni nos das nada.
- **Sin servidores que reciban datos de usuarios.** La app no se conecta a ninguno. El sitio web del proyecto, datapavan.org, es estático y no guarda ningún registro de accesos. Tampoco guarda registro de las descargas que ofrece. Las descargas desde GitHub y las tiendas de apps se rigen por sus propias políticas.
- **Todo se queda en tu teléfono.** Todo el análisis se hace en el dispositivo. Los datos propios de Datapavan se guardan en el almacenamiento privado de la app.
- **Ninguna copia de seguridad sale del teléfono.** La copia de seguridad en la nube de Android y la transferencia entre dispositivos están desactivadas para los datos de Datapavan.
- **Al desinstalar se borran los datos de Datapavan.**

## Qué guarda Datapavan en tu teléfono

- **El registro del plan de corrección.** Por cada cambio que haces con el plan: el nombre de paquete
  de la app, la hora, la pantalla que abrió y lo que la app tenía antes y después (sus permisos
  sensibles, su acceso especial y su permiso de VPN, y si estaba habilitada e instalada). Te permite
  deshacer un cambio y ver si alguno ha vuelto. La pantalla del registro lo borra con un toque.
- **La revisión estricta de sensores:** qué acceso tenía cada app cuando la revisaste.
- **Tus ajustes:** la apariencia y, antes de Android 13, el idioma que elegiste.
- **Los resultados del análisis de rastreadores,** para no volver a analizar las apps que no han
  cambiado, y los **paquetes de datos** que importaste.

Todo ello se queda en el almacenamiento privado de la app y nunca se incluye en copias de seguridad ni
se envía. Cualquiera que pueda abrir Datapavan en tu teléfono desbloqueado puede verlo, igual que puede
ver el resto de la app.

**Datapavan Advanced, desde la 0.2.0, también guarda:**

- **Un registro de conexiones, solo si eliges llevar uno.** Eliges entre no conservar nada, 1, 7 o 30 días; hasta que
  elijas, no guarda nada. Cada entrada contiene la app, adónde se conectó (la dirección, el puerto y el nombre, con el
  origen del que Datapavan obtuvo el nombre), los bytes en cada sentido, la hora y si estabas usando la app en ese
  momento, si se ejecutaba con su notificación o ninguna de las dos cosas. Cada entrada se cifra con una clave propia de
  su día, protegida por el almacén de claves de Android; en un teléfono con bloqueo de pantalla, los días anteriores
  solo se pueden leer mientras está desbloqueado. Los días que superan el plazo que elegiste se borran junto con sus
  claves, y un toque lo borra todo. Para las apps que envías a través de tu herramienta para eludir bloqueos, el
  registro no guarda ningún destino salvo que lo actives.
- **El tráfico reciente de cada app, para la vista «Now»,** solo en memoria. Desaparece cuando el firewall se detiene.
- **Los ajustes de tu herramienta para eludir bloqueos:** si las apps pasan por ella y cuáles, el host y el puerto de la
  herramienta, y la contraseña que Datapavan creó para ella; esta contraseña está cifrada con una clave protegida por el
  almacén de claves de Android.
- **Las apps que dejas fuera del firewall,** que entonces se conectan a internet sin pasar por él: sus nombres, hasta
  que las vuelvas a incluir.

## La versión 0.1 no puede abrir conexiones de red

Datapavan Basic 0.1 no solicita el permiso INTERNET, así que el propio Android le impide abrir
conexiones de red. La compilación falla si algún componente intenta añadir ese permiso. Como cualquier
app, aún puede pasar información a otra app cuando se lo pides, por ejemplo cuando abres un enlace.

Lo que hace Android por sí mismo queda fuera del control de Datapavan. En los teléfonos con los servicios de Google, Play Protect puede dar a Google información sobre las apps que instalas desde cualquier origen, incluida Datapavan, y puede enviarle una app desconocida para que la compruebe. Puedes desactivar parte de esto en los ajustes de Play Protect, en Play Store. La comprobación de hardware de Datapavan también puede hacer que Android contacte con Google: en los teléfonos que obtienen sus claves de certificación del servidor de aprovisionamiento de Google, una comprobación que ya no encuentra ninguna le pide más a Android (Android 13 avisa al servicio de aprovisionamiento y, desde Android 14, es el almacén de claves el que se las pide a ese servicio), y Android las obtiene por su propia conexión. Datapavan no envía nada por su cuenta.

## A qué se conecta Datapavan Advanced

Datapavan Advanced, desde la 0.2.0, reenvía el tráfico de tus apps a donde ellas lo envían, a través del firewall en el
teléfono; nada de él se nos envía. Por su cuenta, pregunta al resolvedor DNS de tu red por los nombres que buscan las
apps, como lo haría el teléfono sin Datapavan Advanced, mediante una conexión cifrada donde el teléfono usaba una.
Cuando envías apps a través de tu herramienta para eludir bloqueos, sus búsquedas de nombres van a la herramienta, y sus
demás consultas DNS van a través de la herramienta a Quad9, una fundación suiza que no registra direcciones, así que
Quad9 ve la dirección de la herramienta, no la tuya.

## Permisos y para qué se necesitan

| Permiso | Para qué se usa | Desde |
|---|---|---|
| Ver las apps instaladas | Listar las apps y sus permisos | v0.1 |
| Acceso a datos de uso (lo permites tú en Ajustes; opcional) | Mostrar cuántos datos ha enviado y recibido cada app, y qué apps llevas mucho tiempo sin abrir. Para ello, Datapavan solo lee los totales y la fecha en que se usó cada app por última vez, y no guarda nada de ello; Datapavan Basic nunca lee qué app abriste y cuándo. Cuando compruebas una actividad en una app, también lee los contadores de tráfico totales del teléfono, que no necesitan ningún permiso, para ver si el recuento de Android está actualizado; estos números se quedan en memoria mientras la comprobación está en pantalla | v0.1 |
| Acceso a datos de uso, en Datapavan Advanced | Saber, para cada conexión, si estabas usando su app en ese momento, si se ejecutaba con una notificación que mostraba Android (música, navegación) o ninguna de las dos cosas. Para ello, Advanced también lee el historial de Android, desde el arranque del teléfono, sobre qué app estaba en pantalla y cuándo, qué apps ejecutaban un servicio en primer plano, cuáles usaste de otras formas (por ejemplo, tocando su notificación) y cuándo se encendió o apagó la pantalla y apareció la pantalla de bloqueo; y si cada app puede mostrar notificaciones. Lo que averigua lo guarda solo en dos sitios: en memoria para la vista «Now» y, si llevas un registro de conexiones, como el estado de cada entrada, durante los días que elegiste | Datapavan Advanced, desde la 0.2.0 |
| Estado de la red | Saber si hay una VPN activa. No permite ninguna conexión | v0.1 |
| Ocultar las superposiciones de otras apps | Desde Android 12: mientras Datapavan está en la pantalla, otras apps no pueden mostrarse encima. No permite ninguna conexión | Datapavan Basic posterior a la 0.1.2 y Datapavan Advanced |
| VPN (lo permites tú) | El firewall **local**. El tráfico se filtra en el teléfono y nunca se nos envía | Datapavan Advanced, desde la 0.2.0 |
| Internet | Reenviar el tráfico de otras apps a través del firewall local. Datapavan Basic nunca lo pide | Datapavan Advanced, desde la 0.2.0 |

## Actualizaciones opcionales de las listas de rastreadores (previstas)

El propio Datapavan solo importa archivos de listas firmados. Si llegan las descargas opcionales, se
obtendrán de un sitio espejo público, y solo si activas esta opción. Como en cualquier descarga:

- el operador del sitio espejo ve tu dirección IP y la hora de la solicitud;
- el operador, y cualquiera que observe tu red, puede saber que el dispositivo usa Datapavan.

La solicitud no contiene nada sobre tu teléfono, tus apps ni tu actividad. Las actualizaciones están firmadas, y las
listas más antiguas nunca se aceptan en lugar de las más recientes. Puedes desactivar las actualizaciones e importar
los archivos de listas manualmente. Cuando existan sitios espejo, esta política nombrará a cada operador y dirá qué
registra y durante cuánto tiempo.

## Contacto

Para preguntas sobre esta política: abre una incidencia (issue) en GitHub. Para cualquier asunto delicado, usa el
formulario de informe privado indicado en [SECURITY.md](https://github.com/visadahyu/datapavan/blob/main/SECURITY.md).
