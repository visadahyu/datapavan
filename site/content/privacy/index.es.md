---
title: "Política de privacidad"
---

Esta es una traducción. El [texto en inglés](https://datapavan.org/privacy/index.html) es el que se aplica.

- **Vigente desde:** 2026-11-07
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

## La versión 0.1 no puede abrir conexiones de red

Datapavan Basic 0.1 no solicita el permiso INTERNET, así que el propio Android le impide abrir
conexiones de red. La compilación falla si algún componente intenta añadir ese permiso. Como cualquier
app, aún puede pasar información a otra app cuando se lo pides, por ejemplo cuando abres un enlace.

Lo que hace Android por sí mismo queda fuera del control de Datapavan. En los teléfonos con los servicios de Google, Play Protect puede dar a Google información sobre las apps que instalas desde cualquier origen, incluida Datapavan, y puede enviarle una app desconocida para que la compruebe. Puedes desactivar parte de esto en los ajustes de Play Protect, en Play Store.

## Permisos y para qué se necesitan

| Permiso | Para qué se usa | Desde |
|---|---|---|
| Ver las apps instaladas | Listar las apps y sus permisos | v0.1 |
| Acceso a datos de uso (lo permites tú en Ajustes; opcional) | Mostrar cuántos datos ha enviado y recibido cada app, y qué apps llevas mucho tiempo sin abrir. Datapavan solo lee los totales y la fecha en que se usó cada app por última vez, nunca qué app abriste y cuándo, y no guarda nada de ello. Cuando compruebas una actividad en una app, también lee los contadores de tráfico totales del teléfono, que no necesitan ningún permiso, para ver si el recuento de Android está actualizado; estos números se quedan en memoria mientras la comprobación está en pantalla | v0.1 |
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
