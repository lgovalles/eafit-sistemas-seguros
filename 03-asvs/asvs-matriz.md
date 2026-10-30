## 3. OWASP ASVS — Matriz de Cumplimiento (Nivel 1)

Se evaluaron dos capítulos de OWASP ASVS v4.0.3, seleccionados por su relación directa con las vulnerabilidades explotadas en la sección 1 y el modelado de amenazas de la sección 2:

- **V2 — Authentication**: conecta con la vulnerabilidad de autenticación débil (sección 1.5).
- **V5 — Validation, Sanitization and Encoding**: conecta con SQL Injection y XSS (secciones 1.1 y 1.2).

Alcance evaluado: flujo de login y registro, y flujo de carrito de OWASP Juice Shop (los mismos auditados en las secciones 1 y 2).

### 3.1 V2 — Authentication (Nivel 1)

| ID ASVS | Requisito | Estado | Evidencia / Hallazgo | Remediación |
|---|---|---|---|---|
| 2.1.1 | Contraseñas de usuario de mínimo 12 caracteres | **Falla** | Formulario de registro: `minlength="5"` en el campo password (confirmado vía inspección en DevTools) | Elevar la longitud mínima a 12 caracteres, tanto en frontend como en backend |
| 2.1.2 | Se permiten contraseñas de 64+ caracteres, hasta 128 | **Falla** | Formulario de registro: `maxlength="40"` en el campo password (confirmado vía inspección en DevTools) | Elevar el límite máximo a al menos 64 caracteres |
| 2.1.3 | Las contraseñas no se truncan | **Cumple** | Login exitoso con contraseña completa (`Hola_Mundo_2026! 😊 áéíóú @#€%&*()...`), confirmando que el backend no trunca ni rechaza la cadena completa | — |
| 2.1.4 | Se permite cualquier carácter Unicode imprimible, incluidos espacios y emoji | **Cumple** | Login exitoso con contraseña que incluye emoji, acentos y caracteres especiales — confirmado a nivel de backend, no solo en el campo | — |
| 2.1.5 | El usuario puede cambiar su contraseña | **Cumple** | Disponible en `/#/privacy-security/change-password` | — |
| 2.1.6 | El cambio de contraseña requiere la actual y la nueva | **Cumple** | El formulario de cambio de contraseña exige ambos campos | — |
| 2.1.7 | Las contraseñas se verifican contra listas de contraseñas filtradas | **Falla** | No se observa ninguna validación contra bases de datos de contraseñas comprometidas (ej. `admin123` fue aceptada sin advertencia) | Integrar verificación contra una API tipo Have I Been Pwned Passwords |
| 2.1.8 | Se ofrece un medidor de fortaleza de contraseña | **Cumple** | El formulario de registro muestra un indicador de fortaleza | — |
| 2.1.9 | No se exigen reglas de composición que restrinjan el tipo de caracteres | **Falla** | El registro exige combinación obligatoria de mayúscula, minúscula, número y carácter especial | Eliminar reglas de composición forzada; priorizar longitud sobre complejidad |
| 2.1.10 | No existe rotación periódica obligatoria ni historial de contraseñas | **Cumple** | No se observa ningún mecanismo de expiración o historial | — |
| 2.1.11 | Se permite pegar contraseñas y usar gestores de contraseñas | **Cumple** | El campo de contraseña no bloquea `paste` | — |
| 2.1.12 | El usuario puede ver temporalmente la contraseña completa | **Cumple** | Ícono de mostrar/ocultar contraseña (👁) visible en el formulario de login | — |

### 3.2 V2 — General Authenticator y Credential Recovery (Nivel 1)

| ID ASVS | Requisito | Estado | Evidencia / Hallazgo | Remediación |
|---|---|---|---|---|
| 2.2.1 | Controles anti-automatización limitan intentos fallidos (máx. 100/hora) | **Falla** | Confirmado en sección 1.5: múltiples intentos de login fallidos consecutivos sin bloqueo, delay ni CAPTCHA | Implementar rate limiting y bloqueo temporal de cuenta tras N intentos fallidos |
| 2.2.3 | Se envían notificaciones tras cambios de datos de autenticación o inicios de sesión riesgosos | **Falla** | No se observó ninguna notificación al usuario tras el cambio de contraseña ni tras el login con la cuenta admin desde la explotación de SQLi | Implementar notificaciones por correo ante eventos sensibles de la cuenta |
| 2.5.1 | Los secretos de recuperación no se envían en texto plano | *No aplica en este alcance* | Juice Shop no envía secretos por correo; usa pregunta de seguridad + reseteo directo | — |
| 2.5.2 | No se usan pistas de contraseña ni preguntas de seguridad | **Falla** | El flujo de recuperación de contraseña usa preguntas de seguridad (ej. "¿Nombre de tu mascota?"), explotable por ingeniería social o búsqueda pública | Reemplazar por un mecanismo basado en token enviado a un canal verificado (correo/SMS) |
| 2.5.3 | La recuperación nunca revela la contraseña actual | **Cumple** | El flujo permite establecer una nueva contraseña, no muestra la anterior | — |
| 2.5.4 | No existen cuentas compartidas o por defecto | **Falla** | Confirmado en sección 1.5: la cuenta `admin@juice-sh.op` conserva la contraseña por defecto `admin123` | Forzar cambio de contraseña en primer uso para cuentas administrativas |
| 2.5.5 | Se notifica al usuario cuando se cambia un factor de autenticación | **Falla** | No se observan notificaciones tras cambios de contraseña o email | Implementar notificaciones por correo |
| 2.5.6 | La recuperación usa un mecanismo seguro (TOTP, token, etc.) | **Falla** | Depende de la pregunta de seguridad débil (ver 2.5.2) | Migrar a recuperación basada en token de un solo uso enviado por canal verificado |

### 3.3 V5.1 — Input Validation (Nivel 1)

| ID ASVS | Requisito | Estado | Evidencia / Hallazgo | Remediación |
|---|---|---|---|---|
| 5.1.1 | Defensas contra HTTP Parameter Pollution | **Falla** | `GET /rest/products/search?q=apple&q=juice` devuelve `200 OK` con `{"status":"success","data":[]}` — el backend no valida ni rechaza parámetros duplicados; los procesa de forma silenciosa e inesperada (probablemente como arreglo), devolviendo resultados vacíos sin advertencia | Validar en servidor que cada parámetro aparezca una sola vez; rechazar con `400 Bad Request` si se detectan duplicados |
| 5.1.2 | Protección contra asignación masiva de parámetros (mass assignment) | **Falla** | En Postman, `POST http://localhost:3000/api/Users/` con `"role":"admin"` en el JSON de registro devolvió `201 Created` y un usuario creado (`id: 28`) cuya respuesta incluye `"role":"admin"`. Evidencia de aceptación del atributo sensible; queda pendiente confirmar persistencia y acceso administrativo efectivo. | Aplicar una lista positiva de campos permitidos en el registro; excluir `role` y otros atributos privilegiados del DTO de entrada y asignar el rol por defecto exclusivamente en el backend. |
| 5.1.3 | Toda entrada se valida con listas positivas (allow lists) | **Falla** | Confirmado directamente por la explotación de SQL Injection (sección 1.1): el campo email no valida formato ni contenido antes de usarse en la consulta | Validar formato de entrada (ej. regex de email) antes de cualquier procesamiento |
| 5.1.4 | Los datos estructurados están fuertemente tipados y validados contra un esquema | **Falla** | En Postman, `POST http://localhost:3000/api/Users/` sin el campo `email` devolvió `201 Created`, `status: success` y creó el usuario `id: 30` con `role: admin`. La API aceptó un registro sin un dato esencial, evidenciando validación insuficiente de campos obligatorios. No se ha comprobado aún el rechazo de tipos JSON incorrectos. | Validar el cuerpo JSON en el backend con un esquema estricto, exigir `email` y sus tipos y formatos correctos, y rechazar entradas inválidas con `400` o `422` sin crear registros. |
| 5.1.5 | Las redirecciones solo permiten destinos en lista blanca | *Verificar* | En Chrome DevTools se probaron `GET /redirect?to=google.com` y `GET /redirect?to=https%3A%2F%2Fexample.com`. Ambas devolvieron `406 Not Acceptable` (`Unrecognized target URL for redirect`) y no redirigieron a destinos externos. Es evidencia favorable, pero no demuestra el control completo: falta probar un destino autorizado y posibles evasiones. La página de error expone rutas internas y trazas de Express. | Mantener una lista explícita de destinos permitidos, probar redirecciones autorizadas y variantes de URL; ocultar las trazas internas en las respuestas de error. |

### 3.4 V5.3 — Output Encoding and Injection Prevention (Nivel 1)

| ID ASVS | Requisito | Estado | Evidencia / Hallazgo | Remediación |
|---|---|---|---|---|
| 5.3.1 | La codificación de salida corresponde al intérprete y contexto | **Falla** | El motor de búsqueda inserta el término buscado como HTML sin codificar (sección 1.2) | Usar codificación contextual (HTML entity encoding) según dónde se renderiza el dato |
| 5.3.2 | La codificación preserva el charset/locale del usuario | *No evaluado* | Fuera del alcance práctico de esta auditoría | — |
| 5.3.3 | Escape contextual protege contra XSS reflejado, almacenado y DOM-based | **Falla** | Confirmado en sección 1.2: XSS DOM-based explotado vía parámetro de búsqueda | Sanitizar/escapar antes de insertar en el DOM; evitar bindings tipo `[innerHTML]` sin sanitización |
| 5.3.4 | Las consultas a base de datos usan queries parametrizadas, ORM o equivalente | **Falla** | Confirmado en sección 1.1: la consulta de login se arma por concatenación de strings | Usar prepared statements o el ORM de forma correcta en todas las consultas |
| 5.3.5 | Codificación específica de contexto donde no hay parametrización disponible | *No evaluado* | Fuera del alcance práctico de esta auditoría | — |
| 5.3.6 | Protección contra inyección JSON/JavaScript | **Falla** | TC-01: registro con caracteres especiales en securityAnswer devolvió 201; TC-02: al modificar el JSON para incluir role=admin, la respuesta 201 devolvió role=admin (ID 32). Evidencia de asignación masiva; la inyección JavaScript en búsqueda y reseñas no quedó demostrada. | Aplicar esquema estricto de propiedades permitidas y bloquear role en registro; mantener la evaluación de ejecución JavaScript separada. |
| 5.3.7 | Protección contra inyección LDAP | **No aplica** | Juice Shop no usa LDAP | — |
| 5.3.8 | Protección contra inyección de comandos del SO | *Inconclusive* | Revisión estática del build y dependencias (cross-spawn, foreground-child). No se identificó ejecución directa de comandos a partir de entrada controlada por usuario; tampoco se demostró cobertura completa. | Revisar puntos de ejecución del sistema operativo cuando estén dentro del alcance. |
| 5.3.9 | Protección contra Local/Remote File Inclusion | *Inconclusive* | /ftp/ permitió listar y acceder a acquisitions.md; intentos de traversal devolvieron 403. En /profile/image/url se observó 302 y un archivo 32.jpg cuyo SHA-256 coincide con favicon.ico; evidencia compatible con descarga remota controlada (posible SSRF), no con ejecución/inclusión de archivos. La repetición con 127.0.0.1 no quedó confirmada independientemente. | Separar el hallazgo de posible SSRF; restringir destinos de descarga, redes internas y redirecciones. No concluir LFI/RFI sin prueba específica. |
| 5.3.10 | Protección contra inyección XPath/XML | **No aplica** | Clasificación N/A ratificada: no se identificó procesamiento de XML/XPath en los flujos auditados. | — |

### 3.5 Observación adicional: inconsistencia de validación entre formularios

Se detectó que el campo de contraseña en el formulario de **registro** aplica `minlength="5"` y `maxlength="40"`, mientras que el mismo campo en el formulario de **login** solo aplica `minlength="1"` y no define `maxlength`. Esto sugiere que la validación de longitud es puramente del lado del cliente (HTML) y no está respaldada por una validación consistente en el servidor, lo cual es, en sí mismo, una mala práctica (control de seguridad implementado solo en frontend, fácilmente evadible interceptando la petición).

### 3.6 Resumen y conclusión (actualizado al 30/10/2026)

De los **35 requisitos** de la matriz: **18 Falla**, **9 Cumple**, **2 Inconclusive**, **1 Verificar**, **2 No evaluado** y **3 No aplica / fuera del alcance**. Estos conteos reflejan los estados registrados, no equivalen a cobertura de prueba completa.

El bloque V5.3 queda cerrado administrativamente para esta fase. Se mantiene **5.3.10 = No aplica** y se registran **5.3.8 y 5.3.9 = Inconclusive**; no se harán pruebas adicionales en esta iteración.

**Nota de trazabilidad:** el fallo observado en TC-02 (campo `role` aceptado como `admin`) demuestra directamente asignación masiva, vinculada también a **5.1.2**. Se conserva el estado **Falla** de 5.3.6 acordado en el seguimiento, pero la evidencia disponible no demuestra por sí sola ejecución de JavaScript/JSON injection. Esta limitación debe figurar en la revisión final.

La concentración de fallas en V2 (gestión de contraseñas y recuperación) y V5 (validación de entrada y codificación de salida) confirma, a nivel de estándar, las causas raíz detrás de las vulnerabilidades explotadas en la sección 1: la aplicación no valida ni sanitiza de forma consistente (SQLi, XSS, mass assignment), y la gestión de credenciales carece de controles básicos de robustez (contraseñas por defecto, ausencia de rate limiting, recuperación basada en preguntas de seguridad).

### 3.7 Evidencias de cierre — V5.3

| ID | Caso / fuente | Resultado verificable | Interpretación |
|---|---|---|---|
| 5.3.6 | TC-01, POST `/api/Users/` | 201 Created con caracteres especiales en `securityAnswer` | Aceptación de entrada; no prueba ejecución de código |
| 5.3.6 | TC-02, POST `/api/Users/` | 201 Created y `role: admin` en la respuesta | Asignación masiva confirmada; evidencia principal de 5.1.2 |
| 5.3.6 | Búsqueda y reseña con cadenas JavaScript | La cadena de búsqueda se mostró como texto; la reseña con etiqueta `img` se mostró literalmente; no apareció el marcador esperado en consola | No se confirmó ejecución JavaScript en esos intentos |
| 5.3.8 | Inspección de archivos JS del build | Se revisaron referencias a procesos, `cross-spawn` y `foreground-child`; sin ejecución explotable demostrada | Inconclusive |
| 5.3.9 | `GET /ftp/` y `GET /ftp/acquisitions.md` | Listado accesible y documento confidencial recuperable; intentos de traversal devolvieron 403 | Exposición de archivos, sin demostrar LFI/RFI |
| 5.3.9 | `POST /profile/image/url` | 302 hacia `/profile`; archivo `32.jpg` recuperado del contenedor | Descarga de URL controlada, compatible con SSRF |
| 5.3.9 | Comparación SHA-256 | `32.jpg` y `favicon-original.ico`: `21CBE884EAF2C3B3EF828E127B2C735F280C7CB10CBFE0299C94A910E20A1B3E` | Contenido idéntico; no prueba ejecución |
| 5.3.9 | Repetición con `127.0.0.1` | 302 y mismo hash del archivo recuperado | No confirma una nueva descarga, porque pudo persistir el archivo anterior |
| 5.3.10 | Revisión del alcance | Sin procesamiento XML/XPath identificado | No aplica |

**Hallazgo independiente:** posible SSRF por descarga remota mediante `imageUrl`, que requiere restricciones de destinos y validación del lado servidor. El hallazgo no se equipara automáticamente con una falla de inclusión de archivos.
