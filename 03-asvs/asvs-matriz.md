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
| 5.1.2 | Protección contra asignación masiva de parámetros (mass assignment) | *Verificar* | Revisar si `PUT`/`POST` a endpoints como `/api/Users` permiten modificar campos no expuestos en el formulario (ej. `role`) | — |
| 5.1.3 | Toda entrada se valida con listas positivas (allow lists) | **Falla** | Confirmado directamente por la explotación de SQL Injection (sección 1.1): el campo email no valida formato ni contenido antes de usarse en la consulta | Validar formato de entrada (ej. regex de email) antes de cualquier procesamiento |
| 5.1.4 | Los datos estructurados están fuertemente tipados y validados contra un esquema | *Verificar* | Revisar si la API valida los bodies JSON contra un esquema (ej. JSON Schema) | — |
| 5.1.5 | Las redirecciones solo permiten destinos en lista blanca | *Verificar* | Juice Shop tiene un reto conocido de "unvalidated redirect" en `/redirect?to=`; probar con una URL externa | — |

### 3.4 V5.3 — Output Encoding and Injection Prevention (Nivel 1)

| ID ASVS | Requisito | Estado | Evidencia / Hallazgo | Remediación |
|---|---|---|---|---|
| 5.3.1 | La codificación de salida corresponde al intérprete y contexto | **Falla** | El motor de búsqueda inserta el término buscado como HTML sin codificar (sección 1.2) | Usar codificación contextual (HTML entity encoding) según dónde se renderiza el dato |
| 5.3.2 | La codificación preserva el charset/locale del usuario | *No evaluado* | Fuera del alcance práctico de esta auditoría | — |
| 5.3.3 | Escape contextual protege contra XSS reflejado, almacenado y DOM-based | **Falla** | Confirmado en sección 1.2: XSS DOM-based explotado vía parámetro de búsqueda | Sanitizar/escapar antes de insertar en el DOM; evitar bindings tipo `[innerHTML]` sin sanitización |
| 5.3.4 | Las consultas a base de datos usan queries parametrizadas, ORM o equivalente | **Falla** | Confirmado en sección 1.1: la consulta de login se arma por concatenación de strings | Usar prepared statements o el ORM de forma correcta en todas las consultas |
| 5.3.5 | Codificación específica de contexto donde no hay parametrización disponible | *No evaluado* | Fuera del alcance práctico de esta auditoría | — |
| 5.3.6 | Protección contra inyección JSON/JavaScript | *Verificar* | No se probó explícitamente | — |
| 5.3.7 | Protección contra inyección LDAP | **No aplica** | Juice Shop no usa LDAP | — |
| 5.3.8 | Protección contra inyección de comandos del SO | *Verificar* | No se probó explícitamente en este alcance | — |
| 5.3.9 | Protección contra Local/Remote File Inclusion | *Verificar* | Juice Shop tiene retos conocidos de path traversal en la subida/descarga de archivos; no se probó en este alcance | — |
| 5.3.10 | Protección contra inyección XPath/XML | **No aplica** | No se identificó procesamiento de XML/XPath en los flujos auditados | — |

### 3.5 Observación adicional: inconsistencia de validación entre formularios

Se detectó que el campo de contraseña en el formulario de **registro** aplica `minlength="5"` y `maxlength="40"`, mientras que el mismo campo en el formulario de **login** solo aplica `minlength="1"` y no define `maxlength`. Esto sugiere que la validación de longitud es puramente del lado del cliente (HTML) y no está respaldada por una validación consistente en el servidor, lo cual es, en sí mismo, una mala práctica (control de seguridad implementado solo en frontend, fácilmente evadible interceptando la petición).

### 3.6 Resumen y conclusión

De los 27 requisitos Nivel 1 evaluados:
- **Falla:** 12 (44%) — mayoritariamente concentrados en gestión de contraseñas y validación/codificación de entrada, coherente con las vulnerabilidades críticas confirmadas en la sección 1.
- **Cumple:** 8 (30%)
- **Verificar / No evaluado / No aplica:** 7 (26%) — requieren una prueba puntual adicional o están fuera del alcance de login/carrito definido para este trabajo.

La concentración de fallas en V2 (gestión de contraseñas y recuperación) y V5 (validación de entrada y codificación de salida) confirma, a nivel de estándar, las causas raíz detrás de las 5 vulnerabilidades explotadas en la sección 1: la aplicación no valida ni sanitiza de forma consistente, y la gestión de credenciales carece de controles básicos de robustez.
