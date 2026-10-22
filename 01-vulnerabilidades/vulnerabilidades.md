# Informe Técnico — Modelado Integral de Seguridad (OWASP Juice Shop)

Proyecto de recuperación individual — curso Desarrollo de Sistemas Seguros (0453_2666), EAFIT.

**Autor:** Luis Gabriel Ovalle
**Aplicación auditada:** OWASP Juice Shop

## 1. Análisis de Vulnerabilidades

Se desplegó localmente OWASP Juice Shop (`docker run -p 3000:3000 bkimminich/juice-shop`) y se interceptó el tráfico con OWASP ZAP para documentar la explotación de 5 vulnerabilidades críticas del OWASP Top 10.

### 1.1 Inyección SQL (Login Bypass)

**Descripción:** el formulario de login construye la consulta SQL concatenando directamente los campos de entrada, sin parametrizar.

**Explotación:**
1. En el campo email: `' OR 1=1--`
2. Contraseña: cualquier valor.
3. Petición interceptada: `POST /rest/user/login` — respuesta `200 OK` con token JWT y `"umail":"admin@juice-sh.op"`.

**Impacto:** acceso completo a la cuenta administradora sin conocer credenciales.

**Mitigación:**
```javascript
// Vulnerable
db.query(`SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`)

// Mitigado
db.query('SELECT * FROM users WHERE email = ? AND password = ?', [email, password])
```
![Petición POST con SQL injection](images/sql-injection-login-request.png) 

![Petición POST con SQL injection](images/sql-injection-login-response.png) 

### 1.2 Cross-Site Scripting (DOM-based)

**Descripción:** el componente de resultados de búsqueda inserta el término buscado en el DOM sin sanitizar.

**Explotación:** navegar a `http://localhost:3000/#/search?q=<iframe src="javascript:alert('xss')">` — el script se ejecuta al cargar los resultados (confirmado por el reto resuelto "DOM XSS").

**Impacto:** ejecución de JavaScript arbitrario en el navegador de la víctima; robo de sesión, defacement, phishing.

**Mitigación:** evitar bindings tipo `[innerHTML]` con datos no confiables; usar interpolación de texto plano (`{{ }}`) o sanitizar con DOMPurify antes de insertar HTML.

![DOM-based](images/xss-dom-success.png) 

### 1.3 IDOR (Insecure Direct Object Reference)

**Descripción:** el endpoint del carrito no valida que el recurso solicitado pertenezca al usuario autenticado.

**Explotación:** `GET /rest/basket/2` con el token propio devuelve `200 OK` con el carrito de otro usuario (`"UserId":2`, productos y totales ajenos).

**Impacto:** exposición de datos personales y de compra de otros usuarios.

**Mitigación:** validar en servidor que `basket.UserId` coincide con el usuario del token antes de responder.

![Insecure Direct Object Reference](images/idor-basket-response-1.png) 

![Insecure Direct Object Reference](images/idor-basket-response-2.png) 

### 1.4 Control de Acceso Roto

**Descripción:** el endpoint `DELETE /api/BasketItems/<id>` no valida la propiedad del ítem antes de ejecutar el borrado.

**Explotación:** con el token propio, `DELETE /api/BasketItems/4` y `DELETE /api/BasketItems/9` (pertenecientes al carrito de otro usuario) devuelven `200 OK`. Un segundo intento sobre el mismo id devuelve `404 Not Found`, confirmando el borrado. La respuesta posterior de `GET /rest/basket/4` muestra menos productos que antes.

**Impacto:** cualquier usuario autenticado puede modificar o destruir datos de otros usuarios (no solo leerlos).

**Mitigación:** verificar en servidor que `basketItem.BasketId` pertenece al `Basket` del usuario autenticado antes de autorizar el `DELETE`.

![ Control de Acceso Roto](images/delete-1.png) 

![ Control de Acceso Roto](images/delete-2.png) 

### 1.5 Autenticación Débil

**Descripción:** la cuenta administradora conserva su contraseña por defecto, y la aplicación no limita los intentos de login.

**Explotación:** login con `admin@juice-sh.op` / `admin123` — acceso inmediato (reto "Password Strength" resuelto). Además, se confirmó la ausencia de bloqueo tras múltiples intentos fallidos consecutivos.

**Impacto:** cuenta administradora comprometida por fuerza bruta o conocimiento de credenciales por defecto.

**Mitigación:** forzar cambio de contraseña en primer uso, política de complejidad mínima, bloqueo temporal de cuenta y rate limiting tras N intentos fallidos.

![Autenticación Débil](images/weak-auth-login-success.png) 

## 2. Modelado de Amenazas (DFD + STRIDE)

_Pendiente — en elaboración._

## 3. OWASP ASVS — Matriz de Cumplimiento

_Pendiente — entrega 30 de octubre._

## 4. Pipeline CI/CD con SAST

_Pendiente — entrega 30 de octubre._