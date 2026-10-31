## 4. Pipeline CI/CD con SAST

Pipeline y reglas implementados sobre el fork donde se audita la aplicación: [lgovalles/juice-shop](https://github.com/lgovalles/juice-shop).

- Workflow: [`.github/workflows/sast.yml`](https://github.com/lgovalles/juice-shop/blob/main/.github/workflows/sast.yml)
- Reglas propias: [`.semgrep/custom-rules.yml`](https://github.com/lgovalles/juice-shop/blob/main/.semgrep/custom-rules.yml)

### 4.1 Herramienta y diseño del pipeline

Se eligió **Semgrep** (open source, sin dependencia de un servicio en la nube ni licencia) como herramienta SAST, integrada en un workflow de **GitHub Actions** que se ejecuta en cada `push`/`pull request` a `main`/`develop`. El pipeline combina dos fuentes de reglas:

1. **Rulesets comunitarios** (`p/owasp-top-ten`, `p/javascript`, `p/typescript`, `p/security-audit`) — cobertura general para JS/TS y Express.
2. **Reglas propias del proyecto** (`.semgrep/custom-rules.yml`) — escritas específicamente para detectar los patrones de las vulnerabilidades ya explotadas en la sección 1, calibradas contra el código real de Juice Shop.

El job falla (`--error`, exit code ≠ 0) si se detecta algún hallazgo de severidad `ERROR`, bloqueando el merge. Los resultados se publican en formato SARIF como artefacto y se suben a la pestaña *Security* del repositorio vía `github/codeql-action/upload-sarif`. Se excluye `data/static/codefixes/` del escaneo, siguiendo la misma convención ya usada por el workflow `codeql-analysis.yml` del proyecto (esa carpeta contiene snippets educativos intencionalmente vulnerables que no son código en producción).

```yaml
name: SAST (Semgrep)

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  semgrep:
    name: Static Application Security Testing
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@v4
      - name: Run Semgrep (community rulesets + reglas propias del proyecto)
        run: |
          semgrep scan \
            --config p/owasp-top-ten \
            --config p/javascript \
            --config p/typescript \
            --config p/security-audit \
            --config .semgrep/custom-rules.yml \
            --exclude "frontend/node_modules" --exclude "node_modules" \
            --exclude "test" --exclude "cypress" --exclude "data/static/codefixes" \
            --severity ERROR --error \
            --sarif --output semgrep-results.sarif
      - name: Subir resultados SARIF (pestaña Security)
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep-results.sarif
```

### 4.2 Ejecución contra el código fuente de Juice Shop

Se ejecutó el pipeline contra el código fuente de la aplicación (la misma auditada en las secciones 1–3) para obtener evidencia real, antes de incorporarlo al repositorio.

**Resultado del ruleset comunitario:** 61 hallazgos en 1193 archivos analizados (24 reglas distintas disparadas), incluyendo secretos hardcodeados (`hardcoded-jwt-secret`, `hardcoded-hmac-key` en `lib/insecurity.ts`), uso de `eval` (`routes/captcha.ts`, `routes/userProfile.ts`) y listados de directorio expuestos (`server.ts`). Sin embargo, **no detectó** la inyección SQL real explotada en la sección 1.1 — las reglas genéricas de taint-tracking solo dispararon sobre los archivos educativos de `data/static/codefixes/` (snippets de ejemplo incluidos en el propio repo para enseñar el *fix*), no sobre las rutas en producción (`routes/login.ts`, `routes/search.ts`).

**Resultado de las reglas propias** (diseñadas a partir del hallazgo de la sección 1.1): detectaron con precisión los dos puntos reales de inyección SQL por concatenación en template literals:

| Regla | Archivo : línea | Relación con la sección 1 |
|---|---|---|
| `raw-sql-template-literal-concat` | `routes/login.ts:34` | **Es la línea exacta explotada en 1.1** (`' OR 1=1--`) — `sequelize.query(\`...${req.body.email}...\`)` |
| `raw-sql-template-literal-concat` | `routes/search.ts:23` | SQLi adicional (por unión) en el buscador de productos, no reportada en la sección 1 — hallazgo nuevo del pipeline |
| `innerhtml-assignment-unsanitized` | `frontend/src/hacking-instructor/index.ts:126` | Patrón de asignación directa a `innerHTML`, de la misma familia que el XSS DOM-based de 1.2 |
| `innerhtml-assignment-unsanitized` | `frontend/src/hacking-instructor/index.ts:142` | Ídem |

El ruleset comunitario también marcó `routes/redirect.ts:18` (`express-open-redirect`) como posible redirección abierta. Al revisar el código, esa ruta sí valida el destino contra una lista blanca (`security.isRedirectAllowed`) antes de redirigir — **consistente con el resultado `406` observado dinámicamente en la sección 3 (ítem 5.1.5)**. Es un falso positivo del análisis estático (no entiende el guard condicional), que confirma por qué SAST y pruebas dinámicas (DAST) son complementarios y no sustitutos entre sí.

### 4.3 Conclusión

El pipeline, con las reglas genéricas por sí solas, **no habría bloqueado** el commit que introdujo la inyección SQL explotada en la sección 1.1: las reglas comunitarias no generalizan al patrón específico de este proyecto (`sequelize.query` + template literal). Al añadir una regla propia calibrada contra el hallazgo real, el pipeline sí detecta y **bloquea el merge** (severidad `ERROR`) tanto del login vulnerable como de una segunda inyección SQL no identificada previamente en el buscador de productos. Esto demuestra el valor de combinar rulesets genéricos con reglas específicas del dominio/aplicación derivadas de los propios hallazgos de pentesting, y refuerza la recomendación de la sección 1.1 (consultas parametrizadas) con un control preventivo automatizado en el pipeline de CI/CD, antes de que el código vulnerable llegue a producción.

![ Pieline CI CD](img/workflows1.png) 

![ GitHug Actions](img/workflows.png) 

![ GitHug Actions](img/workflows3.png) 