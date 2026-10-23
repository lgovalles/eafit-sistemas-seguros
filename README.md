# Actividad de Modelado Integral (End-to-End) — Desarrollo de Sistemas Seguros

Proyecto de recuperación individual del curso **Desarrollo de Sistemas Seguros (0453_2666)**, EAFIT.

Consiste en un análisis de seguridad end-to-end sobre **OWASP Juice Shop** como aplicación vulnerable de referencia, cubriendo cuatro frentes: explotación de vulnerabilidades, modelado de amenazas, evaluación contra OWASP ASVS, y automatización de análisis estático en un pipeline CI/CD.

**Aplicación auditada:** [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — fork con el pipeline configurado: [lgovalles/juice-shop](https://github.com/lgovalles/juice-shop)

## Estructura del repositorio

## Estructura del repositorio

| Carpeta | Contenido | Valor |
|---|---|---|
| [`01-vulnerabilidades/`](01-vulnerabilidades/vulnerabilidades.md) | Explotación documentada de 5 vulnerabilidades críticas del OWASP Top 10 2025 (capturas, peticiones HTTP interceptadas, mitigación en código) | 25% |
| [`02-modelado-amenazas/`](02-modelado-amenazas/02-modelado-amenazas.md) | DFD + STRIDE. Modelo: [Threat Dragon JSON](02-modelado-amenazas/ThreatDragonModels/Modelo%20de%20Amenazas%20-%20Login%20y%20Carrito%20-%20Juice%20Shop/Modelo%20de%20Amenazas%20-%20Login%20y%20Carrito%20-%20Juice%20Shop.json) | 25% |
| `03-asvs/` | Matriz de cumplimiento frente a dos capítulos de OWASP ASVS, Nivel 1 | 25% |
| `04-cicd-sast/` | Documentación del pipeline de GitHub Actions con análisis SAST (código en el fork de Juice Shop) | 25% |

## Vulnerabilidades analizadas

1. Inyección SQL
2. XSS almacenado
3. IDOR (Insecure Direct Object Reference)
4. Control de acceso roto
5. Autenticación débil

## Autor

Luis Gabriel Ovalle — Curso Desarrollo de Sistemas Seguros, EAFIT
