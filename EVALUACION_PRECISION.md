# Evaluación de Precisión y Análisis de Resultados (`sast-scan`)

Este documento consolida los resultados obtenidos al ejecutar `sast-scan` sobre dos conjuntos de prueba:
1. **Suite controlada (`tests/samples/`)**: 22 archivos JavaScript y TypeScript con casos vulnerables, casos seguros y casos diseñados para probar falsos positivos ([samples-report.sarif](file:///C:/Users/rodri/Desktop/u/proyecto%20segcomp/samples-report.sarif)).
2. **Proyecto real (`OWASP Juice Shop`)**: repositorio completo con 673 archivos soportados, de los cuales 646 fueron analizados y 27 fragmentos sintácticamente incompletos en `data/static/codefixes/` fueron omitidos con advertencia ([juice-shop-report.sarif](file:///C:/Users/rodri/Desktop/u/proyecto%20segcomp/juice-shop-report.sarif)).

---

## 1. Tabla de Métricas por Regla y Conjunto de Prueba

> **Fórmula de Precisión:** $\text{Precisión} = \frac{TP}{TP + FP} \times 100\%$  
> *(donde $TP$ = Verdaderos Positivos, $FP$ = Falsos Positivos, $FN$ = Falsos Negativos).*

### A. Suite Controlada (`tests/samples/`)

| Regla | Casos Evaluados | Verdaderos Positivos (TP) | Falsos Positivos (FP) | Falsos Negativos (FN) | Verdaderos Negativos (TN) | Precisión |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`sql-injection` (`CWE-89`)** | 42 | 21 | 4 | 1 | 16 | **84.00%** |
| **`hardcoded-secrets` (`CWE-798`)** | 41 | 23 | 5 | 1 | 12 | **82.14%** |
| **Total (`tests/samples/`)** | **83** | **44** | **9** | **2** | **28** | **83.02%** |

### B. Proyecto Real (`OWASP Juice Shop`)

| Regla | Archivos Analizados | Hallazgos Reportados | Severidad (`CRITICAL` / `HIGH` / `LOW`) | Verdaderos Positivos (TP) | Falsos Positivos (FP) | Falsos Negativos (FN) | Precisión |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`sql-injection` (`CWE-89`)** | 646 | 6 | 6 / 0 / 0 | 6 | 0 | **0** | **100.00%** |
| **`hardcoded-secrets` (`CWE-798`)** | 646 | 273 | 1 / 74 / 198 | 1 | 272 *(198 atenuados a `LOW`)* | **≥ 1** *(confirmado)* | **0.37%** |
| **Total (`Juice Shop`)** | **646** | **279** | **7 / 74 / 198** | **7** | **272** | **≥ 1** | **2.51%** |

> **Impacto de la atenuación en directorio `test/` (`isInTestDirectory`):**  
> - De los 272 falsos positivos operacionales de `hardcoded-secrets`, **198** ubicados dentro de la carpeta `test/` fueron atenuados automáticamente de `HIGH` a **`LOW`**, reduciendo en un **72.8%** las alertas bloqueantes (`HIGH`) para `--fail-on HIGH` (pasaron de 272 a **74**).  
> - Los **74** hallazgos restantes en `HIGH` corresponden a **73** archivos `*.spec.ts` dentro de `frontend/src/app/` (fuera de una carpeta llamada `test/`) y **1** contraseña de demostración (`testingPassword = 'IamUsedForTesting'`) en `frontend/src/app/login/login.component.ts:73`.  
> - En `tests/samples/`, al haberse ajustado la detección al directorio `test` (singular), los 28 hallazgos de `hardcoded-secrets` conservan sus severidades originales (`19 HIGH` y `9 CRITICAL`).

---

## 2. Desglose de Falsos Positivos y Falsos Negativos Detectados

### En `tests/samples/`

1. **Falsos Positivos en `sql-injection` (`4 FP` en `21-fp-sql-injection.ts`)**:
   - `i18n.translate("Select a file from ${folder} ...")`: texto en inglés que coincide con el patrón `SELECT ... FROM`.
   - `client.get("https://api.example.com/events?from=...&limit=...")`: objeto llamado `client` (coincide con patrón de BD) llamando a `.get()` con parámetros HTTP `from` y `limit`.
   - `searchIndex.query("articles where tag:${topic}")`: método `.query()` ajeno a SQL que contiene la palabra `where`.
   - `prisma.$queryRawUnsafe(sql)`: variable `sql` reasignada únicamente con literales estáticos en ramas `if`.

2. **Falso Negativo en `sql-injection` (`1 FN`)**:
   - `17-ts-async-service-sqli.ts:19`: `driver.batch(["DELETE FROM " + table + " WHERE archived = 1"])` no fue detectado porque el primer argumento de `.batch()` es un arreglo (`ArrayExpression`) y la regla inspecciona expresiones de cadena/objeto directas.

3. **Falsos Positivos en `hardcoded-secrets` (`5 FP` en `22-fp-hardcoded-secrets.ts`)**:
   - `passwordResetText` y `apiKeyDescription`: textos de interfaz de usuario cuyos sufijos (`Text`, `Description`) no están en la lista de exclusión.
   - `jwtSecret: 'auth.config.jwt_secret_reference'`: clave de configuración/i18n asignada a un nombre sensible.
   - `docsExampleToken: 'ghp_000000000000000000000000000000000000'`: token de ejemplo de baja entropía que dispara la firma de GitHub antes de los filtros de entropía.
   - `localDevDb: 'postgres://postgres:postgres@localhost:5432/dev_db'`: URI local de desarrollo con credenciales por defecto.

4. **Falso Negativo en `hardcoded-secrets` (`1 FN`)**:
   - `13-ts-class-properties-secrets.ts:8`: `this.clientSecret = overrideSecret ?? "fallback_client_secret_value_123456"` no fue detectado porque la asignación utiliza un operador `??` (*nullish coalescing*) y la extracción estática solo evalúa literales directos.

### En `OWASP Juice Shop`

- **`sql-injection`**: **6 TP / 0 FP / 0 FN**. Al verificar todas las llamadas a `sequelize.query()` y los marcadores `vuln-code-snippet` del backend, se confirmó que detectó el 100% de las inyecciones SQL reales (`routes/login.ts:34` y `routes/search.ts:23`), además de 4 variantes vulnerables en `data/static/codefixes/`, sin marcar las consultas estáticas (`routes/search.ts:47`) ni las versiones corregidas con consultas parametrizadas (`_2_correct.ts`).
- **`hardcoded-secrets`**: **1 TP / 272 FP / ≥ 1 FN**. Detectó correctamente la llave privada RSA en `lib/insecurity.ts:21` (`CRITICAL`). Con la atenuación aplicada al directorio `test/`, **198** hallazgos sobre datos ficticios en pruebas de backend/API pasaron a severidad `LOW` (no bloqueante para `--fail-on HIGH`), mientras que **73** hallazgos en archivos `*.spec.ts` del frontend (ubicados en `frontend/src/app/`, fuera de una carpeta `test/`) y **1** contraseña de demostración en `login.component.ts:73` permanecen en `HIGH`.
  - **Falso Negativo confirmado (`lib/insecurity.ts:42`)**: La clave HMAC hardcodeada en `crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj')` no fue detectada porque se pasa directamente como argumento posicional sin estar asignada a una variable con nombre sensible ni coincidir con un prefijo de firma conocida (`ghp_`, `sk_live_`, `AKIA`, etc.). *(Se indica `≥ 1` porque en un proyecto de 646 archivos sin un catálogo completo de secretos ocultos, la existencia de otros secretos pasados como argumentos anónimos requiere auditoría manual).*
