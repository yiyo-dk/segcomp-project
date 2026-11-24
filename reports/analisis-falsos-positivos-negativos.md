# Análisis de Falsos Positivos y Falsos Negativos (`sast-scan`)

Este documento recopila los **falsos positivos** y **falsos negativos (no detectados)** observados al ejecutar `sast-scan` sobre los archivos de prueba en `tests/samples/`, junto con la explicación técnica basada en el funcionamiento actual de `src/rules/sql-injection.rule.ts` y `src/rules/hardcoded-secrets.rule.ts`.

---

## 1. Falsos Positivos Detectados (9 casos verificados)

Archivos de prueba incluidos en `tests/samples/`:
- `tests/samples/21-fp-sql-injection.ts`
- `tests/samples/22-fp-hardcoded-secrets.ts`

### 1.1 Regla `sql-injection` (`CWE-89`) — 4 falsos positivos

1. **Texto en inglés que coincide con `SQL_KEYWORD_PATTERN` en función arbitraria**
   - **Archivo / Línea:** `tests/samples/21-fp-sql-injection.ts:5`
   - **Código:** `i18n.translate(\`Select a file from ${folder} to continue\`)`
   - **Motivo:** En `CallExpression`, si la llamada es dinámica y ni el objeto (`i18n`) está en `NON_SQL_LOG_OBJECTS` ni el método (`translate`) está en `NON_SQL_UTILITY_METHODS`, la regla evalúa `SQL_KEYWORD_PATTERN` (`/\b(?:SELECT\b[\s\S]*?\bFROM|...)\b/i`) sobre el texto estático. La frase `"Select a file from ..."` cumple ese patrón aunque no sea SQL.

2. **Cliente HTTP llamado `client` usando `.get()` con parámetros de URL `from` y `limit`**
   - **Archivo / Línea:** `tests/samples/21-fp-sql-injection.ts:14`
   - **Código:** `client.get(\`https://api.example.com/events?from=${startDate}&limit=${limit}\`)`
   - **Motivo:** El método `get` pertenece a `QUERY_METHODS` (pensado para drivers como `sqlite.get`), y el nombre del receptor `client` coincide con `DB_OBJECT_PATTERN`. Como la URL contiene `from=` y `limit=`, coincide con `PARTIAL_SQL_PATTERN` (`FROM`, `LIMIT`), disparando la alerta en una petición HTTP común.

3. **Buscador no-SQL con método `.query()` y palabra parcial `where`**
   - **Archivo / Línea:** `tests/samples/21-fp-sql-injection.ts:19`
   - **Código:** `searchIndex.query(\`articles where tag:${topic}\`)`
   - **Motivo:** `query` forma parte de `HIGH_CONFIDENCE_QUERY_METHODS`. Para estos métodos, basta con que `PARTIAL_SQL_PATTERN` coincida con alguna palabra suelta (en este caso `where`) para reportar un hallazgo `CRITICAL`, sin verificar si la cadena tiene estructura real de consulta SQL.

4. **Variable `let` reasignada únicamente con literales estáticos en `$queryRawUnsafe`**
   - **Archivo / Línea:** `tests/samples/21-fp-sql-injection.ts:31`
   - **Código:**
     ```ts
     let sql = 'SELECT id, name FROM active_users';
     if (useArchive) {
       sql = 'SELECT id, name FROM archived_users';
     }
     return prisma.$queryRawUnsafe(sql);
     ```
   - **Motivo:** `isStaticExpression()` exige `binding.constant === true` para considerar segura una variable `Identifier`. Al existir una reasignación (`let` + `if`), el binding deja de ser constante aunque todas las ramas asignen literales estáticos sin entrada de usuario.

---

### 1.2 Regla `hardcoded-secrets` (`CWE-798`) — 5 falsos positivos (+1 caso menor)

1. **Textos de interfaz de usuario con sufijos no excluidos (`Text`, `Description`)**
   - **Archivo / Línea:** `tests/samples/22-fp-hardcoded-secrets.ts:5-6`
   - **Código:**
     ```ts
     passwordResetText: 'We sent a recovery link to your email address.',
     apiKeyDescription: 'Generate a new key from your developer dashboard.',
     ```
   - **Motivo:** `SENSITIVE_NAME_PATTERN` detecta `password` y `apiKey`, pero `NON_SECRET_SUFFIX_PATTERN` solo excluye sufijos como `label`, `placeholder`, `message`, `hint`, etc., sin incluir `text` ni `description`. Como son cadenas largas (`>= 6`), se reportan como secretos `HIGH`.

2. **Clave de referencia/configuración asignada a propiedad `jwtSecret`**
   - **Archivo / Línea:** `tests/samples/22-fp-hardcoded-secrets.ts:11`
   - **Código:** `jwtSecret: 'auth.config.jwt_secret_reference'`
   - **Motivo:** El filtro `isLikelyPlaceholderOrSafeValue()` excluye constantes `UPPER_SNAKE_CASE` de baja entropía, rutas de archivos y URLs, pero no excluye identificadores de configuración con puntos (`dot.notation`) ni cadenas descriptivas en `snake_case` minúscula.

3. **Token de ejemplo/relleno que coincide con firma de GitHub**
   - **Archivo / Línea:** `tests/samples/22-fp-hardcoded-secrets.ts:16`
   - **Código:** `export const docsExampleToken = 'ghp_000000000000000000000000000000000000';`
   - **Motivo:** En `checkNamedAssignment()` y `checkStandaloneLiteral()`, `matchSecretSignature()` se ejecuta **antes** que `isLikelyPlaceholderOrSafeValue()` y sin validar entropía mínima. Cualquier cadena con el prefijo `ghp_` seguido de 36 ceros se reporta como `CRITICAL`.

4. **URI local de desarrollo con credenciales de ejemplo**
   - **Archivo / Línea:** `tests/samples/22-fp-hardcoded-secrets.ts:19`
   - **Código:** `export const localDevDb = 'postgres://postgres:postgres@localhost:5432/dev_db';`
   - **Motivo:** La expresión regular de `Database Connection String with Credentials` coincide con cualquier URI que contenga `usuario:contraseña@host`, incluso cuando apunta a `localhost` con credenciales genéricas de desarrollo local.

5. **Caso menor observado en `tests/samples/08-secrets-common-vars-and-objects.js:3`**
   - **Código:** `let jwtSecret = "initial-placeholder";`
   - **Motivo:** `PLACEHOLDER_PATTERN` contempla valores exactos como `placeholder`, `changeme` o `dummy`, pero no variantes compuestas como `"initial-placeholder"`.

---

## 2. Falsos Negativos / No Detectados (2 casos verificados)

Observados al escanear `tests/samples/` (reporte en `reports/samples-findings.txt`):

### 2.1 Regla `hardcoded-secrets` (`CWE-798`)

1. **Secreto hardcodeado como *fallback* en expresión lógica (`??` o `||`)**
   - **Archivo / Línea:** `tests/samples/13-ts-class-properties-secrets.ts:8`
   - **Código:**
     ```ts
     this.clientSecret = overrideSecret ?? "fallback_client_secret_value_123456";
     ```
   - **Motivo:** El método `checkNamedAssignment()` llama a `extractStaticString(valueNode)`, que únicamente extrae valores si el nodo derecho de la asignación es directamente un `StringLiteral` o un `TemplateLiteral` sin interpolaciones. Al estar envuelto en una `LogicalExpression` (`overrideSecret ?? "..."`), `extractStaticString` devuelve `null` y el secreto no se reporta (salvo que coincida con una firma en `checkStandaloneLiteral`).

### 2.2 Regla `sql-injection` (`CWE-89`)

2. **SQL concatenado dentro de un arreglo (`ArrayExpression`) pasado a `batch()`**
   - **Archivo / Línea:** `tests/samples/17-ts-async-service-sqli.ts:19`
   - **Código:**
     ```ts
     return driver.batch(["DELETE FROM " + table + " WHERE archived = 1"]);
     ```
   - **Motivo:** Aunque `batch` está registrado en `QUERY_METHODS`, el visitor `CallExpression` únicamente inspecciona el primer argumento (`path.node.arguments[0]`) mediante `extractQueryNodeFromArg()`, que solo desenvuelve expresiones o propiedades `{ sql | text }` de un `ObjectExpression`. Al recibir un `ArrayExpression` (`[...]`), `isStaticExpression` y `extractStaticText` no recorren los elementos del arreglo, por lo que la concatenación maliciosa pasa desapercibida.
