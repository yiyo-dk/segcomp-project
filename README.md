# `sast-scan` (`segcomp-project`)

Herramienta CLI de **Análisis Estático de Seguridad de Aplicaciones (SAST)** para proyectos **JavaScript y TypeScript** (`.js`, `.jsx`, `.ts`, `.tsx`), construida en Node.js con TypeScript y `@babel/parser` / `@babel/traverse`.

Analiza cada archivo en **una sola pasada del AST (Árbol de Sintaxis Abstracta)** fusionando todos los *visitors* de las reglas activas, y genera reportes legibles en consola o en formato estándar **SARIF v2.1.0**.

---

## Requisitos e Instalación

- **Node.js**: `>= 22.18.0` (o `>= 24.11.0`)
- **Gestor de paquetes**: `pnpm` (`^11.22.0`)

```bash
# 1. Instalar dependencias
pnpm install

# 2. Compilar TypeScript a ./dist
pnpm run build
```

Opcionalmente, para usar el comando `sast-scan` de forma global desde la terminal tras compilar:

```bash
pnpm link --global
```

---

## Scripts disponibles (`package.json`)

| Script | Comando real | Descripción |
| --- | --- | --- |
| `pnpm dev` | `tsx src/index.ts` | Ejecuta el CLI directamente desde TypeScript sin compilar. |
| `pnpm build` | `tsc` | Compila `src/` hacia `dist/` generando `.js`, `.d.ts` y sourcemaps. |
| `pnpm start` | `node dist/index.js` | Ejecuta la versión compilada en `dist/`. |
| `pnpm test` | `vitest run` | Ejecuta toda la suite de pruebas unitarias con Vitest. |

> **Nota al pasar argumentos con `pnpm`:** añade `--` antes de los flags para que `pnpm` los reenvíe al CLI (por ejemplo, `pnpm dev -- ./src --format sarif`).

---

## Uso del CLI y Flags

### Sintaxis

```bash
sast-scan <target> [options]
```

Formas equivalentes de ejecución sin enlace global:

```bash
# Modo desarrollo (con tsx)
pnpm dev -- <target> [options]

# Modo compilado (requiere pnpm run build previo)
pnpm start -- <target> [options]
# o directamente con Node:
node dist/index.js <target> [options]
```

### Argumento `<target>`

Acepta cualquiera de los siguientes formatos:
- **Directorio**: ej. `./src` o `.` (busca recursivamente `**/*.{js,jsx,ts,tsx}`).
- **Archivo individual**: ej. `src/api/users.ts`.
- **Patrón glob**: ej. `"src/**/*.ts"`.

El motor ignora automáticamente los directorios:
- `node_modules/`
- `dist/`
- `.git/`
- `coverage/`

### Opciones y Flags

| Flag | Alias | Valores permitidos | Por defecto | Descripción |
| --- | --- | --- | --- | --- |
| `--format <format>` | `-f` | `text` \| `sarif` | `text` | Formato de salida del reporte. No distingue mayúsculas/minúsculas. |
| `--out <file>` | `-o` | Ruta de archivo | *stdout* | Escribe el reporte en un archivo (crea directorios padre si no existen). En modo `text`, desactiva códigos de color ANSI automáticamente al guardar a archivo. |
| `--fail-on <severity>` | — | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` | `HIGH` | Umbral mínimo de severidad que hace que el proceso termine con `exit code 1`. |
| `--version` | `-V` | — | `1.0.0` | Muestra la versión actual del CLI. |
| `--help` | `-h` | — | — | Muestra la ayuda de comandos y opciones. |

---

## Ejemplos de ejecución

### 1. Escaneo rápido en consola (desarrollo)

```bash
pnpm dev -- ./src
```

### 2. Escaneo usando el compilado de producción

```bash
pnpm run build
node dist/index.js ./src
```

### 3. Fallar el proceso desde severidad `MEDIUM` en adelante

```bash
node dist/index.js ./src --fail-on MEDIUM
```

### 4. Exportar reporte en formato SARIF v2.1.0 (ideal para GitHub Code Scanning / CI)

```bash
node dist/index.js ./src --format sarif --out reports/results.sarif
```

O imprimir el JSON SARIF directamente en consola:

```bash
node dist/index.js ./src --format sarif
```

### 5. Guardar reporte en texto plano sin códigos ANSI

```bash
node dist/index.js ./src --format text --out reports/sast-report.txt
```

### 6. Ver ayuda y versión

```bash
node dist/index.js --help
node dist/index.js --version
```

---

## Códigos de salida (Exit Codes) y CI/CD

El CLI asigna un peso numérico a cada nivel de severidad:

- `LOW` = `1`
- `MEDIUM` = `2`
- `HIGH` = `3`
- `CRITICAL` = `4`

| Código de salida | Significado |
| --- | --- |
| `0` | Escaneo completado sin hallazgos que alcancen o superen el umbral de `--fail-on`. |
| `1` | Se detectó al menos un hallazgo con severidad `>= --fail-on`, o ocurrió un error de argumentos/ejecución. |

---

## Reglas de seguridad incluidas

### 1. `sql-injection` (`CWE-89`, Severidad: `CRITICAL`)
Archivo: `src/rules/sql-injection.rule.ts`

- **Qué detecta:**
  - Concatenación con `+`, `.concat()` o *template literals* interpolados (`${...}`) dentro de métodos de consulta (`query`, `execute`, `raw`, `prepare`, `exec`, `all`, `get`, `run`, `batch`, `$queryRawUnsafe`, `$executeRawUnsafe`).
  - Objetos de opciones de consulta (`{ text: ... }` / `{ sql: ... }`, ej. `pg`).
  - Variables locales construidas dinámicamente y rastreadas en el `Scope` (`const sql = "SELECT ... " + id`, `query += ...`).
  - *Tagged templates* inseguros (``knex.raw`...` ``) y fragmentos sin escapar dentro de templates parametrizados (`Prisma.raw("id = " + id)`).
  - Wrappers personalizados que reciban SQL construido dinámicamente.
- **Falsos positivos evitados:**
  - Consultas parametrizadas (`$1`, `?`), literales/constantes estáticas, templates parametrizados seguros (``prisma.$queryRaw`...` ``), ``String.raw`...` ``, rutas Express (`app.get`), `Map.get`, `RegExp.exec` y logs (`console.log`).

### 2. `hardcoded-secrets` (`CWE-798`, Severidad base: `HIGH` / `CRITICAL` según firma)
Archivo: `src/rules/hardcoded-secrets.rule.ts`

- **Qué detecta:**
  - Asignaciones estáticas (`StringLiteral` o `TemplateLiteral` sin interpolaciones) en variables, propiedades de objetos, propiedades de clase y reasignaciones cuyo nombre indique secreto (`password`, `secret`, `apiKey`, `token`, `clientSecret`, `jwtSecret`, `privateKey`, etc.).
  - Firmas de alta confianza incluso sin nombre de variable sensible o como argumento directo de función:
    - Bloques de llaves privadas PEM (`-----BEGIN ... PRIVATE KEY-----`) — `CRITICAL`
    - Tokens de GitHub (`ghp_...`, `github_pat_...`, etc.) — `CRITICAL`
    - Llaves secretas de Stripe (`sk_live_...`, `sk_test_...`, `rk_...`) — `CRITICAL`
    - URIs de bases de datos con credenciales embebidas (`postgres://user:pass@host`) — `CRITICAL`
    - AWS Access Key ID (`AKIA...`, `ASIA...`) — `HIGH`
    - Tokens de Slack (`xox...`), Google API Keys (`AIza...`), llaves `sk-...` y JWTs hardcodeados — `HIGH`
- **Falsos positivos evitados:**
  - Variables de entorno (`process.env.*`), retornos de funciones, sufijos de UI/metadatos (`passwordPlaceholder`, `apiKeyHeader`, `privateKeyPath`, `secretUrl`), placeholders (`changeme`, `your-api-key`), cadenas cortas (`< 6` caracteres), rutas de archivos/URLs sin credenciales y constantes `UPPER_SNAKE_CASE` de baja entropía (`calculateShannonEntropy < 3.8`).

---

## Arquitectura del proyecto

```text
segcomp-project/
├── src/
│   ├── core/
│   │   ├── parser.ts                 # Parseo de código a AST con @babel/parser
│   │   └── scanner.ts                # Resolución con fast-glob y recorrido en 1 pasada
│   ├── reporters/
│   │   ├── console.reporter.ts       # Salida formateada con colores (picocolors)
│   │   └── sarif.reporter.ts         # Generador SARIF v2.1.0 (@types/sarif)
│   ├── rules/
│   │   ├── hardcoded-secrets.rule.ts # Regla CWE-798
│   │   └── sql-injection.rule.ts     # Regla CWE-89
│   ├── types/
│   │   └── finding.ts                # Contratos Finding, Rule, RuleContext, Severity
│   └── index.ts                      # Entrypoint CLI (commander)
├── tests/
│   ├── hardcoded-secrets.rule.test.ts
│   └── sql-injection.rule.test.ts
├── package.json
└── tsconfig.json
```

---

## Cómo agregar una nueva regla

1. Crea un archivo en `src/rules/<nombre>.rule.ts` implementando la interfaz `Rule` de `src/types/finding.ts`:
   ```ts
   import type { Rule, RuleContext, TraverseOptions } from '../types/finding.js';

   export const myRule: Rule = {
     id: 'my-rule-id',
     cwe: 'CWE-XXX',
     name: 'My Security Rule',
     severity: 'MEDIUM',
     description: 'Descripción de la vulnerabilidad.',
     remediation: 'Cómo corregir la vulnerabilidad.',
     createVisitor(context: RuleContext): TraverseOptions {
       return {
         CallExpression(path) {
           // Inspeccionar nodo AST y llamar a context.report({ line, column, message })
         },
       };
     },
   };
   ```
2. Registra la regla en el arreglo `DEFAULT_RULES` dentro de `src/index.ts`.
3. Agrega pruebas unitarias en `tests/<nombre>.rule.test.ts` y verifica con:
   ```bash
   pnpm run build && pnpm test
   ```

## Uso de IA

Se hizo uso de Antigravity para la realización del proyecto.