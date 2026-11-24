// Casos diseñados para provocar FALSOS POSITIVOS en hardcoded-secrets (CWE-798)

// 1. Texto de UI cuyo sufijo ("Text", "Description") no está en NON_SECRET_SUFFIX_PATTERN
export const uiStrings = {
  passwordResetText: 'We sent a recovery link to your email address.',
  apiKeyDescription: 'Generate a new key from your developer dashboard.',
};

// 2. Identificador de configuración / clave i18n asignada a variable con nombre sensible
export const authSettings = {
  jwtSecret: 'auth.config.jwt_secret_reference',
  secretEnvName: 'APP_INTERNAL_SIGNING_SECRET_KEY_V2',
};

// 3. String de relleno/documentación que coincide con firma de GitHub (baja entropía, evaluada antes de filtros)
export const docsExampleToken = 'ghp_000000000000000000000000000000000000';

// 4. URI local de desarrollo con credenciales de ejemplo
export const localDevDb = 'postgres://postgres:postgres@localhost:5432/dev_db';
