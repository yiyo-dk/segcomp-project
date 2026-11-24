// Enfoque: Falsos positivos de secretos (env vars, placeholders, metadatos UI, baja entropía).
export const safeConfig = {
  password: process.env.DB_PASSWORD,
  apiKey: getSecretFromVault(),
  passwordPlaceholder: "Enter your password here",
  apiKeyHeader: "X-Api-Key",
  privateKeyPath: "/etc/ssl/private/app.key",
  secretUrl: "https://vault.internal.local/v1/secret",
  devToken: "changeme",
  sampleKey: "your-api-key",
  shortSecret: "abc",
};

export const APP_SECRET_LABEL = "APPLICATION_SECRET_HEADER_NAME";

function getSecretFromVault() {
  return process.env.VAULT_KEY || "";
}
