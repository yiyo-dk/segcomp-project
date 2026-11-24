// Enfoque: Firmas de alta confianza (AWS, Stripe, GitHub, Slack) en variables y argumentos.
export const awsAccessKey = "AKIAIOSFODNN7EXAMPLE";
const stripeLiveKey = "sk_live_51H8xYz9AbCdEfGhIjKlMnOpQrStUvWxYz123456";
const githubClassicToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD";
const githubFineToken = "github_pat_11ABCDEFG0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ";

export function notifySlack(client) {
  return client.postMessage("xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx");
}
