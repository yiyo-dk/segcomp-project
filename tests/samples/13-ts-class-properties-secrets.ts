// Enfoque: Propiedades de clase en TypeScript (private, readonly, static) con secretos.
export class PaymentGatewayClient {
  private readonly apiKey: string = "sk_test_51N9xYz0AbCdEfGhIjKlMnOpQrStUvWxYz654321";
  static jwtSecret = "super-secret-class-level-jwt-signing-key";
  protected clientSecret: string;

  constructor(overrideSecret?: string) {
    this.clientSecret = overrideSecret ?? "fallback_client_secret_value_123456";
  }

  public getKeyPrefix(): string {
    return this.apiKey.slice(0, 7);
  }
}
