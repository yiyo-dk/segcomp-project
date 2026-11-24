// Enfoque: Interfaces/tipos TS, JWT hardcodeado, Google API Key (AIza...) y llaves sk-...
export interface ThirdPartyCredentials {
  googleMapsApiKey: string;
  openAiKey: string;
  serviceJwt: string;
}

export const credentials: ThirdPartyCredentials = {
  googleMapsApiKey: "AIzaSyDaGmWKa4JsXZ-9876543210abcdefghijk",
  openAiKey: "sk-proj-1234567890abcdefghijklmnopqrstuvwxyzABCD",
  serviceJwt:
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
};
