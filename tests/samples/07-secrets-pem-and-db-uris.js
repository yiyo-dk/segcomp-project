// Enfoque: Llaves privadas PEM y URIs de bases de datos con credenciales embebidas.
export const signingKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA75+3ExampleKeyMaterialForStaticAnalysisTestingOnly
-----END RSA PRIVATE KEY-----`;

export const postgresUrl = "postgres://admin:S3cr3tP@ssw0rd!@db.internal.local:5432/prod";
export const mongoUri = "mongodb+srv://root:MySuperSecret99@cluster0.example.net/app";
