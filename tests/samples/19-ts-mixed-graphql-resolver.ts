// Enfoque: Resolver GraphQL/API realista en TS combinando SQLi, secretos y consultas seguras.
const SLACK_ALERT_TOKEN = "xoxp-998877665544-112233445566-AbCdEfGhIjKlMnOpQrStUvWx";

interface Context {
  prisma: {
    $queryRawUnsafe: (sql: string) => Promise<unknown[]>;
    $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) => Promise<unknown[]>;
  };
}

export const resolvers = {
  Query: {
    searchOrders: async (_: unknown, args: { term: string }, ctx: Context) => {
      return ctx.prisma.$queryRawUnsafe(
        `SELECT * FROM orders WHERE reference LIKE '%${args.term}%'`
      );
    },
    getOrderById: async (_: unknown, args: { id: string }, ctx: Context) => {
      return ctx.prisma.$queryRaw`SELECT * FROM orders WHERE id = ${args.id}`;
    },
  },
  alertToken: SLACK_ALERT_TOKEN,
};
