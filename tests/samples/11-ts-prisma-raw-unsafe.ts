// Enfoque: Prisma ($queryRawUnsafe, $executeRawUnsafe, Prisma.raw vs $queryRaw tagged seguro).
interface PrismaClientLike {
  $queryRawUnsafe<T = unknown>(query: string): Promise<T>;
  $executeRawUnsafe(query: string): Promise<number>;
  $queryRaw<T = unknown>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T>;
}

const Prisma = {
  raw: (sql: string) => sql,
};

export async function getUsersUnsafe(prisma: PrismaClientLike, orgId: string) {
  return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE org_id = '${orgId}'`);
}

export async function purgeLogsUnsafe(prisma: PrismaClientLike, days: number) {
  return prisma.$executeRawUnsafe("DELETE FROM logs WHERE age_days > " + days);
}

export async function getWithPrismaRaw(prisma: PrismaClientLike, filter: string) {
  return prisma.$queryRaw`SELECT * FROM items WHERE ${Prisma.raw("category = '" + filter + "'")}`;
}

export async function getUsersSafe(prisma: PrismaClientLike, orgId: string) {
  return prisma.$queryRaw`SELECT * FROM users WHERE org_id = ${orgId}`;
}
