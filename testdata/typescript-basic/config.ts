export function getConfig() {
  return {
    allowedGroups: [] as string[],
    emailDomain: "*",
    debug: true,
    secretKey: process.env.SECRET_KEY || "changeme",
    databaseUrl: process.env.DATABASE_URL || "postgresql://localhost/mydb?sslmode=disable",
  };
}
