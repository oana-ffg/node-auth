import { PrismaClient } from '../generated/prisma';

// Reuse one connection pool across controllers and scheduled cleanup jobs.
export const prisma = new PrismaClient();
