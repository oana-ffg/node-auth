import { PrismaClient } from '../generated/prisma';

const prisma = new PrismaClient();

export const cleanupExpiredRefreshTokens = async (): Promise<{ deletedCount: number }> => {
  try {
    const result = await prisma.refreshToken.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(), // Delete tokens that expired before now
        },
      },
    });

    console.log(`🧹 Cleanup: Removed ${result.count} expired refresh tokens`);
    
    return { deletedCount: result.count };
  } catch (error) {
    console.error('❌ Error during refresh token cleanup:', error);
    throw error;
  }
};