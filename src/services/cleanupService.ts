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

export const cleanupExpiredChallenges = async (): Promise<{ deletedCount: number }> => {
  try {
    const result = await prisma.challenge.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(), // Delete challenges that expired before now
        },
      },
    });

    console.log(`🧹 Cleanup: Removed ${result.count} expired WebAuthn challenges`);
    
    return { deletedCount: result.count };
  } catch (error) {
    console.error('❌ Error during challenge cleanup:', error);
    throw error;
  }
};

// Combined cleanup function that runs both cleanups
export const performAllCleanups = async (): Promise<{ refreshTokensDeleted: number; challengesDeleted: number }> => {
  const [refreshTokenResult, challengeResult] = await Promise.all([
    cleanupExpiredRefreshTokens(),
    cleanupExpiredChallenges(),
  ]);

  return {
    refreshTokensDeleted: refreshTokenResult.deletedCount,
    challengesDeleted: challengeResult.deletedCount,
  };
};