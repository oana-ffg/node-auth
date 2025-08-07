import * as cron from 'node-cron';
import { cleanupExpiredRefreshTokens } from '../services/cleanupService';
import { APP_CONFIG } from '../constants';

let isCleanupJobRunning = false;

export const startScheduledJobs = (): void => {
  console.log('🕒 Starting scheduled jobs...');

  cron.schedule(APP_CONFIG.CLEANUP.SCHEDULE, async () => {
    if (isCleanupJobRunning) {
      console.log('⏳ Cleanup job already running, skipping this execution');
      return;
    }

    isCleanupJobRunning = true;
    
    try {
      console.log('🧹 Starting expired refresh token cleanup...');
      const result = await cleanupExpiredRefreshTokens();
      
      if (result.deletedCount > 0) {
        console.log(`✅ Cleanup completed: ${result.deletedCount} expired tokens removed`);
      } else {
        console.log('✅ Cleanup completed: No expired tokens found');
      }
    } catch (error) {
      console.error('❌ Cleanup job failed:', error);
    } finally {
      isCleanupJobRunning = false;
    }
  }, {
    timezone: APP_CONFIG.CLEANUP.TIMEZONE,
  });

  console.log(`✅ Cleanup job scheduled: ${APP_CONFIG.CLEANUP.SCHEDULE} (${APP_CONFIG.CLEANUP.TIMEZONE})`);
};