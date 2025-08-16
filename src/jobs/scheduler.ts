import * as cron from 'node-cron';
import { performAllCleanups } from '../services/cleanupService';
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
      console.log('🧹 Starting cleanup of expired tokens and challenges...');
      const result = await performAllCleanups();
      
      const totalDeleted = result.refreshTokensDeleted + result.challengesDeleted;
      if (totalDeleted > 0) {
        console.log(`✅ Cleanup completed: ${result.refreshTokensDeleted} expired tokens and ${result.challengesDeleted} expired challenges removed`);
      } else {
        console.log('✅ Cleanup completed: No expired items found');
      }
    } catch (error) {
      console.error('❌ Cleanup job failed:', error);
    } finally {
      isCleanupJobRunning = false;
    }
  }, {
    timezone: APP_CONFIG.CLEANUP.TIMEZONE,
  });

  console.log(`✅ Cleanup job scheduled: ${APP_CONFIG.CLEANUP.SCHEDULE} (${APP_CONFIG.CLEANUP.TIMEZONE}) - Cleaning tokens and challenges`);
};