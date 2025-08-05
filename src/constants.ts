/**
 * Application constants and configuration
 * Centralized place for app-wide constants that can be easily modified
 */

/**
 * Validates that required environment variables are present
 * Halts the application if any required variables are missing
 */
function validateEnvironment(): void {
  const requiredEnvVars = [
    { name: 'JWT_SECRET', value: process.env.JWT_SECRET },
  ];

  const missingVars = requiredEnvVars.filter(env => !env.value);
  
  if (missingVars.length > 0) {
    console.error('❌ Missing required environment variables:');
    missingVars.forEach(env => {
      console.error(`   - ${env.name}`);
    });
    console.error('\nPlease set these environment variables and restart the application.');
    process.exit(1);
  }
}

// Validate environment variables on module load
validateEnvironment();

export const APP_CONFIG = {
  // Application name - used in 2FA QR codes and other places where app identification is needed
  NAME: process.env.APP_NAME || 'NodeAuth',
  
  // Application version - useful for API responses and logging
  VERSION: process.env.APP_VERSION || '1.0.0',
  
  // Environment
  ENV: process.env.NODE_ENV || 'development',
  
  // API configuration
  API: {
    PREFIX: '/api',
    PORT: process.env.PORT || 3000,
  },
  
  // JWT configuration
  JWT: {
    SECRET: process.env.JWT_SECRET!,
    EXPIRES_IN: process.env.JWT_EXPIRES_IN || '15m',
    REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  },
  
  // Security configuration
  SECURITY: {
    BCRYPT_ROUNDS: 12,
    PASSWORD_MIN_LENGTH: 8,
  },
  
  // Encryption configuration for 2FA secrets
  ENCRYPTION: {
    ALGORITHM: 'aes-256-gcm',
    IV_LENGTH: 12, // For GCM, this is 12 or 16 bytes
    TAG_LENGTH: 16, // GCM authentication tag length
    KEY_LENGTH: 32, // 256 bits
    SALT_LENGTH: 32, // 256-bit salt
    PBKDF2_ITERATIONS: 200000, // Increase for higher security, but more latency
  },
  
  // Rate limiting configuration
  RATE_LIMIT: {
    // General rate limit for all endpoints
    GENERAL: {
      WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes in milliseconds
      MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'), // Maximum requests per window
      MESSAGE: 'Too many requests from this IP, please try again later.',
    },
    
    // Strict rate limit for authentication endpoints (login, register)
    AUTH: {
      WINDOW_MS: parseInt(process.env.RATE_LIMIT_AUTH_WINDOW_MS || '900000'), // 15 minutes in milliseconds
      MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_AUTH_MAX_REQUESTS || '5'), // Maximum auth attempts per window
      MESSAGE: 'Too many authentication attempts from this IP, please try again later.',
    },
    
    // Very strict rate limit for 2FA operations
    TWO_FA: {
      WINDOW_MS: parseInt(process.env.RATE_LIMIT_2FA_WINDOW_MS || '900000'), // 15 minutes in milliseconds
      MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_2FA_MAX_REQUESTS || '3'), // Maximum 2FA attempts per window
      MESSAGE: 'Too many 2FA attempts from this IP, please try again later.',
    },
  },
} as const;

// Type for the app config to ensure type safety
export type AppConfig = typeof APP_CONFIG;

/**
 * Helper function to parse duration strings (e.g., '7d', '15m') into milliseconds
 * @param duration - Duration string in format like '7d', '15m', '1h'
 * @returns Duration in milliseconds
 */
export function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)([dhms])$/);
  if (!match) {
    throw new Error(`Invalid duration format: ${duration}. Expected format like '7d', '15m', '1h'`);
  }
  
  const value = parseInt(match[1], 10);
  const unit = match[2];
  
  const multipliers = {
    's': 1000,        // seconds
    'm': 60 * 1000,   // minutes
    'h': 60 * 60 * 1000, // hours
    'd': 24 * 60 * 60 * 1000, // days
  };
  
  return value * multipliers[unit as keyof typeof multipliers];
} 