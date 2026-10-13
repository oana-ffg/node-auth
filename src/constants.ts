/**
 * Application constants and configuration
 * Centralized place for app-wide constants that can be easily modified
 */

/**
 * Validates that required environment variables are present
 * Halts the application if any required variables are missing
 */
function validateEnvironment(): void {
  // Collect all validation errors to display them at once
  const errors: string[] = [];

  // JWT secret validation
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    errors.push('JWT_SECRET is required');
  } else if (jwtSecret.length < 32) {
    errors.push('JWT_SECRET must be at least 32 characters long');
  }

  // Database URL validation (Prisma datasource)
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    errors.push('DATABASE_URL is required');
  } else if (!/^postgresql:\/\//i.test(databaseUrl)) {
    errors.push('DATABASE_URL must be a valid PostgreSQL connection string starting with "postgresql://"');
  }

  // Encryption version for new data
  const encryptionVersion = process.env.ENCRYPTION_VERSION_FOR_NEW_DATA || 'v1';
  if (encryptionVersion !== 'v1' && encryptionVersion !== 'v2') {
    errors.push('ENCRYPTION_VERSION_FOR_NEW_DATA must be either "v1" or "v2"');
  }

  // Encryption keys validation
  const encryptionKeyV1 = process.env.ENCRYPTION_KEY_V1;
  if (!encryptionKeyV1) {
    errors.push('ENCRYPTION_KEY_V1 is required');
  } else if (encryptionKeyV1.length < 32) {
    errors.push('ENCRYPTION_KEY_V1 must be at least 32 characters long');
  }

  const encryptionKeyV2 = process.env.ENCRYPTION_KEY_V2;
  if (encryptionVersion === 'v2') {
    if (!encryptionKeyV2) {
      errors.push('ENCRYPTION_KEY_V2 is required when ENCRYPTION_VERSION_FOR_NEW_DATA is set to "v2"');
    } else if (encryptionKeyV2.length < 32) {
      errors.push('ENCRYPTION_KEY_V2 must be at least 32 characters long');
    }
  } else if (encryptionKeyV2 && encryptionKeyV2.length < 32) {
    errors.push('ENCRYPTION_KEY_V2 must be at least 32 characters long when provided');
  }

  // WebAuthn environment variables validation
  const webauthnOrigin = process.env.WEBAUTHN_ORIGIN;
  if (webauthnOrigin) {
    try {
      const originUrl = new URL(webauthnOrigin);
      
      // Enforce HTTPS for non-development environments except for localhost/127.0.0.1
      const isDevelopment = process.env.NODE_ENV === 'development';
      const isLocalhost = originUrl.hostname === 'localhost' || originUrl.hostname === '127.0.0.1';
      
      if (!isDevelopment && !isLocalhost && originUrl.protocol !== 'https:') {
        errors.push('WEBAUTHN_ORIGIN must use HTTPS in non-development environments unless the host is localhost or 127.0.0.1');
      }
      
      // Validate WEBAUTHN_RP_ID if provided
      const webauthnRpId = process.env.WEBAUTHN_RP_ID;
      if (webauthnRpId) {
        const originHost = originUrl.hostname;
        
        // Check if RP_ID equals origin host or is a registrable suffix
        if (webauthnRpId !== originHost && !originHost.endsWith('.' + webauthnRpId)) {
          errors.push(`WEBAUTHN_RP_ID "${webauthnRpId}" must equal the origin host "${originHost}" or be a registrable suffix of it`);
        }
      }
      
    } catch (error) {
      errors.push('WEBAUTHN_ORIGIN must be a valid URL');
    }
  }

  // Validate WEBAUTHN_USER_VERIFICATION
  const webauthnUserVerification = process.env.WEBAUTHN_USER_VERIFICATION;
  if (webauthnUserVerification) {
    const validValues = ['required', 'preferred', 'discouraged'];
    if (!validValues.includes(webauthnUserVerification.toLowerCase())) {
      errors.push(`WEBAUTHN_USER_VERIFICATION must be one of: ${validValues.join(', ')} (case-insensitive)`);
    }
  }

  // Validate WEBAUTHN_TIMEOUT
  const webauthnTimeout = process.env.WEBAUTHN_TIMEOUT;
  if (webauthnTimeout) {
    const timeoutValue = parseInt(webauthnTimeout, 10);
    if (isNaN(timeoutValue) || timeoutValue <= 0) {
      errors.push('WEBAUTHN_TIMEOUT must be a positive integer');
    }
  }

  if (errors.length > 0) {
    console.error('❌ Environment validation failed:');
    errors.forEach(err => console.error(`   - ${err}`));
    console.error('\nPlease set these environment variables correctly and restart the application.');
    process.exit(1);
  }
}

// Validate environment variables on module load
validateEnvironment();

// Resolve WebAuthn origin and RP ID defaults in one place to ensure consistency
const DEFAULT_WEBAUTHN_ORIGIN = process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000';

function deriveHostnameFromOrigin(origin: string | undefined): string | undefined {
  if (!origin) {
    return undefined;
  }
  try {
    const parsed = new URL(origin);
    return parsed.hostname || undefined;
  } catch {
    return undefined;
  }
}

const DEFAULT_WEBAUTHN_RP_ID = process.env.WEBAUTHN_RP_ID
  || deriveHostnameFromOrigin(DEFAULT_WEBAUTHN_ORIGIN)
  || 'localhost';

// Allowed values for WebAuthn user verification preference
const USER_VERIFICATION_VALUES = ['required', 'preferred', 'discouraged'] as const;
type UserVerification = (typeof USER_VERIFICATION_VALUES)[number];

function isUserVerification(value: string): value is UserVerification {
  return (USER_VERIFICATION_VALUES as readonly string[]).includes(value);
}

const RESOLVED_USER_VERIFICATION: UserVerification = (() => {
  const normalized = (process.env.WEBAUTHN_USER_VERIFICATION || 'preferred').toLowerCase();
  return isUserVerification(normalized) ? normalized : 'preferred';
})();

export const APP_CONFIG = {
  // Application name - used in 2FA QR codes and other places where app identification is needed
  NAME: process.env.APP_NAME || 'NodeAuth',
  
  // API configuration
  API: {
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
  
  // Cleanup job configuration
  CLEANUP: {
    SCHEDULE: process.env.CLEANUP_SCHEDULE || '0 2 * * *', // Daily at 2 AM by default
    TIMEZONE: process.env.CLEANUP_TIMEZONE || 'America/New_York',
  },
  
  // WebAuthn/Passkey configuration
  WEBAUTHN: {
    RP_NAME: process.env.WEBAUTHN_RP_NAME || 'NodeAuth',
    RP_ID: DEFAULT_WEBAUTHN_RP_ID,
    ORIGIN: DEFAULT_WEBAUTHN_ORIGIN,
    TIMEOUT: (() => {
      const raw = process.env.WEBAUTHN_TIMEOUT;
      const defaultMs = 60000;
      const minMs = 1000;
      const maxMs = 300000;
      const parsed = raw !== undefined ? parseInt(raw, 10) : defaultMs;
      const safeValue = Number.isNaN(parsed) || parsed < 0 ? defaultMs : parsed;
      return Math.max(minMs, Math.min(maxMs, safeValue));
    })(), // 60 seconds
    USER_VERIFICATION: RESOLVED_USER_VERIFICATION,
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