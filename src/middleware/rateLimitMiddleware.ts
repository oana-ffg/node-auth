import rateLimit from 'express-rate-limit';
import { APP_CONFIG } from '../constants';

/**
 * General rate limiter for all API endpoints
 * Applies a moderate rate limit to prevent general API abuse
 */
export const generalRateLimit = rateLimit({
  windowMs: APP_CONFIG.RATE_LIMIT.GENERAL.WINDOW_MS,
  max: APP_CONFIG.RATE_LIMIT.GENERAL.MAX_REQUESTS,
  message: {
    error: APP_CONFIG.RATE_LIMIT.GENERAL.MESSAGE,
    retryAfter: Math.ceil(APP_CONFIG.RATE_LIMIT.GENERAL.WINDOW_MS / 1000),
  },
  standardHeaders: 'draft-7', // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // Skip successful requests when counting towards the limit
  skipSuccessfulRequests: false,
  // Skip failed requests when counting towards the limit  
  skipFailedRequests: false,
});

/**
 * Strict rate limiter for authentication endpoints (login, register)
 * Prevents brute force attacks on authentication
 */
export const authRateLimit = rateLimit({
  windowMs: APP_CONFIG.RATE_LIMIT.AUTH.WINDOW_MS,
  max: APP_CONFIG.RATE_LIMIT.AUTH.MAX_REQUESTS,
  message: {
    error: APP_CONFIG.RATE_LIMIT.AUTH.MESSAGE,
    retryAfter: Math.ceil(APP_CONFIG.RATE_LIMIT.AUTH.WINDOW_MS / 1000),
  },
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  // Only count failed requests for auth endpoints to prevent lockout on successful logins
  skipSuccessfulRequests: true,
  skipFailedRequests: false,
});

/**
 * Very strict rate limiter for 2FA operations
 * Prevents abuse of two-factor authentication endpoints
 */
export const twoFALimit = rateLimit({
  windowMs: APP_CONFIG.RATE_LIMIT.TWO_FA.WINDOW_MS,
  max: APP_CONFIG.RATE_LIMIT.TWO_FA.MAX_REQUESTS,
  message: {
    error: APP_CONFIG.RATE_LIMIT.TWO_FA.MESSAGE,
    retryAfter: Math.ceil(APP_CONFIG.RATE_LIMIT.TWO_FA.WINDOW_MS / 1000),
  },
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  // Count all requests for 2FA operations as they are sensitive
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
});