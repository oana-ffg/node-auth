import { z } from 'zod';
import { APP_CONFIG } from '../constants';

export const registerSchema = z.object({
  email: z.email(),
  password: z
    .string()
    .min(APP_CONFIG.SECURITY.PASSWORD_MIN_LENGTH, `Password must be at least ${APP_CONFIG.SECURITY.PASSWORD_MIN_LENGTH} characters`)
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
});

export const loginSchema = z.object({
  email: z.email(),
  password: z.string(),
});

export const login2FASchema = z.object({
  otp: z.string().length(6, { message: 'OTP must be exactly 6 digits.' }),
  tempToken: z.string().min(1, { message: 'Temporary token is required.' }),
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(1, { message: 'Refresh token is required.' }),
});

export const confirm2FASchema = z.object({
  otp: z.string().length(6, { message: 'OTP must be exactly 6 digits.' }),
});

export const reset2FASchema = z.object({
  password: z.string().min(1, { message: 'Password is required.' }),
});

export const disable2FASchema = z.object({
  password: z.string().min(1, { message: 'Password is required.' }),
});

export const generate2FASchema = z.object({
  password: z.string().min(1, { message: 'Password is required for 2FA management.' }),
});

export const deleteAccountSchema = z.object({
  password: z.string().min(1, { message: 'Password is required to delete account.' }),
});