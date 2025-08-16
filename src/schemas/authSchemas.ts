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

export const passkeyRegistrationStartSchema = z.object({
  password: z.string().min(1, { message: 'Password is required for passkey registration.' }),
  name: z.string().optional(),
});

// Base64url regex pattern (no padding, URL-safe characters)
const base64urlRegex = /^[A-Za-z0-9_-]+$/;

export const passkeyRegistrationCompleteSchema = z.object({
  credential: z.object({
    id: z.string().regex(base64urlRegex, 'id must be base64url encoded'),
    rawId: z.string().regex(base64urlRegex, 'rawId must be base64url encoded'),
    response: z.object({
      attestationObject: z.string().regex(base64urlRegex, 'attestationObject must be base64url encoded'),
      clientDataJSON: z.string().regex(base64urlRegex, 'clientDataJSON must be base64url encoded'),
      transports: z.array(z.enum(['usb', 'nfc', 'ble', 'internal', 'hybrid', 'cable'])).optional(),
    }),
    type: z.literal('public-key'),
    clientExtensionResults: z.record(z.string(), z.unknown()).optional(),
    authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
  }),
  name: z.string().optional(),
});

export const passkeyAuthenticationStartSchema = z.object({
  email: z.email().optional(),
});

export const passkeyAuthenticationCompleteSchema = z.object({
  credential: z.object({
    id: z.string(),
    rawId: z.string(),
    response: z.object({
      authenticatorData: z.string(),
      clientDataJSON: z.string(),
      signature: z.string(),
      userHandle: z.string().nullable().optional(),
    }),
    type: z.literal('public-key'),
    clientExtensionResults: z.object({}).optional(),
    authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
  }),
});

export const passkeyDeleteSchema = z.object({
  passkeyId: z.string().min(1, { message: 'Passkey ID is required.' }),
  password: z.string().min(1, { message: 'Password is required to delete passkey.' }),
});

export const passkeyRenameSchema = z.object({
  passkeyId: z.string().min(1, { message: 'Passkey ID is required.' }),
  name: z.string().min(1, { message: 'Passkey name is required.' }).max(50, { message: 'Passkey name must be 50 characters or less.' }),
});