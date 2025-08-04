import { Request, Response } from 'express'; // Import types for request and response objects from Express
import bcrypt from 'bcrypt'; // Import bcrypt for hashing and comparing passwords securely
import { PrismaClient } from '../generated/prisma'; // Import Prisma client for database interactions
import crypto from 'crypto'; // Add this import at the top
import jwt from 'jsonwebtoken'; // Import jsonwebtoken for creating and verifying JWT tokens
import dotenv from 'dotenv'; // Import dotenv to load environment variables from .env file
import { registerSchema, loginSchema, login2FASchema, refreshSchema, confirm2FASchema, reset2FASchema, disable2FASchema, generate2FASchema, deleteAccountSchema } from '../schemas/authSchemas'; // Import our custom auth schemas
import { z } from 'zod';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import { AuthenticatedRequest } from '../middleware/authMiddleware';
import { APP_CONFIG, parseDuration } from '../constants';

/**
 * Prisma client instance used to interact with the database.
 * Provides methods to perform CRUD operations on the database tables.
 */
const prisma = new PrismaClient(); // Instantiate Prisma client to interact with the database

/**
 * Loads environment variables from a .env file into process.env.
 * This allows secure configuration of sensitive data like JWT secrets.
 */
dotenv.config(); // Load environment variables from .env file into process.env

/**
 * Registers a new user by creating a user record in the database.
 * Route: POST /register
 *
 * @param {Request} req - Express request object containing user email and password in the body.
 * @param {Response} res - Express response object used to send back status and messages.
 * @returns {Promise<Response>} JSON response indicating success or failure of registration.
 */
export const registerUser = async (req: Request, res: Response) => {
  const parse = registerSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }
  const { email, password } = parse.data;

  try {
    // Check if a user with the given email already exists in the database
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      // If user exists, respond with a conflict error
      return res.status(409).json({ error: 'User already exists.' });
    }

    // Hash the password using bcrypt with configured salt rounds for security
    const hashedPassword = await bcrypt.hash(password, APP_CONFIG.SECURITY.BCRYPT_ROUNDS);

    // Create a new user record in the database with the hashed password
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });

    // Respond with success message and user details (excluding password)
    return res.status(201).json({
      message: 'User registered successfully.',
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.createdAt,
      },
    });
  } catch (err) {
    // Log any errors and respond with internal server error
    console.error(err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
};

/**
 * Authenticates a user by validating credentials and issuing a JWT token.
 * If 2FA is enabled, returns a temporary token that requires 2FA completion.
 * Route: POST /login
 *
 * @param {Request} req - Express request object containing user email and password in the body.
 * @param {Response} res - Express response object used to send back status, messages, and token.
 * @returns {Promise<Response>} JSON response containing access token on successful login or error message.
 */
export const loginUser = async (req: Request, res: Response) => {
  const parse = loginSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }
  const { email, password } = parse.data;

  try {
    // Find the user in the database by email
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      // If user not found, respond with unauthorized error
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Compare the provided password with the stored hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      // If password does not match, respond with unauthorized error
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Check if 2FA is enabled for this user
    if (user.twoFactorEnabled) {
      // Generate a temporary token for 2FA verification
      const tempToken = jwt.sign(
        { 
          userId: user.id, 
          temp: true,
          purpose: '2fa_verification'
        },
        APP_CONFIG.JWT.SECRET,
        { expiresIn: '5m' } as jwt.SignOptions // Short expiry for security
      );

      return res.status(200).json({
        message: '2FA verification required',
        requires2FA: true,
        tempToken,
        user: {
          id: user.id,
          email: user.email,
        },
      });
    }

    // If 2FA is not enabled, proceed with normal login
    return await completeLogin(user, res);
  } catch (err) {
    // Log any errors and respond with internal server error
    console.error(err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
};

/**
 * Completes login with 2FA verification using the temporary token from the loginUser function
 * Route: POST /login/2fa
 *
 * @param {Request} req - Express request object containing OTP and temporary token.
 * @param {Response} res - Express response object used to send back status, messages, and token.
 * @returns {Promise<Response>} JSON response containing access token on successful login or error message.
 */
export const loginWith2FA = async (req: Request, res: Response) => {
  const parse = login2FASchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }
  const { otp, tempToken } = parse.data;

  try {
    // Verify the temporary token
    let decoded;
    try {
      decoded = jwt.verify(tempToken, APP_CONFIG.JWT.SECRET) as any;
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired temporary token.' });
    }

    // Check if this is a valid temporary token for 2FA verification
    if (!decoded.temp || decoded.purpose !== '2fa_verification') {
      return res.status(401).json({ error: 'Invalid token type.' });
    }

    // Find the user
    const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    // Check if 2FA is enabled
    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(400).json({ error: '2FA is not enabled for this account.' });
    }

    // Verify the OTP code
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: otp,
      window: 2, // Allow for time drift (2 time steps = 60 seconds)
    });

    if (!verified) {
      return res.status(401).json({ error: 'Invalid 2FA code.' });
    }

    // Complete the login process
    return await completeLogin(user, res);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
};

/**
 * Helper function to complete the login process by generating tokens.
 * 
 * @param {any} user - The user object from the database
 * @param {Response} res - Express response object
 * @returns {Promise<Response>} JSON response with access and refresh tokens
 */
const completeLogin = async (user: any, res: Response) => {
  // Create a JWT token containing the user's ID, signed with the secret key
  // The token expires based on the configured JWT expiration time
  const token = jwt.sign(
    { userId: user.id },
    APP_CONFIG.JWT.SECRET,
    { expiresIn: APP_CONFIG.JWT.EXPIRES_IN } as jwt.SignOptions
  );

  // Generate and store refresh token in DB with configured expiration
  const refreshToken = crypto.randomUUID();
  const refreshTokenExpiry = new Date();
  refreshTokenExpiry.setTime(refreshTokenExpiry.getTime() + parseDuration(APP_CONFIG.JWT.REFRESH_EXPIRES_IN));

  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: refreshTokenExpiry,
    },
  });

  // Respond with success message and access token
  return res.status(200).json({
    message: 'Login successful',
    accessToken: token,
    refreshToken,
    user: {
      id: user.id,
      email: user.email,
      twoFactorEnabled: user.twoFactorEnabled,
    },
  });
};

/**
 * Issues a new access token using a valid refresh token.
 * Route: POST /refresh
 *
 * @param {Request} req - Express request object containing the refresh token.
 * @param {Response} res - Express response object used to send back status, messages, and new tokens.
 * @returns {Promise<Response>} JSON response containing new access token and rotated refresh token or error message.
 */
export const refreshTokenHandler = async (req: Request, res: Response) => {
  const parse = refreshSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }

  const { refreshToken } = parse.data;

  try {
    const existingToken = await prisma.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: true },
    });

    if (!existingToken) {
      return res.status(401).json({ error: 'Invalid refresh token.' });
    }

    if (existingToken.expiresAt < new Date()) {
      return res.status(403).json({ error: 'Refresh token has expired.' });
    }

    // Rotate the refresh token
    const newRefreshToken = crypto.randomUUID();
    const newExpiry = new Date();
    newExpiry.setTime(newExpiry.getTime() + parseDuration(APP_CONFIG.JWT.REFRESH_EXPIRES_IN));

    await prisma.$transaction([
      prisma.refreshToken.delete({ where: { token: refreshToken } }),
      prisma.refreshToken.create({
        data: {
          token: newRefreshToken,
          userId: existingToken.userId,
          expiresAt: newExpiry,
        },
      }),
    ]);

    // Issue new access token
    const accessToken = jwt.sign(
      { userId: existingToken.userId },
      APP_CONFIG.JWT.SECRET,
      { expiresIn: APP_CONFIG.JWT.EXPIRES_IN } as jwt.SignOptions
    );

    return res.status(200).json({
      message: 'Token refreshed successfully',
      accessToken,
      refreshToken: newRefreshToken,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
};

/**
 * Generates a 2FA secret and returns a QR code URL to scan with an authenticator app.
 * If 2FA is already enabled, requires password verification.
 * Route: POST /2fa/generate
 */
export const generate2FASecret = async (req: AuthenticatedRequest, res: Response) => {
  const parse = generate2FASchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }
  const { password } = parse.data;

  const userId = req.userId; 
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });

  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return res.status(404).json({ error: 'User not found' });

  // Always require password verification for security
  if (!password) {
    return res.status(400).json({ 
      error: 'Password is required to manage 2FA settings.' 
    });
  }

  // Verify the provided password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ error: 'Invalid password.' });
  }

  // If 2FA is already enabled, return existing secret
  if (user.twoFactorEnabled && user.twoFactorSecret) {

    const secret = {
      base32: user.twoFactorSecret,
      otpauth_url: speakeasy.otpauthURL({
        secret: user.twoFactorSecret,
        label: user.email,
        issuer: APP_CONFIG.NAME,
        algorithm: 'sha1',
        digits: 6,
        period: 30,
      })
    };

    const qr = await qrcode.toDataURL(secret.otpauth_url);

    return res.json({ 
      otpauthUrl: secret.otpauth_url, 
      qrCodeDataURL: qr,
      message: '2FA is already enabled. This is your existing setup.'
    });
  }

  // Generate new secret only if 2FA is not enabled
  const secret = speakeasy.generateSecret({
    name: `${APP_CONFIG.NAME} (${user.email})`,
  });

  await prisma.user.update({
    where: { id: userId },
    data: { twoFactorSecret: secret.base32 },
  });

  const otpauthUrl = secret.otpauth_url!;
  const qr = await qrcode.toDataURL(otpauthUrl);

  return res.json({ otpauthUrl, qrCodeDataURL: qr });
};

/**
 * Confirms a 2FA OTP code and enables 2FA for the user if valid.
 * Route: POST /2fa/confirm
 *
 * @param {AuthenticatedRequest} req - Express request object containing the OTP code in the body.
 * @param {Response} res - Express response object used to send back status and messages.
 * @returns {Promise<Response>} JSON response indicating success or failure of OTP confirmation.
 */
export const confirm2FA = async (req: AuthenticatedRequest, res: Response) => {
  const parse = confirm2FASchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }
  const { otp } = parse.data;

  const userId = req.userId;
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    // Find the user and verify they have a 2FA secret
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.twoFactorSecret) {
      return res.status(400).json({ error: '2FA secret not found. Please generate a 2FA secret first.' });
    }

    // Verify the OTP code using speakeasy
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: otp,
      window: 2, // Allow for time drift (2 time steps = 60 seconds)
    });
    
    if (!verified) {
      return res.status(400).json({ error: 'Invalid OTP code. Please try again.' });
    }

    // Enable 2FA for the user
    await prisma.user.update({
      where: { id: userId },
      data: { twoFactorEnabled: true },
    });

    return res.status(200).json({
      message: '2FA enabled successfully',
      twoFactorEnabled: true,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
};

/**
 * Resets 2FA by generating a new secret. Requires password verification for security.
 * Route: POST /2fa/reset
 *
 * @param {AuthenticatedRequest} req - Express request object containing password in the body.
 * @param {Response} res - Express response object used to send back status, messages, and new secret.
 * @returns {Promise<Response>} JSON response containing new 2FA secret or error message.
 */
export const reset2FA = async (req: AuthenticatedRequest, res: Response) => {
  const parse = reset2FASchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }
  const { password } = parse.data;

  const userId = req.userId;
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    // Find the user and verify password
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify the provided password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password.' });
    }

    // Generate new secret
    const secret = speakeasy.generateSecret({
      name: `${APP_CONFIG.NAME} (${user.email})`,
    });

    // Update user with new secret and disable 2FA until confirmed
    await prisma.user.update({
      where: { id: userId },
      data: { 
        twoFactorSecret: secret.base32,
        twoFactorEnabled: false // Disable until new setup is confirmed
      },
    });

    const otpauthUrl = secret.otpauth_url!;
    const qr = await qrcode.toDataURL(otpauthUrl);

    return res.status(200).json({
      message: '2FA reset successfully. Please scan the new QR code and confirm setup.',
      otpauthUrl,
      qrCodeDataURL: qr,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
};

/**
 * Disables 2FA for the user. Requires password verification for security.
 * Route: POST /2fa/disable
 *
 * @param {AuthenticatedRequest} req - Express request object containing password in the body.
 * @param {Response} res - Express response object used to send back status and messages.
 * @returns {Promise<Response>} JSON response indicating success or failure of 2FA disable.
 */
export const disable2FA = async (req: AuthenticatedRequest, res: Response) => {
  const parse = disable2FASchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }
  const { password } = parse.data;

  const userId = req.userId;
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    // Find the user and verify password
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if 2FA is enabled
    if (!user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is not enabled for this account.' });
    }

    // Verify the provided password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password.' });
    }

    // Disable 2FA and clear the secret
    await prisma.user.update({
      where: { id: userId },
      data: { 
        twoFactorEnabled: false,
        twoFactorSecret: null
      },
    });

    return res.status(200).json({
      message: '2FA disabled successfully.',
      twoFactorEnabled: false,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
};

/**
 * Deletes the user account and all associated data. Requires password verification for security.
 * This action is irreversible and will delete all user data including refresh tokens.
 * Route: DELETE /account
 *
 * @param {AuthenticatedRequest} req - Express request object containing password in the body.
 * @param {Response} res - Express response object used to send back status and messages.
 * @returns {Promise<Response>} JSON response indicating success or failure of account deletion.
 */
export const deleteAccount = async (req: AuthenticatedRequest, res: Response) => {
  const parse = deleteAccountSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }
  const { password } = parse.data;

  const userId = req.userId;
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    // Find the user and verify password
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify the provided password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password.' });
    }

    // Delete all associated data in a transaction to ensure data consistency
    await prisma.$transaction(async (tx) => {
      // Verify the user still exists before deletion
      const currentUser = await tx.user.findUnique({
        where: { id: userId }
      });

      if (!currentUser) {
        throw new Error('User no longer exists');
      }

      // Delete the user account (cascading deletes will handle refresh tokens and backup codes)
      await tx.user.delete({
        where: { id: userId },
      });
    });

    return res.status(200).json({
      message: 'Account deleted successfully. All data has been permanently removed.',
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
};