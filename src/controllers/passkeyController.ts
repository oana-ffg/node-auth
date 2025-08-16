import { Request, Response } from 'express';
import { PrismaClient, DeviceType } from '../generated/prisma';
import { AuthenticatedRequest } from '../middleware/authMiddleware';
import { APP_CONFIG } from '../constants';
import { z } from 'zod';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

import type {
  GenerateRegistrationOptionsOpts,
  GenerateAuthenticationOptionsOpts,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';

import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/types';

import {
  passkeyRegistrationStartSchema,
  passkeyRegistrationCompleteSchema,
  passkeyAuthenticationStartSchema,
  passkeyAuthenticationCompleteSchema,
  passkeyDeleteSchema,
  passkeyRenameSchema,
} from '../schemas/authSchemas';

const prisma = new PrismaClient();

// Helper function to create challenge expiration date
function getChallengeExpiration(): Date {
  const expiration = new Date();
  expiration.setTime(expiration.getTime() + APP_CONFIG.WEBAUTHN.TIMEOUT + 30000); // Timeout + 30s grace period
  return expiration;
}

/**
 * Starts passkey registration process by generating challenge options
 * Route: POST /passkey/register/start
 */
export const startPasskeyRegistration = async (req: AuthenticatedRequest, res: Response) => {
  const parse = passkeyRegistrationStartSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }

  const { password } = parse.data;
  const userId = req.userId;
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { passkeys: true },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify the provided password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password.' });
    }

    // Get existing passkeys for excludeCredentials
    const existingPasskeys = user.passkeys.map(passkey => ({
      id: passkey.credentialId,
      type: 'public-key' as const,
      transports: passkey.transports as AuthenticatorTransport[],
    }));

    const options: GenerateRegistrationOptionsOpts = {
      rpName: APP_CONFIG.WEBAUTHN.RP_NAME,
      rpID: APP_CONFIG.WEBAUTHN.RP_ID,
      userID: Buffer.from(user.id),
      userName: user.email,
      userDisplayName: user.email,
      timeout: APP_CONFIG.WEBAUTHN.TIMEOUT,
      attestationType: 'none',
      excludeCredentials: existingPasskeys,
      authenticatorSelection: {
        residentKey: 'preferred',
        requireResidentKey: false, // Don't require it, but prefer it
        userVerification: APP_CONFIG.WEBAUTHN.USER_VERIFICATION,
        // Don't specify authenticatorAttachment to allow both platform and cross-platform
      },
      supportedAlgorithmIDs: [-7, -257], // ES256, RS256
    };

    const registrationOptions = await generateRegistrationOptions(options);

    // Store challenge in database
    await prisma.challenge.create({
      data: {
        challenge: registrationOptions.challenge,
        userId: user.id,
        type: 'registration',
        expiresAt: getChallengeExpiration(),
      },
    });

    return res.json(registrationOptions);
  } catch (err) {
    console.error('Passkey registration start error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Completes passkey registration by verifying the credential
 * Route: POST /passkey/register/complete
 */
export const completePasskeyRegistration = async (req: AuthenticatedRequest, res: Response) => {
  const parse = passkeyRegistrationCompleteSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }

  const { credential, name } = parse.data;
  const userId = req.userId;
  
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Parse client data to get challenge
    let clientDataJSON: any;
    try {
      clientDataJSON = JSON.parse(Buffer.from(credential.response.clientDataJSON, 'base64url').toString());
    } catch (e) {
      return res.status(400).json({ error: 'Invalid client data' });
    }

    const expectedChallenge = clientDataJSON.challenge;
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No challenge found in client data' });
    }

    // Verify challenge exists in database and is valid
    const challengeRecord = await prisma.challenge.findUnique({
      where: { challenge: expectedChallenge },
    });

    if (!challengeRecord) {
      return res.status(400).json({ error: 'Challenge not found or expired' });
    }

    if (challengeRecord.expiresAt < new Date()) {
      // Clean up expired challenge
      await prisma.challenge.delete({ where: { id: challengeRecord.id } });
      return res.status(400).json({ error: 'Challenge has expired' });
    }

    if (challengeRecord.type !== 'registration' || challengeRecord.userId !== user.id) {
      return res.status(400).json({ error: 'Invalid challenge for this operation' });
    }

    const verification: VerifyRegistrationResponseOpts = {
      response: credential as RegistrationResponseJSON,
      expectedChallenge,
      expectedOrigin: APP_CONFIG.WEBAUTHN.ORIGIN,
      expectedRPID: APP_CONFIG.WEBAUTHN.RP_ID,
      requireUserVerification: APP_CONFIG.WEBAUTHN.USER_VERIFICATION === 'required',
    };

    const verificationResponse = await verifyRegistrationResponse(verification);

    if (!verificationResponse.verified || !verificationResponse.registrationInfo) {
      return res.status(400).json({ error: 'Passkey registration verification failed' });
    }

    const registrationInfo = verificationResponse.registrationInfo!;
    const credentialPublicKey = registrationInfo.credential.publicKey;
    const counter = registrationInfo.credential.counter;
    const credentialDeviceType = registrationInfo.credentialDeviceType;
    const mappedDeviceType: DeviceType =
      credentialDeviceType === 'singleDevice'
        ? DeviceType.single_device
        : credentialDeviceType === 'multiDevice'
        ? DeviceType.cross_platform
        : DeviceType.unknown;
    const credentialBackedUp = registrationInfo.credentialBackedUp;

    // Check if credential already exists
    const existingPasskey = await prisma.passkey.findUnique({
      where: { credentialId: credential.id },
    });

    if (existingPasskey) {
      return res.status(409).json({ error: 'This passkey is already registered' });
    }

    // Save the passkey to database
    // Store credential.id directly since that's what the client sends back during authentication
    const credentialIdToStore = credential.id;
    
    const passkey = await prisma.passkey.create({
      data: {
        userId: user.id,
        credentialId: credentialIdToStore,
        publicKey: Buffer.from(credentialPublicKey).toString('base64url'),
        counter: BigInt(counter),
        deviceType: mappedDeviceType,
        backedUp: credentialBackedUp,
        transports: credential.response.transports || [],
        name: name || `Passkey ${new Date().toLocaleDateString()}`,
      },
    });

    // Clean up used challenge
    await prisma.challenge.delete({ where: { id: challengeRecord.id } });

    return res.status(201).json({
      message: 'Passkey registered successfully',
      passkey: {
        id: passkey.id,
        name: passkey.name,
        createdAt: passkey.createdAt,
        deviceType: passkey.deviceType,
        backedUp: passkey.backedUp,
      },
    });
  } catch (err) {
    console.error('Passkey registration complete error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Starts passkey authentication process by generating challenge options
 * Route: POST /passkey/authenticate/start
 */
export const startPasskeyAuthentication = async (req: Request, res: Response) => {
  const parse = passkeyAuthenticationStartSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }

  const { email } = parse.data;

  try {
    let allowCredentials: { id: string; type: 'public-key'; transports?: AuthenticatorTransport[] }[] = [];

    // If email is provided, get user's passkeys for allowCredentials
    // However, we should be more permissive to allow for better UX
    if (email) {
      const user = await prisma.user.findUnique({
        where: { email },
        include: { passkeys: true },
      });

      if (user && user.passkeys.length > 0) {
        allowCredentials = user.passkeys.map(passkey => ({
          id: passkey.credentialId,
          type: 'public-key' as const,
          transports: passkey.transports as AuthenticatorTransport[],
        }));
      } else {
        // Don't set allowCredentials - let the authenticator handle discoverable credentials
      }
    }

    const options: GenerateAuthenticationOptionsOpts = {
      timeout: APP_CONFIG.WEBAUTHN.TIMEOUT,
      // Only set allowCredentials if we found specific credentials and email was provided
      // This allows for better discoverable credential support
      allowCredentials: (email && allowCredentials.length > 0) ? allowCredentials : undefined,
      userVerification: APP_CONFIG.WEBAUTHN.USER_VERIFICATION,
      rpID: APP_CONFIG.WEBAUTHN.RP_ID,
    };

    const authenticationOptions = await generateAuthenticationOptions(options);

    // Store challenge in database
    await prisma.challenge.create({
      data: {
        challenge: authenticationOptions.challenge,
        email,
        type: 'authentication',
        expiresAt: getChallengeExpiration(),
      },
    });

    return res.json(authenticationOptions);
  } catch (err) {
    console.error('Passkey authentication start error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Completes passkey authentication by verifying the assertion
 * Route: POST /passkey/authenticate/complete
 */
export const completePasskeyAuthentication = async (req: Request, res: Response) => {
  const parse = passkeyAuthenticationCompleteSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }

  const { credential } = parse.data;

  try {
    // Parse client data to get challenge
    let clientDataJSON: any;
    try {
      clientDataJSON = JSON.parse(Buffer.from(credential.response.clientDataJSON, 'base64url').toString());
    } catch (e) {
      return res.status(400).json({ error: 'Invalid client data' });
    }

    const expectedChallenge = clientDataJSON.challenge;
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No challenge found in client data' });
    }

    // Verify challenge exists in database and is valid
    const challengeRecord = await prisma.challenge.findUnique({
      where: { challenge: expectedChallenge },
    });

    if (!challengeRecord) {
      return res.status(400).json({ error: 'Challenge not found or expired' });
    }

    if (challengeRecord.expiresAt < new Date()) {
      // Clean up expired challenge
      await prisma.challenge.delete({ where: { id: challengeRecord.id } });
      return res.status(400).json({ error: 'Challenge has expired' });
    }

    if (challengeRecord.type !== 'authentication') {
      return res.status(400).json({ error: 'Invalid challenge for this operation' });
    }

    // Find the passkey in the database
    // The credential.id from the client is already base64url encoded
    const passkey = await prisma.passkey.findUnique({
      where: { credentialId: credential.id },
      include: { user: true },
    });


    if (!passkey) {
      return res.status(401).json({ error: 'Passkey not found' });
    }

    const verification = {
      response: credential as AuthenticationResponseJSON,
      expectedChallenge,
      expectedOrigin: APP_CONFIG.WEBAUTHN.ORIGIN,
      expectedRPID: APP_CONFIG.WEBAUTHN.RP_ID,
      credential: {
        id: passkey.credentialId,
        publicKey: new Uint8Array(Buffer.from(passkey.publicKey, 'base64url')),
        counter: Number(passkey.counter),
        transports: passkey.transports as ('ble' | 'hybrid' | 'internal' | 'nfc' | 'usb')[],
      },
      requireUserVerification: APP_CONFIG.WEBAUTHN.USER_VERIFICATION === 'required',
    };

    const verificationResponse = await verifyAuthenticationResponse(verification);

    if (!verificationResponse.verified) {
      return res.status(401).json({ error: 'Passkey authentication verification failed' });
    }

    // Update counter and last used
    await prisma.passkey.update({
      where: { id: passkey.id },
      data: {
        counter: BigInt(verificationResponse.authenticationInfo?.newCounter || 0),
        lastUsed: new Date(),
      },
    });

    // Clean up used challenge
    await prisma.challenge.delete({ where: { id: challengeRecord.id } });

    // Generate JWT tokens (similar to regular login)
    const accessToken = jwt.sign(
      { userId: passkey.user.id },
      APP_CONFIG.JWT.SECRET,
      { expiresIn: APP_CONFIG.JWT.EXPIRES_IN } as jwt.SignOptions
    );

    // Generate and store refresh token
    const refreshToken = crypto.randomUUID();
    const refreshTokenExpiry = new Date();
    refreshTokenExpiry.setTime(refreshTokenExpiry.getTime() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: passkey.user.id,
        expiresAt: refreshTokenExpiry,
      },
    });

    return res.status(200).json({
      message: 'Passkey authentication successful',
      accessToken,
      refreshToken,
      user: {
        id: passkey.user.id,
        email: passkey.user.email,
        twoFactorEnabled: passkey.user.twoFactorEnabled,
      },
    });
  } catch (err) {
    console.error('Passkey authentication complete error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Lists all passkeys for the authenticated user
 * Route: GET /passkey/list
 */
export const listPasskeys = async (req: AuthenticatedRequest, res: Response) => {
  const userId = req.userId;
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const passkeys = await prisma.passkey.findMany({
      where: { userId },
      select: {
        id: true,
        name: true,
        deviceType: true,
        backedUp: true,
        transports: true,
        createdAt: true,
        lastUsed: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    return res.json({ passkeys });
  } catch (err) {
    console.error('List passkeys error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Deletes a passkey for the authenticated user
 * Route: DELETE /passkey/:id
 */
export const deletePasskey = async (req: AuthenticatedRequest, res: Response) => {
  const { id: passkeyId } = req.params;
  const parse = passkeyDeleteSchema.safeParse({ ...req.body, passkeyId });
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }

  const { password } = parse.data;
  const userId = req.userId;

  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    // Verify user and password
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Find and delete the passkey
    const passkey = await prisma.passkey.findFirst({
      where: { id: passkeyId, userId },
    });

    if (!passkey) {
      return res.status(404).json({ error: 'Passkey not found' });
    }

    await prisma.passkey.delete({
      where: { id: passkeyId },
    });

    return res.json({ message: 'Passkey deleted successfully' });
  } catch (err) {
    console.error('Delete passkey error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Renames a passkey for the authenticated user
 * Route: PATCH /passkey/:id/rename
 */
export const renamePasskey = async (req: AuthenticatedRequest, res: Response) => {
  const { id: passkeyId } = req.params;
  const parse = passkeyRenameSchema.safeParse({ ...req.body, passkeyId });
  if (!parse.success) {
    return res.status(400).json({ error: z.flattenError(parse.error) });
  }

  const { name } = parse.data;
  const userId = req.userId;

  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    // Find and update the passkey
    const passkey = await prisma.passkey.findFirst({
      where: { id: passkeyId, userId },
    });

    if (!passkey) {
      return res.status(404).json({ error: 'Passkey not found' });
    }

    const updatedPasskey = await prisma.passkey.update({
      where: { id: passkeyId },
      data: { name },
      select: {
        id: true,
        name: true,
        deviceType: true,
        backedUp: true,
        transports: true,
        createdAt: true,
        lastUsed: true,
      },
    });

    return res.json({
      message: 'Passkey renamed successfully',
      passkey: updatedPasskey,
    });
  } catch (err) {
    console.error('Rename passkey error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};