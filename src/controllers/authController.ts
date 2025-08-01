import { Request, Response } from 'express'; // Import types for request and response objects from Express
import bcrypt from 'bcrypt'; // Import bcrypt for hashing and comparing passwords securely
import { PrismaClient } from '../generated/prisma'; // Import Prisma client for database interactions
import crypto from 'crypto'; // Add this import at the top
import jwt from 'jsonwebtoken'; // Import jsonwebtoken for creating and verifying JWT tokens
import dotenv from 'dotenv'; // Import dotenv to load environment variables from .env file
import { registerSchema, loginSchema } from '../schemas/authSchemas'; // Import our custom auth schemas
import { z } from 'zod';

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

    // Hash the password using bcrypt with 10 salt rounds for security
    const hashedPassword = await bcrypt.hash(password, 10); // 10 = salt rounds

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

    // Create a JWT token containing the user's ID, signed with the secret key
    // The token expires based on the JWT_EXPIRES_IN environment variable or defaults to 15 minutes
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET as string,
      { expiresIn: process.env.JWT_EXPIRES_IN || '15m' } as jwt.SignOptions
    );

    // Generate and store refresh token in DB with 7-day expiration
    const refreshToken = crypto.randomUUID();
    const refreshTokenExpiry = new Date();
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7); // 7 days expiration

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
    });
  } catch (err) {
    // Log any errors and respond with internal server error
    console.error(err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
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
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required.' });
  }

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
    newExpiry.setDate(newExpiry.getDate() + 7);

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
      process.env.JWT_SECRET as string,
      { expiresIn: process.env.JWT_EXPIRES_IN || '15m' } as jwt.SignOptions
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