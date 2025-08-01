

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';

// Extend Request to include the decoded user
export interface AuthenticatedRequest extends Request {
  user?: string | jwt.JwtPayload;
}

/**
 * Middleware to verify JWT token from the Authorization header.
 * If valid, attaches decoded user info to req.user and calls next().
 * If invalid or missing, sends a 401 Unauthorized response.
 */
export const verifyToken = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }

  const token = authHeader.split(' ')[1];
  console.log('JWT_SECRET:', process.env.JWT_SECRET);
  console.log('token:', token);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};