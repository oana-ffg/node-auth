

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { APP_CONFIG } from '../constants';

// Extend Request to include the decoded user
export interface AuthenticatedRequest extends Request {
  userId?: string;
}

/**
 * Middleware to verify JWT token from the Authorization header.
 * If valid, attaches decoded user info to req.userId and calls next().
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

  try {
    const decoded = jwt.verify(token, APP_CONFIG.JWT.SECRET) as { userId: string };
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};