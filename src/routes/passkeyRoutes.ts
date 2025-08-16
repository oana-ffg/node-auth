import express from 'express';
import {
  startPasskeyRegistration,
  completePasskeyRegistration,
  startPasskeyAuthentication,
  completePasskeyAuthentication,
  listPasskeys,
  deletePasskey,
  renamePasskey,
} from '../controllers/passkeyController';
import { verifyToken } from '../middleware/authMiddleware';
import { authRateLimit, generalRateLimit } from '../middleware/rateLimitMiddleware';

const router = express.Router();

// Passkey registration routes (require authentication)
router.post('/register/start', verifyToken, generalRateLimit, startPasskeyRegistration);
router.post('/register/complete', verifyToken, generalRateLimit, completePasskeyRegistration);

// Passkey authentication routes (public)
router.post('/authenticate/start', authRateLimit, startPasskeyAuthentication);
router.post('/authenticate/complete', authRateLimit, completePasskeyAuthentication);

// Passkey management routes (require authentication)
router.get('/list', verifyToken, generalRateLimit, listPasskeys);
router.delete('/:id', verifyToken, generalRateLimit, deletePasskey);
router.patch('/:id/rename', verifyToken, generalRateLimit, renamePasskey);

export default router;