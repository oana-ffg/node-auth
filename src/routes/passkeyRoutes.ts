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
import { authRateLimit } from '../middleware/rateLimitMiddleware';

const router = express.Router();

// Passkey registration routes (require authentication)
router.post('/register/start', verifyToken, startPasskeyRegistration);
router.post('/register/complete', verifyToken, completePasskeyRegistration);

// Passkey authentication routes (public)
router.post('/authenticate/start', authRateLimit, startPasskeyAuthentication);
router.post('/authenticate/complete', authRateLimit, completePasskeyAuthentication);

// Passkey management routes (require authentication)
router.get('/list', verifyToken, listPasskeys);
router.delete('/:id', verifyToken, deletePasskey);
router.patch('/:id/rename', verifyToken, renamePasskey);

export default router;