import express from "express";
import { confirm2FA, generate2FASecret, loginUser, loginWith2FA, refreshTokenHandler, registerUser, reset2FA, disable2FA, deleteAccount } from "../controllers/authController";
import { verifyToken } from "../middleware/authMiddleware";
import { authRateLimit, twoFALimit } from "../middleware/rateLimitMiddleware";

const router: express.Router = express.Router(); 

router.post('/register', authRateLimit, registerUser);
router.post('/login', authRateLimit, loginUser);
router.post('/login/2fa', authRateLimit, loginWith2FA);
router.post('/refresh', refreshTokenHandler);
router.post('/2fa/generate', twoFALimit, verifyToken, generate2FASecret);
router.post('/2fa/confirm', twoFALimit, verifyToken, confirm2FA);
router.post('/2fa/reset', twoFALimit, verifyToken, reset2FA);
router.post('/2fa/disable', twoFALimit, verifyToken, disable2FA);
router.delete('/account', verifyToken, deleteAccount);

export default router;