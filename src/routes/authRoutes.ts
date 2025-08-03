import express from "express";
import { confirm2FA, generate2FASecret, loginUser, loginWith2FA, refreshTokenHandler, registerUser, reset2FA, disable2FA } from "../controllers/authController";
import { verifyToken } from "../middleware/authMiddleware";

const router: express.Router = express.Router(); 

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/login/2fa', loginWith2FA);
router.post('/refresh', refreshTokenHandler);
router.post('/2fa/generate', verifyToken, generate2FASecret);
router.post('/2fa/confirm', verifyToken, confirm2FA);
router.post('/2fa/reset', verifyToken, reset2FA);
router.post('/2fa/disable', verifyToken, disable2FA);

export default router;