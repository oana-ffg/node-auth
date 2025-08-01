import express from "express";
import { loginUser, refreshTokenHandler, registerUser } from "../controllers/authController";

const router: express.Router = express.Router(); 

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/refresh', refreshTokenHandler);

export default router;