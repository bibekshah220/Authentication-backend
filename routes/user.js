import express from 'express';
import { registerUser } from '../controllers/user.controller.js';

const router = express.Router();

// Register route
router.post("/register", registerUser);

router.post("/verify/:token", verifyUser);
router.post("/login", loginUser);
router.post("/request-otp", requestOtp);
router.post("/verify-otp", verifyOtp);
router.post("/refresh-token", refreshToken);
router.post("/logout", logoutUser);


export default router;

