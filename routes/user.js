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
router.get("/profile", isAuth, myProfile);
router.post("/update-profile", isAuth, updateProfile);
router.post("/change-password", isAuth, changePassword);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);   



export default router;

