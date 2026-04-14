import express from 'express';
import {
	registerUser,
	verifyUser,
	loginUser,
	requestOtp,
	verifyOtp,
	refreshToken,
	logoutUser,
	myProfile,
	updateProfile,
	changePassword,
	forgotPassword,
	resetPassword,
	deleteAccount,
	getAllUsers,
	getUserById,
	updateUserByAdmin,
	deleteUserByAdmin
} from '../controllers/user.controller.js';
import { isAuth, isAdmin } from '../middlewares/isAuth.js';

const router = express.Router();


// Auth and user routes
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
router.post("/delete-account", isAuth, deleteAccount);
// Admin routes
router.get("/admin/users", isAuth, isAdmin, getAllUsers);
router.get("/admin/user/:id", isAuth, isAdmin, getUserById);
router.put("/admin/update-user/:id", isAuth, isAdmin, updateUserByAdmin);
router.delete("/admin/delete-user/:id", isAuth, isAdmin, deleteUserByAdmin);

export default router;

