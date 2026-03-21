import express from 'express';
import { registerUser } from '../controllers/user.controller.js';

const router = express.Router();

// Register route
router.post("/register", registerUser);

router.post("/verify/:token", verifyUser);

export default router;

