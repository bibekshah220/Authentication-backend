import sanitize from "mongo-sanitize";
import TryCatch from "../middlewares/tryCatch.js";
import { registerSchema, loginSchema } from "../config/zod.js";
import { redisClient } from "../server.js";
import { user } from "../models/user.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import sendEmail from "../config/sendMail.js";
import { getOtpHtml, getVerifyEmailHtml } from "../config/html.js";
import { generateToken, generateAccessToken, verifyRefreshToken } from "../config/generateToken.js";
// Add missing imports for route dependencies
import { revokeRefreshToken } from "../config/generateToken.js";
import { isAuth } from "../middlewares/isAuth.js";
import { isAdmin } from "../middlewares/isAuth.js";
// Reset password implementation
export const resetPassword = TryCatch(async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;
  if (!token || !newPassword) {
    return res.status(400).json({ message: "Token and new password are required" });
  }
  const resetKey = `reset:${token}`;
  const userData = await redisClient.get(resetKey);
  if (!userData) {
    return res.status(400).json({ message: "Invalid or expired reset token" });
  }
  const { id } = JSON.parse(userData);
  const foundUser = await user.findById(id);
  if (!foundUser) {
    return res.status(404).json({ message: "User not found" });
  }
  foundUser.password = await bcrypt.hash(newPassword, 10);
  await foundUser.save();
  await redisClient.del(resetKey);
  await redisClient.del(`user:${foundUser._id}`);
  return res.json({ message: "Password reset successfully" });
});

// Delete account implementation
export const deleteAccount = TryCatch(async (req, res) => {
  const userObj = req.user;
  if (!userObj) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  await user.deleteOne({ _id: userObj._id });
  await redisClient.del(`user:${userObj._id}`);
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  return res.json({ message: "Account deleted successfully" });
});

export const requestOtp = TryCatch(async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }
  const existingUser = await user.findOne({ email });
  if (!existingUser) {
    return res.status(400).json({ message: "User with this email does not exist" });
  }
  const otp = Math.floor(10000 + Math.random() * 90000).toString();
  const otpKey = `otp:${email}`;
  await redisClient.set(otpKey, JSON.stringify({ otp, email }), { EX: 300 });
  const subject = "Your OTP for login";
  const html = getOtpHtml({ email, otp });
  await sendEmail(email, subject, html);
  return res.json({
    message: "An OTP has been sent to your email address. It will expire in 5 minutes",
  });
});
// Get all users (admin only)
export const getAllUsers = TryCatch(async (req, res) => {
  const users = await user.find().select("-password");
  res.json({ users });
});
// Get user by ID (admin only)
export const getUserById = TryCatch(async (req, res) => {
  const { id } = req.params;
  const foundUser = await user.findById(id).select("-password");
  if (!foundUser) {
    return res.status(404).json({ message: "User not found" });
  }
  res.json({ user: foundUser });
});
// Update user by admin
export const updateUserByAdmin = TryCatch(async (req, res) => {
  const { id } = req.params;
  const { name, email, role } = req.body;
  const foundUser = await user.findById(id);
  if (!foundUser) {
    return res.status(404).json({ message: "User not found" });
  }
  if (name) foundUser.name = name;
  if (email) foundUser.email = email;
  if (role) foundUser.role = role;
  await foundUser.save();
  await redisClient.del(`user:${foundUser._id}`);
  res.json({ message: "User updated successfully", user: foundUser });
});
// Delete user by admin
export const deleteUserByAdmin = TryCatch(async (req, res) => {
  const { id } = req.params;
  const foundUser = await user.findById(id);
  if (!foundUser) {
    return res.status(404).json({ message: "User not found" });
  }
  await user.deleteOne({ _id: id });
  await redisClient.del(`user:${id}`);
  res.json({ message: "User deleted successfully" });
});

export const registerUser = TryCatch(async (req, res) => {
  const sanitizedData = sanitize(req.body);
  const validation = registerSchema.safeParse(sanitizedData);

  if (!validation.success) {
    const zodError = validation.error;
    let firstErrorMessage = "validation failed";
    let allErrors = [];

    if (zodError?.issues && Array.isArray(zodError.issues)) {
      allErrors = zodError.issues.map((issue) => ({
        fields: issue.path ? issue.path.join(".") : "unknown",
        message: issue.message || "validation error",
        code: issue.code,
      }));

      firstErrorMessage = allErrors[0]?.message || "validation Error";
    }

    return res.status(400).json({
      message: firstErrorMessage,
      errors: allErrors,
    });
  }

  const { name, email, password } = validation.data;

  const ratemitKey = `register-rate-limit:${req.ip}:${email}`;

  if (await redisClient.get(ratemitKey)) {
    return res.status(429).json({
      message: "Too many registration attempts. Please try again later.",
    });
  }

  const existingUser = await user.findOne({ email });

  if (existingUser) {
    return res.status(400).json({
      message: "User with this email already exists",
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const verfiedtoken = crypto.randomBytes(32).toString("hex");
  const verifykey = `verify:${verfiedtoken}`;
  const dataStore = {
    name,
    email,
    password: hashedPassword,
  };
  await redisClient.set(verifykey, JSON.stringify(dataStore), { EX: 300 });

  const subject = "verify your email for account creation";
  const html = getVerifyEmailHtml({
    email,
    token: verfiedtoken,
  });

  await sendEmail(email, subject, html);

  await redisClient.set(ratemitKey, "true", { EX: 60 });

  return res.json({
    message:
      "If your email is valid, a verification link has been sent. it will expire in 5 minutes",
  });
});

export const verifyUser = TryCatch(async (req, res) => {
  const { token } = req.params;
  if (!token) {
    return res.status(400).json({
      message: "Verification token is required",
    });
  }

  const verifykey = `verify:${token}`;
  const userData = await redisClient.get(verifykey);
  if (!userData) {
    return res.status(400).json({
      message: "Invalid or expired verification token",
    });
  }

  await redisClient.del(verifykey);
  let userdata;
  try {
    userdata = typeof userData === "string" ? JSON.parse(userData) : userData;
  } catch (err) {
    return res.status(500).json({
      message: "Failed to parse user data from verification token.",
    });
  }

  const existingUser = await user.findOne({ email: userdata.email });
  if (existingUser) {
    return res.status(400).json({
      message: "User with this email already exists",
    });
  }

  const newUser = new user({
    name: userdata.name,
    email: userdata.email,
    password: userdata.password,
  });
  await newUser.save();

  return res.status(201).json({
    message: "User verified and created successfully",
    user: {
      id: newUser._id,
      name: newUser.name,
      email: newUser.email,
    },
  });
});

export const loginUser = TryCatch(async (req, res) => {
  const sanitizedData = sanitize(req.body);
  const validation = loginSchema.safeParse(sanitizedData);

  if (!validation.success) {
    const zodError = validation.error;
    let firstErrorMessage = "validation failed";
    let allErrors = [];
    if (zodError?.issues && Array.isArray(zodError.issues)) {
      allErrors = zodError.issues.map((issue) => ({
        fields: issue.path ? issue.path.join(".") : "unknown",
        message: issue.message || "validation error",
        code: issue.code,
      }));
      firstErrorMessage = allErrors[0]?.message || "validation error";
    }
    return res.status(400).json({
      message: firstErrorMessage,
      errors: allErrors,
    });
  }

  const { email, password } = validation.data;
  const ratelimitKey = `login-rate-limit:${req.ip}:${email}`;

  if (await redisClient.get(ratelimitKey)) {
    return res.status(429).json({
      message: "Too many login attempts. Please try again later.",
    });
  }

  const existingUser = await user.findOne({ email });
  if (!existingUser) {
    await redisClient.set(ratelimitKey, "true", { EX: 60 });
    return res.status(400).json({
      message: "Invalid email or password",
    });
  }

  const isPasswordValid = await bcrypt.compare(password, existingUser.password);
  if (!isPasswordValid) {
    await redisClient.set(ratelimitKey, "true", { EX: 60 });
    return res.status(400).json({
      message: "Invalid email or password",
    });
  }

  await redisClient.del(ratelimitKey);

  // Instead of returning login success here, send OTP for 2FA
  const otp = Math.floor(10000 + Math.random() * 90000).toString();
  const otpKey = `otp:${email}`;
  await redisClient.set(otpKey, JSON.stringify({ otp, email }), { EX: 300 });
  const subject = "Your OTP for login";
  const html = getOtpHtml({ email, otp });
  await sendEmail(email, subject, html);
  await redisClient.set(ratelimitKey, "true", { EX: 60 });
  return res.json({
    message:
      "If your email is valid, an OTP has been sent to your email address. It will expire in 5 minutes",
  });
});

export const verifyOtp = TryCatch(async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({
      message: "please provide all details",
    });
  }

  const otpKey = `otp:${email}`;

  const storeotpstring = await redisClient.get(otpKey);
  if (!storeotpstring) {
    return res.status(400).json({
      message: "Invalid or expired OTP",
    });
  }

  const storeotp = JSON.parse(storeotpstring);
  if (storeotp.otp !== otp) {
    return res.status(400).json({
      message: "Invalid OTP",
    });
  }

  await redisClient.del(otpKey);

  let foundUser = await user.findOne({ email });
  if (!foundUser) {
    return res.status(400).json({
      message: "User not found",
    });
  }
  await generateToken(foundUser._id, res);
  res.status(200).json({
    message: `Welcome ${foundUser.name}`,
    user: {
      id: foundUser._id,
      name: foundUser.name,
      email: foundUser.email,
    },
  });
});

export const myProfile = TryCatch(async (req, res) => {
  const userObj = req.user;
  res.json({
    message: "User profile fetched successfully",
    user: {
      id: userObj._id,
      name: userObj.name,
      email: userObj.email,
    },
  });
});

export const refreshToken = TryCatch(async (req, res) => {
  const refreshTokenCookie = req.cookies.refreshToken;
  if (!refreshTokenCookie) {
    return res.status(401).json({
      message: "Refresh token not provided",
    });
  }
  const decoded = await verifyRefreshToken(refreshTokenCookie);
  if (!decoded) {
    return res.status(401).json({
      message: "Invalid refresh token",
    });
  }
  generateAccessToken(decoded.id, res);
  return res.json({
    message: "Access token refreshed successfully",
  });
});

export const logoutUser = TryCatch(async (req, res) => {
  const refreshTokenCookie = req.cookies.refreshToken;
  if (refreshTokenCookie) {
    const decoded = await verifyRefreshToken(refreshTokenCookie);
    if (decoded && typeof revokeRefreshToken === 'function') {
      await revokeRefreshToken(decoded);
    }
  }
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  return res.json({
    message: "Logged out successfully",
  });
});

export const updateProfile = TryCatch(async (req, res) => {
  const userObj = req.user;
  const { name } = req.body;  
  if (!name) {
    return res.status(400).json({
      message: "Name is required",
    });
  }
  userObj.name = name;
  await userObj.save();
  await redisClient.del(`user:${userObj._id}`);
  return res.json({
    message: "Profile updated successfully",
    user: {
      id: userObj._id,
      name: userObj.name,
      email: userObj.email,
    },
  });
});

export const changePassword = TryCatch(async (req, res) => {
  const userObj = req.user;
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({
      message: "Please provide old and new password",
    });
  } 
  const isOldPasswordValid = await bcrypt.compare(oldPassword, userObj.password);
  if (!isOldPasswordValid) {
    return res.status(400).json({
      message: "Old password is incorrect",
    });
  }
  userObj.password = await bcrypt.hash(newPassword, 10);
  await userObj.save();
  await redisClient.del(`user:${userObj._id}`);
  return res.json({
    message: "Password changed successfully",
  });
});

export const forgotPassword = TryCatch(async (req, res) => {
  const { email } = req.body; 
  if (!email) {
    return res.status(400).json({
      message: "Email is required",
    });
  } 
  const existingUser = await user.findOne({ email });
  if (!existingUser) {
    return res.status(400).json({
      message: "User with this email does not exist",
    });
  }
  const resetToken = crypto.randomBytes(32).toString("hex");
  const resetKey = `reset:${resetToken}`;
  await redisClient.set(resetKey, JSON.stringify({ id: existingUser._id }), { EX: 900 });   
  const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
  const subject = "Password Reset Request";
  const html = `<p>You requested a password reset. Click the link below to reset your password:</p><a href="${resetLink}">Reset Password</a><p>This link will expire in 15 minutes.</p>`;
  await sendEmail(email, subject, html);  
  return res.json({
    message: "Password reset link has been sent to your email if it exists in our system",
  });
} );  