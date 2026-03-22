import { generateAccessToken, verifyRefreshToken } from "../config/generateToken.js";
import { loginSchema } from "../config/zod.js";

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

  const ratemitKey = `register-rate-limit${req.ip}:${email}`;

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
  // Store as JSON string
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
  const user = req.user;
  res.json({
    message: "User profile fetched successfully",
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
    },
  });
});

export const refreshToken = TryCatch(async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({
      message: "Refresh token not provided",
    });
  }
});

const decoded = await verifyRefreshToken(refreshToken);
if (!decoded) {
  return res.status(401).json({
    message: "Invalid refresh token",
  });
}

  generateAccessToken(decoded.id, res);
  return res.json({
    message: "Access token refreshed successfully",
  });
