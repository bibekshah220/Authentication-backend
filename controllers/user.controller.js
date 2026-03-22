import sanitize from "mongo-sanitize";
import TryCatch from "../middlewares/tryCatch.js"
import { registerSchema } from "../config/zod.js";
import { redisClient } from "../server.js";
import { user } from "../models/user.js";
import bcrypt from "bcrypt";    
import crypto from "crypto";    
import sendEmail from "../config/sendMail.js";
import { getOtpHtml, getVerifyEmailHtml } from "../config/html.js";
import { generateToken } from "../config/generateToken.js";

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

       firstErrorMessage = allErrors[0]?.message||"validation Error";
    }

    return res.status(400).json({
      message: firstErrorMessage,
      errors: allErrors,
    });
  }

  const { name, email, password } = validation.data;

  const ratemitKey = `register-rate-limit${req.ip}:${email}`;

  if(await redisClient.get(ratemitKey)){
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

await redisClient.set(verifykey, dataStore, {EX: 300})

const subject = "verify your email for account creation";
const html= getVerifyEmailHtml({
    email, token: verfiedtoken,
})

await sendEmail(email, subject, html);

await redisClient.set(ratemitKey, "true", {EX: 60});

  return res.json({
   message: "If your email is valid, a verification link has been sent. it will expire in 5 minutes",
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

  return res.status(200).json({
    message: "Login successful",
    user: {
      id: existingUser._id,
      name: existingUser.name,
      email: existingUser.email,
    },
  });

  const user = await user.findOne({ email });
  if (!user) {
    return res.status(400).json({
      message: "Invalid email or password",
    });
  }
const comparePassword = await bcrypt.compare(password, user.password);
if (!comparePassword) {
    return res.status(400).json({
      message: "Invalid email or password",
    });
  }

  const otp = Math.floor(10000 + Math.random() * 90000).toString();

  const otpKey = `otp:${email}`;
 await redisClient.set(otpKey, JSON.stringify({ otp, email }), { EX: 300 });


const subject = "Your OTP for login";
const html = getOtpHtml({email, otp})

await sendEmail(email, subject, html);

await redisClient.set(ratelimitKey, "true", { EX: 60 });

res.json({
  message: "if your email is valid, an OTP has been sent to your email address. it will expire in 5 minutes",
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

  let user = await user.findOne({ email });

const tokenData = await generateToken(user._id, res);

res.status(200).json({
  message: `welcome ${user.name}`,
  user,
});



});
