import sanitize from "mongo-sanitize";
import TryCatch from "../middlewares/tryCatch.js"
import { registerSchema } from "../config/zod.js";
import { redisClient } from "../server.js";
import { user } from "../models/user.js";
import bcrypt from "bcrypt";    
import crypto from "crypto";    
import sendEmail from "../config/sendMail.js";
import { getVerifyEmailHtml } from "../config/html.js";

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
