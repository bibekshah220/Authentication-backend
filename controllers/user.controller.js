import sanitize from "mongo-sanitize";
import TryCatch from "../middlewares/tryCatch.js"
import { registerSchema } from "../config/zod.js";

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

  return res.json({
    name,
    email,
    password,
  });
});
