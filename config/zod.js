import {z} from "zod";


export const registerSchema = z.object({
    name: z.string().min(3, "Name must be at least 3 characters long"),
    email: z.string().email("Invalid email address"),
   password: z
  .string()
  .min(8, "Password must be at least 8 characters long")
  .regex(/[a-z]/, "At least one lowercase letter required")
  .regex(/[A-Z]/, "At least one uppercase letter required")
  .regex(/[0-9]/, "At least one number required")
  .regex(/[@$!%*?&]/, "At least one special character required"),
});

export const loginSchema = z.object({
    email: z.string().email("Invalid email address"),
    password: z.string().min(8, "Password must be at least 8 characters long")
  .regex(/[a-z]/, "At least one lowercase letter required")
  .regex(/[A-Z]/, "At least one uppercase letter required")
  .regex(/[0-9]/, "At least one number required")
  .regex(/[@$!%*?&]/, "At least one special character required"),
});

