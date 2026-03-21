import sanitize from "mongo-sanitize";
import TryCatch from "../middlewares/tryCatch.js"
import { registerSchema } from "../config/zod.js";

export const registerUser = TryCatch(async(req, res) => {

    const sanitizedData = sanitize(req.body);
    const validation = registerSchema.safeParse(sanitizedbody);

    const zodError = validation.error;
 
    if(!validation.success) {
        return res.status(400).json({
            message: zodError,
        });
    }

    const { name, email, password } = validation.data;





res.json({
    name,
    email,
    password
});

})
