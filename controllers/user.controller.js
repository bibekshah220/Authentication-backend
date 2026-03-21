import sanitize from "mongo-sanitize";
import TryCatch from "../middlewares/tryCatch.js"
import { registerSchema } from "../config/zod.js";

export const registerUser = TryCatch(async(req, res) => {

    const sanitizedData = sanitize(req.body);
    const validation = registerSchema.safeParse(sanitizedbody);

res.json({
    name,
    email,
    password
});

})
