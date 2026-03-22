import jwt from "jsonwebtoken";
import { JWT_SECRET } from "../config/index.js";



export const generateToken = async(id,res) =>{
    const accessToken = jwt.sign({id}, JWT_SECRET, { expiresIn: process.env.JWT_SECRET,
        expiresIn: "15d",

     });

     const refreshToken = jwt.sign({id}, process.env.REFRESH_SECRET, {
        expiresIn: "30d",
     });   

const refreshTokenkey = `refreshToken:${id}`;
await redisClient.setEx(refreshTokenkey, 30 * 24 * 60 * 60, refreshToken);

res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 15 * 24 * 60 * 60 * 1000,
}); 
res.cookie("refreshToken", refreshToken, {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: "none",
    secure: true,
});

return { accessToken, refreshToken };
}