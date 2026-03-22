import jwt from "jsonwebtoken";
import { JWT_SECRET } from "../config/index.js";



export const generateToken = async(id,res) =>{
    const accessToken = jwt.sign({id}, JWT_SECRET, { expiresIn: process.env.JWT_SECRET,
        expiresIn: "15d",

     });

     const refreshToken = jwt.sign({id}, process.env.REFRESH_SECRET, {
        expiresIn: "30d",
     });    
}