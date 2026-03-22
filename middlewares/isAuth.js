import jwt from "jsonwebtoken";
import { redisClient } from "../server.js";
import { user as User } from "../models/user.js";

export const isAuth = async (req, res, next) => {
    try {
        const token = req.cookies.accessToken;
        if (!token) {
            return res.status(403).json({
                message: "Unauthorized: No token provided",
            });
        }

        const decodedData = jwt.verify(token, process.env.JWT_SECRET);
        if (!decodedData) {
            return res.status(400).json({
                message: "Token expired",
            });
        }

        const cacheUser = await redisClient.get(`user:${decodedData.id}`);
        if (cacheUser) {
            req.user = JSON.parse(cacheUser);
            return next();
        }

        const foundUser = await User.findById(decodedData.id).select("-password");
        if (!foundUser) {
            return res.status(404).json({
                message: "User not found",
            });
        }

        req.user = foundUser;
        await redisClient.set(`user:${decodedData.id}`, JSON.stringify(foundUser), "EX", 3600);
        return next();
    } catch (error) {
        return res.status(500).json({
            message: error.message,
        });
    }
};

