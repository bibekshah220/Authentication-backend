import express from 'express';
import dotenv from 'dotenv';
import { registerUser } from './controllers/user.controller.js';

import { createClient } from 'redis';


dotenv.config({ path: './.env' });    

console.log('MONGO_URI:', process.env.MONGO_URI);
console.log('PORT:', process.env.PORT);

import connectDB from './config/db.js';

await connectDB();

const redisUrl = process.env.REDIS_URL;

if (!redisUrl) {
  console.error('missing REDIS_URL in environment variables');
  process.exit(1);
}

export const redisClient = createClient({
  url: redisUrl,
});

redisClient.connect().then(() => {
  console.log('Connected to Redis successfully');
}).catch((error) => {
  console.error('Failed to connect to Redis:', error.message);
  process.exit(1);
}); 

const app = express();
// middlewares
app.use(express.json());

// import routes
import userRoutes from './routes/user.js';

// using routes
app.use("/api/v1", userRoutes);

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

