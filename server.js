import express from 'express';
import dotenv from 'dotenv';
import { registerUser } from './controllers/user.controller.js';
import sanitize from 'mongo-sanitize';


dotenv.config({ path: './.env' });    

console.log('MONGO_URI:', process.env.MONGO_URI);
console.log('PORT:', process.env.PORT);

import connectDB from './config/db.js';

await connectDB();




const app = express();
// middlewares
app.use(express.json());

// import routes
import userRoutes from './routes/user.js';

// using routes
app.use("/api/v1", userRoutes);

router.post("/register", registerUser);


const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

