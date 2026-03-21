import express from 'express';
import dotenv from 'dotenv';

dotenv.config({ path: './.env' });    

console.log('MONGO_URI:', process.env.MONGO_URI);
console.log('PORT:', process.env.PORT);

import connectDB from './config/db.js';

await connectDB();




const app = express();


const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

