import mongoose from "mongoose";

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      dbName: "Authentication ",
    });
    console.log("Connected to the database successfully");  
  } catch (error) {
    console.log("Failed to connect to the database:", error.message);
    console.log("Connection string used:", process.env.MONGO_URI);
  }
};

 export default connectDB;