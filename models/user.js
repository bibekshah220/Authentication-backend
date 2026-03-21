import mongoose from "mongoose";

const schema = mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true, 
        unique:true
    },
    password:{  
        type:String,
        required:true
    },
    role: {
        type: String,
        default: "user",
    },

},{
    timestamps:true
});


export const user= mongoose.model("User", schema);  