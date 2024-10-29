import mongoose from "mongoose";
import dotenv from 'dotenv';

// Cargar las variables del archivo .env
dotenv.config();

export const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log("DB is connected - Conectado a la DB MongoAtlas");
    } catch (error) {
        console.log(error);
    }
};
