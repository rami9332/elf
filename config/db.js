import mongoose from "mongoose";

export const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 15000,
    });
    console.log("✅ MongoDB verbunden");
  } catch (err) {
    console.error("❌ MongoDB-Verbindungsfehler:", err.message);
    process.exit(1);
  }
};