// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";

// Import Routes
import authRoutes from "./routes/auth.js";
import profileRoutes from "./routes/profile.js";
import uploadRoutes from "./routes/upload.js";

// Load environment variables
dotenv.config();

const app = express();

/* ------------------------- Core Middleware ------------------------- */

// JSON Body parser
app.use(express.json({ limit: "2mb" }));

// CORS – sehr offen für lokale Entwicklung
const corsOptions = {
  origin: (origin, cb) => cb(null, true), // alles erlauben
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

/* --------------------------- DB-Verbindung ------------------------- */

const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/cyp";

mongoose.set("strictQuery", true);

mongoose
  .connect(MONGO_URI, {
    serverSelectionTimeoutMS: 15000,
  })
  .then(() => console.log("✅ MongoDB verbunden"))
  .catch((err) => {
    console.error("❌ MongoDB Verbindung fehlgeschlagen:", err.message);
  });

/* ------------------------------- Routes ---------------------------- */

// Healthcheck
app.get("/api/health", (req, res) => {
  res.json({ ok: true, env: process.env.NODE_ENV || "development" });
});

// API routes
app.use("/api/auth", authRoutes);
app.use("/api/profile", profileRoutes);
app.use("/api/upload", uploadRoutes);

/* -------------------------- 404 & Fehler --------------------------- */

// 404 – Unbekannte Route
app.use((req, res) => {
  res.status(404).json({
    ok: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
});

// Zentrale Fehlerbehandlung
app.use((err, req, res, next) => {
  console.error("💥 Fehler:", err);
  const status = err.status || 500;
  res.status(status).json({
    ok: false,
    message: err.message || "Internal Server Error",
  });
});

/* ------------------------------ Start ------------------------------ */

const PORT = Number(process.env.PORT) || 4000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 API running on http://localhost:${PORT}`);
});