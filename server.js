// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";

// Routen
import authRoutes from "./routes/auth.js";
import profileRoutes from "./routes/profile.js";
import uploadRoutes from "./routes/upload.js";

dotenv.config();

const app = express();

/* -------------------------- Basis-Middleware -------------------------- */

// Body-Parser
app.use(express.json({ limit: "2mb" }));

// CORS – offen (für lokale Tests / Render-Proxy okay)
const corsOptions = {
  origin: (_origin, cb) => cb(null, true),
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

/* ---------------------------- MongoDB Atlas --------------------------- */

const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb://127.0.0.1:27017/cyp"; // Fallback für lokal

mongoose.set("strictQuery", true);

async function connectDB() {
  try {
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 15000,
    });
    console.log("✅ MongoDB verbunden");
  } catch (err) {
    console.error("❌ MongoDB Verbindung fehlgeschlagen:", err.message);
    // Auf Render lieber NICHT hart beenden – Logs sehen & später retryen:
    // process.exit(1);
  }
}
connectDB();

/* ------------------------------- Routes ------------------------------- */

// Healthcheck (für Render)
app.get("/api/health", (req, res) => {
  res.json({ ok: true, env: process.env.NODE_ENV || "development" });
});

// Optional: schneller DB-Check (zeigt Status & Collections)
app.get("/api/dbcheck", async (req, res, next) => {
  try {
    const state = mongoose.connection.readyState; // 1=connected, 2=connecting, 0=disconnected, 3=disconnecting
    let collections = [];
    if (state === 1 && mongoose.connection.db) {
      const cols = await mongoose.connection.db
        .listCollections()
        .toArray();
      collections = cols.map((c) => c.name).sort();
    }
    res.json({
      ok: state === 1,
      state,
      db: mongoose.connection.name || null,
      collections,
    });
  } catch (err) {
    next(err);
  }
});

// API-Routen
app.use("/api/auth", authRoutes);
app.use("/api/profile", profileRoutes);
app.use("/api/upload", uploadRoutes);

/* -------------------------- 404 & Fehler-Handler ---------------------- */

// 404
app.use((req, res) => {
  res.status(404).json({
    ok: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
});

// Zentraler Fehler-Handler
app.use((err, _req, res, _next) => {
  console.error("💥 Fehler:", err);
  const status = err.status || 500;
  res.status(status).json({
    ok: false,
    message: err.message || "Internal Server Error",
  });
});

/* -------------------------------- Start ------------------------------- */

const PORT = Number(process.env.PORT) || 4000; // Render liefert PORT

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 API running on http://0.0.0.0:${PORT}`);
});