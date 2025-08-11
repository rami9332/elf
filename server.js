// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import morgan from "morgan";

// Routen
import authRoutes from "./routes/auth.js";
import profileRoutes from "./routes/profile.js";
import uploadRoutes from "./routes/upload.js";

dotenv.config();

const app = express();

/* ------------------------- Core Middleware ------------------------- */

// Body-Parser
app.use(express.json({ limit: "2mb" }));

// Logging (nur lokal/Dev)
if (process.env.NODE_ENV !== "production") {
  app.use(morgan("dev"));
}

// CORS – offen (für lokale Tests / Render okay)
const corsOptions = {
  origin: (_origin, cb) => cb(null, true),
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

/* --------------------------- DB-Verbindung ------------------------- */

const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/cyp";
const PORT = Number(process.env.PORT) || 4000;

// Wichtig: kein Query-Buffering während Verbindungsaufbau
mongoose.set("bufferCommands", false);
mongoose.set("strictQuery", true);

// nützliche Logs
const masked = (MONGO_URI || "").replace(/:\/\/([^:]+):[^@]+@/, "://$1:****@");
console.log("🔧 Using MONGO_URI:", masked);

mongoose.connection.on("connected", () => console.log("✅ MongoDB verbunden"));
mongoose.connection.on("error", (err) => console.error("❌ Mongo Error:", err.message));
mongoose.connection.on("disconnected", () => console.warn("ℹ️ Mongo disconnected"));

/* ------------------------------- Routes ---------------------------- */

// Healthcheck
app.get("/api/health", (req, res) => {
  res.json({ ok: true, env: process.env.NODE_ENV || "development" });
});

// Optionaler DB-Check (hilft beim Debuggen)
app.get("/api/dbcheck", async (req, res) => {
  try {
    const state = mongoose.connection.readyState; // 0=disc,1=conn,2=conn'ing,3=disc'ing
    let collections = [];
    let dbName = null;
    if (state === 1 && mongoose.connection.db) {
      dbName = mongoose.connection.name;
      const cols = await mongoose.connection.db.listCollections().toArray();
      collections = cols.map((c) => c.name).sort();
    }
    res.json({ ok: state === 1, state, db: dbName, collections });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

// API
app.use("/api/auth", authRoutes);
app.use("/api/profile", profileRoutes);
app.use("/api/upload", uploadRoutes);

/* -------------------------- 404 & Fehler --------------------------- */

// 404
app.use((req, res) => {
  res.status(404).json({
    ok: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
});

// Zentraler Fehler-Handler
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error("💥 Fehler:", err);
  const status = err.status || 500;
  res.status(status).json({
    ok: false,
    message: err.message || "Internal Server Error",
  });
});

/* ------------------------------ Start ------------------------------ */

// WICHTIG: Server erst starten, wenn Mongo steht
async function start() {
  try {
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 30000, // großzügiger, damit Render-Kaltstart klappt
      socketTimeoutMS: 45000,
    });

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 API running on http://0.0.0.0:${PORT}`);
    });
  } catch (err) {
    console.error("❌ MongoDB Verbindung fehlgeschlagen:", err.message);
    // Auf Render exit, damit ein Restart probiert wird
    process.exit(1);
  }
}

start();