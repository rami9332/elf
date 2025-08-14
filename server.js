// server.js
// ============================================================================
// CYP Backend – Heavy-Duty Server Bootstrap (ESM)
// ----------------------------------------------------------------------------
// Features:
// - .env Config + sichere Defaults
// - Security: helmet, HPP, Rate Limits, Compression, Cookie-Parser
// - CORS (DEV offen; PROD via CLIENT_URL beschränken)
// - Request-ID Header + morgan Logging (skip für Health/Readiness)
// - Prometheus /metrics
// - Swagger /api/docs & /api/docs.json (scannt /routes/*.js & /routes/**/*.js)
// - Health/Readiness/DBCheck
// - Static /uploads
// - MongoDB connect mit Exponential Backoff + Events
// - Graceful Shutdown (SIGINT/SIGTERM/Uncaught/Unhandled)
// - Optional Sentry (DSN via env)
// - Mount: /api/auth, /api/profile, /api/upload, /api/scan, /api/vision (+ /api/vision/debug)
// ============================================================================

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import morgan from "morgan";
import helmet from "helmet";
import compression from "compression";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import hpp from "hpp";
import { v4 as uuid } from "uuid";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";

// Swagger / OpenAPI
import swaggerJsdoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";

// Prometheus
import client from "prom-client";

// Optional: Sentry
import * as Sentry from "@sentry/node";
import { nodeProfilingIntegration } from "@sentry/profiling-node";

// Routen (müssen vorhanden sein)
import authRoutes from "./routes/auth.js";
import profileRoutes from "./routes/profile.js";
import uploadRoutes from "./routes/upload.js";
import scanRoutes from "./routes/scan.js";
import visionRoutes from "./routes/vision.js";

// Optional: Vision-Debug als separater Subrouter (wenn Datei existiert)
let visionDebugRoutes = null;
try {
  const mod = await import("./routes/vision/debug.js");
  visionDebugRoutes = mod.default || mod;
} catch {
  // kein debug-file vorhanden -> ignorieren
}

// ---------------------------------------------------------------------------
// .env laden
dotenv.config();

// ---------------------------------------------------------------------------
// Pfad-Kontext
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// App-Metadaten
const APP_NAME = process.env.APP_NAME || "cyp-backend";
const APP_VERSION = process.env.APP_VERSION || "0.1.0";

// Konfiguration
const CONFIG = {
  NODE_ENV: process.env.NODE_ENV || "development",
  PORT: Number(process.env.PORT) || 4000,
  HOST: process.env.HOST || "0.0.0.0",

  CLIENT_URL: (process.env.CLIENT_URL || "http://localhost:3000").replace(/\/$/, ""),
  MONGO_URI: process.env.MONGO_URI || "mongodb://127.0.0.1:27017/cyp",
  JWT_SECRET: process.env.JWT_SECRET || "dev_secret_change_me",

  TRUST_PROXY: (process.env.TRUST_PROXY ?? "true") === "true",
  COOKIE_SECURE: (process.env.COOKIE_SECURE || "false") === "true",

  // Rate Limits (global)
  RL_WINDOW_MS: Number(process.env.RL_WINDOW_MS) || 15 * 60 * 1000,
  RL_LIMIT: Number(process.env.RL_LIMIT) || 600,

  // Rate Limits (auth-intensiv)
  RL_AUTH_WINDOW_MS: Number(process.env.RL_AUTH_WINDOW_MS) || 10 * 60 * 1000,
  RL_AUTH_LIMIT: Number(process.env.RL_AUTH_LIMIT) || 100,

  // Sentry
  SENTRY_DSN: process.env.SENTRY_DSN || "",
};

// Checks
if (!CONFIG.MONGO_URI) {
  console.error("❌ MONGO_URI fehlt in .env");
  process.exit(1);
}
if (!CONFIG.JWT_SECRET || CONFIG.JWT_SECRET === "dev_secret_change_me") {
  console.warn("⚠️  JWT_SECRET ist dev-Default – nur für DEV okay.");
}

// Maskierte Mongo-URI fürs Log
const maskedMongo = CONFIG.MONGO_URI.replace(/:\/\/([^:]+):[^@]+@/, "://$1:****@");

// ---------------------------------------------------------------------------
// Sentry (optional)
if (CONFIG.SENTRY_DSN) {
  Sentry.init({
    dsn: CONFIG.SENTRY_DSN,
    environment: CONFIG.NODE_ENV,
    release: `${APP_NAME}@${APP_VERSION}`,
    integrations: [nodeProfilingIntegration()],
    tracesSampleRate: 0.2,
    profilesSampleRate: 0.2,
  });
  console.log("🛰️  Sentry initialisiert");
}

// ---------------------------------------------------------------------------
// Express App
const app = express();

// Proxy-Trust (Render/Heroku/CDN)
if (CONFIG.TRUST_PROXY) app.set("trust proxy", true);

// ---------------------------------------------------------------------------
// Frühe Header: Request-ID + Meta
app.use((req, res, next) => {
  const id = req.headers["x-request-id"] || uuid();
  req.id = String(id);
  res.setHeader("x-request-id", req.id);
  res.setHeader("x-app-name", APP_NAME);
  res.setHeader("x-app-version", APP_VERSION);
  next();
});

// ---------------------------------------------------------------------------
// Security Middlewares
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: false, // später granular einsetzen falls nötig
  })
);
app.use(hpp());
app.use(compression());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());

// CORS – DEV offen, PROD per CLIENT_URL
const corsOptions =
  CONFIG.NODE_ENV === "production"
    ? {
        origin: [CONFIG.CLIENT_URL],
        credentials: true,
        allowedHeaders: ["Content-Type", "Authorization", "x-request-id"],
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        maxAge: 86400,
      }
    : {
        origin: (_o, cb) => cb(null, true),
        credentials: true,
        allowedHeaders: ["Content-Type", "Authorization", "x-request-id"],
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        maxAge: 86400,
      };
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ---------------------------------------------------------------------------
// Logging (DEV: morgan)
morgan.token("id", (req) => req.id || "-");
if (CONFIG.NODE_ENV !== "production") {
  app.use(
    morgan(':id :method :url :status :res[content-length] - :response-time ms', {
      skip: (req) => req.url.startsWith("/api/health") || req.url.startsWith("/api/readiness"),
    })
  );
}

// ---------------------------------------------------------------------------
// Rate Limits
const globalLimiter = rateLimit({
  windowMs: CONFIG.RL_WINDOW_MS,
  limit: CONFIG.RL_LIMIT,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: CONFIG.RL_AUTH_WINDOW_MS,
  limit: CONFIG.RL_AUTH_LIMIT,
  standardHeaders: true,
  legacyHeaders: false,
});

// ---------------------------------------------------------------------------
// Prometheus
const register = new client.Registry();
client.collectDefaultMetrics({ register });

const httpRequestDuration = new client.Histogram({
  name: "http_request_duration_ms",
  help: "HTTP request duration in ms",
  labelNames: ["method", "route", "status_code"],
  buckets: [5, 15, 50, 100, 250, 500, 1000, 2000, 5000],
});
register.registerMetric(httpRequestDuration);

app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    const route =
      (req.route && req.route.path) ||
      (req.baseUrl ? `${req.baseUrl}${req.path}` : req.path) ||
      "unknown";
    httpRequestDuration.labels(req.method, route, String(res.statusCode)).observe(Date.now() - start);
  });
  next();
});

app.get("/metrics", async (_req, res) => {
  res.set("Content-Type", register.contentType);
  res.end(await register.metrics());
});

// ---------------------------------------------------------------------------
// Static Files (für Uploads)
app.use("/uploads", express.static(path.join(process.cwd(), "uploads")));

// ---------------------------------------------------------------------------
// Health / Readiness / DB-Check
app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    env: CONFIG.NODE_ENV,
    name: APP_NAME,
    version: APP_VERSION,
    pid: process.pid,
    host: os.hostname(),
  });
});

app.get("/api/readiness", (_req, res) => {
  const ready = mongoose.connection.readyState === 1;
  if (!ready) return res.status(503).json({ ok: false, reason: "db_not_connected" });
  res.json({ ok: true });
});

app.get("/api/dbcheck", async (_req, res) => {
  try {
    const state = mongoose.connection.readyState;
    let collections = [];
    let dbName = null;
    if (state === 1 && mongoose.connection.db) {
      dbName = mongoose.connection.name;
      const cols = await mongoose.connection.db.listCollections().toArray();
      collections = cols.map((c) => c.name).sort();
    }
    res.json({ ok: state === 1, state, db: dbName, collections });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// ---------------------------------------------------------------------------
// Swagger / OpenAPI
const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: "3.0.3",
    info: {
      title: "CYP Backend API",
      version: APP_VERSION,
      description:
        "API Dokumentation für das CYP Backend – Auth, Profile, Upload, Scan, Vision (inkl. Debug in DEV).",
    },
    servers: [{ url: `http://localhost:${CONFIG.PORT}`, description: "Local" }],
    components: {
      securitySchemes: { bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" } },
    },
    security: [{ bearerAuth: [] }],
  },
  apis: [
    path.join(__dirname, "routes/*.js"),
    path.join(__dirname, "routes/**/*.js"),
  ],
});
app.use("/api/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec, { explorer: true }));
app.get("/api/docs.json", (_req, res) => res.json(swaggerSpec));

// ---------------------------------------------------------------------------
// Routen-Mounts
app.use("/api/auth", authLimiter, authRoutes);
app.use("/api/profile", profileRoutes);
app.use("/api/upload", uploadRoutes);
app.use("/api/scan", scanRoutes);
app.use("/api/vision", visionRoutes);

// Debug-Subrouter nur, wenn Datei existiert und nicht Production
if (visionDebugRoutes && CONFIG.NODE_ENV !== "production") {
  app.use("/api/vision", visionDebugRoutes); // ergibt /api/vision/debug/...
}

// ---------------------------------------------------------------------------
// 404
app.use((req, res) => {
  res.status(404).json({
    ok: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
    requestId: req.id || null,
  });
});

// ---------------------------------------------------------------------------
// Sentry Error-Handler (optional)
if (CONFIG.SENTRY_DSN) {
  app.use(Sentry.Handlers.errorHandler());
}

// ---------------------------------------------------------------------------
// Zentraler Fehler-Handler
/* eslint-disable no-unused-vars */
app.use((err, req, res, _next) => {
  const payload = {
    requestId: req.id,
    method: req.method,
    url: req.originalUrl,
    status: err.status || 500,
    message: err.message,
  };
  if (CONFIG.NODE_ENV !== "production" && err.stack) payload.stack = err.stack;
  console.error("💥 Error:", payload);

  res.status(payload.status).json({
    ok: false,
    message: payload.message || "Internal Server Error",
    requestId: payload.requestId,
  });
});
/* eslint-enable no-unused-vars */

// ---------------------------------------------------------------------------
// MongoDB – Verbindung mit Exponential Backoff
mongoose.set("bufferCommands", false);
mongoose.set("strictQuery", true);

console.log(`🔧 Using MONGO_URI: ${maskedMongo}`);

mongoose.connection.on("connected", () => console.log("✅ MongoDB connected"));
mongoose.connection.on("disconnected", () => console.warn("ℹ️ MongoDB disconnected"));
mongoose.connection.on("error", (err) => console.error("❌ Mongo error:", err.message));

async function connectMongoWithRetry(maxRetries = 5) {
  let attempt = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      attempt++;
      await mongoose.connect(CONFIG.MONGO_URI, {
        serverSelectionTimeoutMS: 15000,
        socketTimeoutMS: 45000,
      });
      return;
    } catch (err) {
      const wait = Math.min(1000 * 2 ** attempt, 15000);
      console.error(`❌ Mongo connect failed (try ${attempt}/${maxRetries}): ${err.message}`);
      if (attempt >= maxRetries) {
        console.error("💥 Max retries reached. Exiting.");
        throw err;
      }
      console.log(`⏳ Retry in ${Math.round(wait / 1000)}s...`);
      await new Promise((r) => setTimeout(r, wait));
    }
  }
}

// ---------------------------------------------------------------------------
// Graceful Shutdown
let server;

async function shutdown(kind = "SIGTERM") {
  try {
    console.log(`📴 Received ${kind}. Shutting down gracefully...`);
    if (server) {
      await new Promise((resolve) => server.close(resolve));
      console.log("🔌 HTTP server closed.");
    }
    await mongoose.connection.close();
    console.log("🧹 Mongo connection closed.");
    process.exit(0);
  } catch (e) {
    console.error("💣 Error during shutdown:", e.message);
    process.exit(1);
  }
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("uncaughtException", (err) => {
  console.error("💣 Uncaught Exception:", err);
  shutdown("UNCAUGHT");
});
process.on("unhandledRejection", (reason) => {
  console.error("💣 Unhandled Rejection:", reason);
  shutdown("REJECTION");
});

// ---------------------------------------------------------------------------
// Start
async function start() {
  console.log(`🚀 Starting ${APP_NAME}@${APP_VERSION} in ${CONFIG.NODE_ENV} ...`);
  await connectMongoWithRetry(5);

  server = app.listen(CONFIG.PORT, CONFIG.HOST, () => {
    console.log(`✅ Ready on http://${CONFIG.HOST}:${CONFIG.PORT}`);
  });

  if (process.env.PORT && Number(process.env.PORT) !== CONFIG.PORT) {
    console.log(`ℹ️ Using env PORT=${process.env.PORT}, effective: ${CONFIG.PORT}`);
  }
}

start();