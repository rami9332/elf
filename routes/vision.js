// routes/vision.js
// -----------------------------------------------------------------------------
// Vision API – Enroll, Match, Status + Debug-Unterrouter
// - Eigener Multer-Memory-Uploader (kein externer Upload-Middleware-Import)
// - Optionales FaceScan (utils/faceScan.js); bei Abwesenheit: Stubs
// - Rate-Limits nur für diese Route
// - OpenAPI-Doku via JSDoc (@openapi)
// -----------------------------------------------------------------------------

import { Router } from "express";
import multer from "multer";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import debugRoutes from "./vision/debug.js"; // Unterrouter: /api/vision/debug
import { requireAuth } from "../utils/authMiddleware.js";

// -------------------------------------------------------
// Optional: FaceScan dynamisch laden (wenn vorhanden)
// -------------------------------------------------------
let FaceScan = null;
try {
  const mod = await import("../utils/faceScan.js");
  FaceScan = mod.default || mod;
} catch {
  // kein FaceScan verfügbar -> wir liefern Stubs
}

// -------------------------------------------------------
// Multer Memory Uploader (max 10 MB / Datei)
// -------------------------------------------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
});

// -------------------------------------------------------
// Hilfsfunktionen
// -------------------------------------------------------
function sha256(buf) {
  const h = crypto.createHash("sha256");
  h.update(buf);
  return h.digest("hex");
}
function toB64url(buf) {
  return Buffer.from(buf).toString("base64url");
}
function fromB64url(b) {
  return Buffer.from(b, "base64url");
}
function cosineSimilarity(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return null;
  let dot = 0,
    na = 0,
    nb = 0;
  for (let i = 0; i < a.length; i++) {
    const x = Number(a[i]) || 0;
    const y = Number(b[i]) || 0;
    dot += x * y;
    na += x * x;
    nb += y * y;
  }
  if (!na || !nb) return null;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}
function ok(obj = {}) {
  return { ok: true, ...obj };
}
function fail(status, message, extra = {}) {
  return { status, body: { ok: false, message, ...extra } };
}

// -------------------------------------------------------
// Rate-Limit NUR für Vision
// -------------------------------------------------------
const visionLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60, // 60 req/min pro IP
  standardHeaders: true,
  legacyHeaders: false,
});

// -------------------------------------------------------
/**
 * @openapi
 * tags:
 *   - name: Vision
 *     description: Gesicht/Visual-API (Enroll, Match, Status, Debug)
 */
// -------------------------------------------------------

const router = Router();

// Unterrouter /api/vision/debug
router.use("/debug", visionLimiter, debugRoutes);

// Alle Vision-Routen limitieren
router.use(visionLimiter);

// -------------------------------------------------------
// GET /api/vision – Info
// -------------------------------------------------------
/**
 * @openapi
 * /api/vision:
 *   get:
 *     tags: [Vision]
 *     summary: Basic Info der Vision-API
 *     responses:
 *       200:
 *         description: OK
 */
router.get("/", (req, res) => {
  res.json(
    ok({
      service: "vision",
      hasFaceScan: Boolean(FaceScan),
      features: {
        enroll: true,
        match: true,
        status: true,
        debug: true,
      },
      ts: new Date().toISOString(),
    })
  );
});

// -------------------------------------------------------
// GET /api/vision/status – Model-/Feature-Status
// -------------------------------------------------------
/**
 * @openapi
 * /api/vision/status:
 *   get:
 *     tags: [Vision]
 *     summary: Lädt den Status (Modelle/Qualität/Metriken falls verfügbar)
 *     responses:
 *       200:
 *         description: OK
 */
router.get("/status", (req, res) => {
  const status =
    FaceScan?.status?.() ?? {
      mode: FaceScan ? "model" : "stub",
      models: FaceScan ? "loaded/unknown" : "none",
    };

  res.json(
    ok({
      status,
      ts: new Date().toISOString(),
    })
  );
});

// -------------------------------------------------------
// POST /api/vision/enroll – Embedding extrahieren (auth)
// -------------------------------------------------------
/**
 * @openapi
 * /api/vision/enroll:
 *   post:
 *     tags: [Vision]
 *     summary: Extrahiert ein Embedding aus einem Gesichtsbild (Enroll)
 *     description: |
 *       Erwartet `multipart/form-data` mit Feld **photo**.
 *       Antwort enthält Embedding/Base64 (für DB) und einige Metadaten.
 *     security: [{ bearerAuth: [] }]
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required: [photo]
 *             properties:
 *               photo:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: OK
 *       400:
 *         description: Ungültige Eingabe
 *       500:
 *         description: Interner Fehler
 */
router.post(
  "/enroll",
  requireAuth,
  upload.single("photo"),
  async (req, res) => {
    try {
      if (!req.file?.buffer) {
        const f = fail(400, "Missing 'photo' file");
        return res.status(f.status).json(f.body);
      }

      const buf = req.file.buffer;

      // Wenn FaceScan vorhanden ist, echtes Embedding
      if (FaceScan?.extractSingleEmbedding) {
        const result = await FaceScan.extractSingleEmbedding(buf);

        if (!result?.ok) {
          const f = fail(400, result?.reason || "No face / embedding failed");
          return res.status(f.status).json(f.body);
        }

        const descriptor = Array.isArray(result.descriptor)
          ? result.descriptor
          : Array.from(result.descriptor || []);

        const payload = {
          userId: req.userId ?? null,
          imageHash: sha256(buf),
          box: result.box || null,
          // zwei Darstellungen, du kannst wählen, was du speichern willst:
          embedding: {
            array: descriptor, // numerisches Array
            base64: FaceScan.descriptorToBase64
              ? FaceScan.descriptorToBase64(descriptor)
              : toB64url(Buffer.from(Float32Array.from(descriptor).buffer)),
          },
          ts: new Date().toISOString(),
        };

        return res.json(ok(payload));
      }

      // Stub-Fallback (kein FaceScan vorhanden)
      const stubDescriptor = new Array(128).fill(0).map((_, i) => Math.sin(i) * 0.01);
      const payload = {
        userId: req.userId ?? null,
        imageHash: sha256(buf),
        box: null,
        embedding: {
          array: stubDescriptor,
          base64: toB64url(Buffer.from(Float32Array.from(stubDescriptor).buffer)),
          note: "stub-mode",
        },
        ts: new Date().toISOString(),
      };
      return res.json(ok(payload));
    } catch (e) {
      const f = fail(500, e.message);
      return res.status(f.status).json(f.body);
    }
  }
);

// -------------------------------------------------------
// POST /api/vision/match – Foto gegen gespeichertes Embedding (auth)
// -------------------------------------------------------
/**
 * @openapi
 * /api/vision/match:
 *   post:
 *     tags: [Vision]
 *     summary: Verifiziert ein Bild gegen ein mitgegebenes Embedding
 *     description: |
 *       Erwartet
 *       - `multipart/form-data` mit **photo**
 *       - im JSON-Body EINES der Felder:
 *         - `targetEmbeddingB64` (base64url-kodiertes Float32Array)
 *         - `targetEmbedding` (Array von Zahlen)
 *       Optional: `threshold` (Standard 0.35 Distanz / oder 0.8 Cosine-Score im Stub)
 *     security: [{ bearerAuth: [] }]
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required: [photo]
 *             properties:
 *               photo:
 *                 type: string
 *                 format: binary
 *               targetEmbeddingB64:
 *                 type: string
 *               targetEmbedding:
 *                 type: array
 *                 items:
 *                   type: number
 *               threshold:
 *                 type: number
 *     responses:
 *       200:
 *         description: OK
 *       400:
 *         description: Ungültige Eingabe
 *       500:
 *         description: Interner Fehler
 */
router.post(
  "/match",
  requireAuth,
  upload.single("photo"),
  async (req, res) => {
    try {
      if (!req.file?.buffer) {
        const f = fail(400, "Missing 'photo' file");
        return res.status(f.status).json(f.body);
      }

      // Ziel-Embedding aus Body
      let target = null;
      if (req.body?.targetEmbeddingB64) {
        const raw = fromB64url(String(req.body.targetEmbeddingB64));
        // Float32Array aus Buffer
        const f32 = new Float32Array(raw.buffer, raw.byteOffset, Math.floor(raw.byteLength / 4));
        target = Array.from(f32);
      } else if (Array.isArray(req.body?.targetEmbedding)) {
        target = req.body.targetEmbedding.map((v) => Number(v));
      } else {
        const f = fail(400, "Provide 'targetEmbeddingB64' or 'targetEmbedding' in body");
        return res.status(f.status).json(f.body);
      }

      // Threshold
      let threshold = Number(req.body?.threshold);
      if (!Number.isFinite(threshold) || threshold <= 0) {
        // Standardwerte:
        // - FaceScan (euclidean distance): 0.35 (enger) – anpassbar
        // - Stub (cosine similarity): 0.80 (>= match)
        threshold = FaceScan ? 0.35 : 0.8;
      }

      const buf = req.file.buffer;

      // Echte Pipeline, wenn verfügbar
      if (FaceScan?.extractSingleEmbedding) {
        const live = await FaceScan.extractSingleEmbedding(buf);
        if (!live?.ok) {
          const f = fail(400, live?.reason || "No face / live embedding failed");
          return res.status(f.status).json(f.body);
        }

        const liveDesc = Array.isArray(live.descriptor)
          ? live.descriptor
          : Array.from(live.descriptor || []);

        // Distanz/Score über FaceScan-Utility, falls vorhanden
        let distance = null;
        if (typeof FaceScan.distance === "function") {
          distance = FaceScan.distance(liveDesc, target);
        } else {
          // Fallback: euclidean
          let sum = 0;
          for (let i = 0; i < Math.min(liveDesc.length, target.length); i++) {
            const d = (liveDesc[i] || 0) - (target[i] || 0);
            sum += d * d;
          }
          distance = Math.sqrt(sum);
        }

        const isMatch = distance <= threshold;
        return res.json(
          ok({
            mode: "model",
            distance,
            threshold,
            isMatch,
            liveBox: live.box || null,
            ts: new Date().toISOString(),
          })
        );
      }

      // Stub-Pipeline (Cosine-Similarity)
      const stubLive = new Array(target.length || 128).fill(0).map((_, i) => Math.sin(i * 1.1) * 0.01);
      const score = cosineSimilarity(stubLive, target) ?? 0;
      const isMatch = score >= threshold;

      return res.json(
        ok({
          mode: "stub",
          similarity: score,
          threshold,
          isMatch,
          note: "stub-mode (no real models loaded)",
          ts: new Date().toISOString(),
        })
      );
    } catch (e) {
      const f = fail(500, e.message);
      return res.status(f.status).json(f.body);
    }
  }
);

// -----------------------------------------------------------------------------
// 404 für /api/vision (nur falls jemand eine falsche Unterroute trifft)
// -----------------------------------------------------------------------------
router.use((req, res) => {
  res.status(404).json({ ok: false, message: `Vision route not found: ${req.method} ${req.originalUrl}` });
});

export default router;