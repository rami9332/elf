// routes/vision.js
/**
 * Vision API
 * - /enroll: Gesichts-Template für einen User speichern
 * - /match : Foto scannen, gegen Galerie (DB) matchen
 *
 * Robust:
 * - Multer (memory & disk) für flexible Uploads
 * - Genaue Fehlertexte, Rate-Limits, Validierung
 * - nutzt utils/faceScan.js Methoden:
 *     - assessImageQuality(input)
 *     - extractSingleEmbedding(input)
 *     - descriptorToBase64(descriptor)
 *     - scanAndMatch(input, gallery, { threshold })
 */

import { Router } from "express";
import rateLimit from "express-rate-limit";
import multer from "multer";
import sharp from "sharp";
import User from "../models/User.js";
import FaceScan from "../utils/faceScan.js";
import { requireAuth } from "../utils/authMiddleware.js";

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

const router = Router();

// Rate-Limits (Vision-Endpunkte sind rechenintensiv)
const visionLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "Too many vision requests, slow down." },
});

// Wir nehmen MemoryStorage, weil FaceScan mit Buffern/URLs umgehen kann
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: Number(process.env.MAX_IMAGE_BYTES || 5 * 1024 * 1024) }, // 5MB
});

// Hilfsfunktion: Input aus File oder imageUrl gewinnen
function readInputFromRequest(req) {
  // 1) Datei-Upload (multipart/form-data)
  if (req.file?.buffer) return req.file.buffer;

  // 2) Fallback: URL im Body (JSON)
  if (req.body?.imageUrl && typeof req.body.imageUrl === "string") {
    return req.body.imageUrl.trim();
  }

  return null;
}

// Hilfsfunktion: minimale Bildprüfung (verhindert PDFs/ZIPs)
async function ensureImageBuffer(buf) {
  try {
    const meta = await sharp(buf).metadata();
    if (!meta?.format || !meta.width || !meta.height) {
      throw new Error("Not an image");
    }
  } catch {
    throw new Error("Invalid image data");
  }
}

// ---------------------------------------------------------------------------
// POST /api/vision/enroll
// - userId (Pflicht): für wen das Template gespeichert wird
// - photo (Formfeld) ODER imageUrl im JSON-Body
// - speichert embedding (als base64) in User.faceTemplate
// ---------------------------------------------------------------------------
/**
 * @openapi
 * /api/vision/enroll:
 *   post:
 *     tags: [Vision]
 *     summary: Gesicht einlernen (Template beim User speichern)
 *     security: [{ bearerAuth: [] }]
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required: [userId, photo]
 *             properties:
 *               userId:
 *                 type: string
 *               photo:
 *                 type: string
 *                 format: binary
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, imageUrl]
 *             properties:
 *               userId:
 *                 type: string
 *               imageUrl:
 *                 type: string
 *     responses:
 *       200:
 *         description: Template gespeichert
 */
router.post(
  "/enroll",
  visionLimiter,
  requireAuth,
  upload.single("photo"),
  async (req, res, next) => {
    try {
      const userId = (req.body.userId || "").trim();
      if (!userId) return res.status(400).json({ ok: false, message: "Missing userId" });

      // Zugriffsschutz: nur sich selbst oder Admin
      if (String(req.userId) !== String(userId) && req.userRole !== "admin") {
        return res.status(403).json({ ok: false, message: "Not allowed" });
      }

      const input = readInputFromRequest(req);
      if (!input) {
        return res.status(400).json({ ok: false, message: "Provide photo (file) or imageUrl" });
      }

      // Bei Buffer prüfen, dass wirklich Bild
      if (Buffer.isBuffer(input)) {
        await ensureImageBuffer(input);
      }

      // Optionale Bildqualität (nur Info)
      const quality = await FaceScan.assessImageQuality(input).catch(() => null);

      // Embedding extrahieren
      const emb = await FaceScan.extractSingleEmbedding(input);
      if (!emb?.ok) {
        return res.status(400).json({ ok: false, message: `Embedding failed: ${emb?.reason || "unknown"}` });
      }

      const faceTemplate = FaceScan.descriptorToBase64(emb.descriptor);

      const user = await User.findByIdAndUpdate(
        userId,
        { $set: { faceTemplate } },
        { new: true }
      ).lean();

      if (!user) return res.status(404).json({ ok: false, message: "User not found" });

      res.json({
        ok: true,
        message: "Face template saved",
        quality,
        faceBox: emb.box || null,
        user: { id: user._id, name: user.name, email: user.email },
      });
    } catch (e) {
      next(e);
    }
  }
);

// ---------------------------------------------------------------------------
// POST /api/vision/match
// - photo (Formfeld) ODER imageUrl im JSON-Body
// - optional threshold (Default 0.60; kleiner = strenger)
// - durchsucht alle User mit faceTemplate != null
// - liefert beste Trefferliste sortiert mit Score (0..1)
// ---------------------------------------------------------------------------
/**
 * @openapi
 * /api/vision/match:
 *   post:
 *     tags: [Vision]
 *     summary: Foto gegen gespeicherte Gesichts-Templates matchen
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
 *               threshold:
 *                 type: number
 *                 default: 0.6
 *         application/json:
 *           schema:
 *             type: object
 *             required: [imageUrl]
 *             properties:
 *               imageUrl:
 *                 type: string
 *               threshold:
 *                 type: number
 *                 default: 0.6
 *     responses:
 *       200:
 *         description: Trefferliste
 */
router.post(
  "/match",
  visionLimiter,
  requireAuth,
  upload.single("photo"),
  async (req, res, next) => {
    try {
      const input = readInputFromRequest(req);
      if (!input) {
        return res.status(400).json({ ok: false, message: "Provide photo (file) or imageUrl" });
      }
      if (Buffer.isBuffer(input)) {
        await ensureImageBuffer(input);
      }

      const threshold = req.body.threshold
        ? Math.max(0.1, Math.min(1.0, Number(req.body.threshold)))
        : 0.6;

      // Galerie aus DB aufbauen
      const users = await User.find(
        { faceTemplate: { $exists: true, $ne: null } },
        { name: 1, faceTemplate: 1 }
      ).lean();

      if (!users.length) {
        return res.status(200).json({ ok: true, matches: [], info: "No enrolled faces yet" });
      }

      const gallery = users.map((u) => ({
        id: String(u._id),
        name: u.name || "Unknown",
        descriptor: u.faceTemplate, // base64
      }));

      const out = await FaceScan.scanAndMatch(input, gallery, { threshold });

      // Response im freundlichen Format
      res.json({
        ok: true,
        facesDetected: out.facesDetected || 0,
        bestMatch: out.bestMatch || null,
        matches: out.matches || [],
      });
    } catch (e) {
      next(e);
    }
  }
);

export default router;