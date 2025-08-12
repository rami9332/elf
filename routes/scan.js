// routes/scan.js
import { Router } from "express";
import rateLimit from "express-rate-limit";
import multer from "multer";
import { requireAuth } from "../utils/authMiddleware.js";
import FaceScan from "../utils/faceScan.js";

const router = Router();
const upload = multer({ storage: multer.memoryStorage() });

// Strenges Rate-Limit, weil Scans rechenintensiv sind
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

// einfache Probe
router.get("/ping", (_req, res) => {
  res.json({ ok: true, route: "scan", ts: Date.now() });
});

/**
 * Gesicht „enrollen“ (Template beim User speichern)
 * Erwartet: multipart/form-data mit field "photo" ODER JSON mit { imageUrl }
 * Header: Authorization: Bearer <JWT>
 */
router.post(
  "/face/enroll",
  scanLimiter,
  requireAuth,
  upload.single("photo"),
  async (req, res, next) => {
    try {
      const input = req.file?.buffer || req.body?.imageUrl;
      if (!input) {
        return res.status(400).json({ ok: false, message: "photo oder imageUrl nötig" });
      }

      // Qualität checken & Embedding extrahieren (FaceScan kapselt die Modelle)
      const quality = await FaceScan.assessImageQuality(input);
      const emb = await FaceScan.extractSingleEmbedding(input);
      if (!emb.ok) {
        return res.status(400).json({ ok: false, message: `Embedding fehlgeschlagen: ${emb.reason}` });
      }

      // Template als base64url speichern (du kannst das in deinem User-Modell ablegen)
      const faceTemplate = FaceScan.descriptorToBase64(emb.descriptor);

      // Beispiel: im req.userId steckt die ID aus requireAuth
      // -> Speichere faceTemplate beim User
      // Achtung: Passe das an dein tatsächliches User-Modell an
      const { default: User } = await import("../models/User.js");
      await User.findByIdAndUpdate(
        req.userId,
        { $set: { faceTemplate } },
        { new: true }
      );

      res.json({ ok: true, quality, box: emb.box });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * Bild mit vorhandenen User-Templates matchen
 * Erwartet: multipart/form-data "photo" ODER JSON { imageUrl }
 * Optional: ?threshold=0.6 (0.4..0.9), default 0.6
 */
router.post(
  "/face/match",
  scanLimiter,
  requireAuth,
  upload.single("photo"),
  async (req, res, next) => {
    try {
      const input = req.file?.buffer || req.body?.imageUrl;
      if (!input) return res.status(400).json({ ok: false, message: "photo oder imageUrl nötig" });

      const threshold = req.query.threshold ? Number(req.query.threshold) : 0.6;
      if (!(threshold >= 0.3 && threshold <= 0.9)) {
        return res.status(400).json({ ok: false, message: "threshold muss zwischen 0.3 und 0.9 liegen" });
      }

      const { default: User } = await import("../models/User.js");
      const users = await User.find(
        { faceTemplate: { $exists: true, $ne: null } },
        { name: 1, faceTemplate: 1 }
      ).lean();

      const gallery = users.map(u => ({
        id: String(u._id),
        name: u.name,
        descriptor: u.faceTemplate, // base64url des Embeddings
      }));

      const result = await FaceScan.scanAndMatch(input, gallery, { threshold });

      res.json({ ok: true, ...result });
    } catch (err) {
      next(err);
    }
  }
);

export default router;