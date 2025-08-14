// routes/vision/debug.js
// -----------------------------------------------------------------------------
// Vision Debug-Endpoints:
// - /ping                      -> einfacher Health-Check
// - /echo                      -> gibt Body/Headers zurück (Debug)
// - /inspect                   -> Bild-Metadaten, optional Qualität & Embedding
//
// Der Uploader ist eigenständig (multer memory). Es gibt KEINE Abhängigkeit auf
// andere Middleware-Dateien. FaceScan wird *optional* dynamisch geladen.
// -----------------------------------------------------------------------------

import { Router } from "express";
import multer from "multer";
import crypto from "crypto";
import sharp from "sharp";
import os from "os";
import path from "path";

// FaceScan optional laden — wenn nicht verfügbar, liefern wir nur Metadaten
let FaceScan = null;
try {
  const mod = await import("../../utils/faceScan.js");
  FaceScan = mod.default || mod;
} catch {
  // ok, ohne FaceScan laufen /inspect (nur Metadaten)
}

// optional: fetch für imageUrl (nur wenn installiert)
let fetchFn = null;
try {
  const mod = await import("node-fetch");
  fetchFn = (mod.default || mod);
} catch {
  // kein fetch -> imageUrl wird ignoriert
}

const router = Router();

// Multer Memory Uploader
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
});

// kleine Helfer
function sha256(buf) {
  const h = crypto.createHash("sha256");
  h.update(buf);
  return h.digest("hex");
}
function pick(obj, keys) {
  const out = {};
  for (const k of keys) if (k in obj) out[k] = obj[k];
  return out;
}

// -----------------------------------------------------------------------------
router.get("/ping", (req, res) => {
  res.json({
    ok: true,
    service: "vision-debug",
    now: new Date().toISOString(),
    pid: process.pid,
    host: os.hostname(),
  });
});

// -----------------------------------------------------------------------------
router.post("/echo", async (req, res) => {
  res.json({
    ok: true,
    method: req.method,
    path: req.originalUrl,
    headers: req.headers,
    body: req.body ?? null,
    at: new Date().toISOString(),
  });
});

// -----------------------------------------------------------------------------
router.post(
  "/inspect",
  upload.single("photo"), // erwartet multipart Feld "photo"
  async (req, res) => {
    try {
      // Bildquelle: (a) Datei (photo) oder (b) imageUrl (falls fetch da)
      let buf = null;
      let source = null;

      if (req.file?.buffer) {
        buf = req.file.buffer;
        source = { type: "file", filename: req.file.originalname || null, mimetype: req.file.mimetype || null };
      } else if (req.body?.imageUrl && fetchFn) {
        const url = String(req.body.imageUrl);
        const r = await fetchFn(url);
        if (!r.ok) throw new Error(`imageUrl fetch failed: ${r.status}`);
        buf = Buffer.from(await r.arrayBuffer());
        source = { type: "url", url };
      } else {
        return res.status(400).json({ ok: false, message: "Provide a 'photo' file (multipart) or 'imageUrl'." });
      }

      // Metadaten via sharp
      let meta = null;
      try {
        meta = await sharp(buf, { animated: true }).metadata();
      } catch (e) {
        return res.status(400).json({ ok: false, message: `Invalid image: ${e.message}` });
      }

      const out = {
        ok: true,
        source,
        size: buf.length,
        sha256: sha256(buf),
        meta: pick(meta || {}, [
          "format",
          "width",
          "height",
          "space",
          "hasProfile",
          "hasAlpha",
          "density",
          "pages",
          "delay",
        ]),
      };

      // Flags: ?quality=true & ?embedding=true
      const wantQuality = String(req.query.quality || "").toLowerCase() === "true";
      const wantEmbedding = String(req.query.embedding || "").toLowerCase() === "true";

      if (wantQuality || wantEmbedding) {
        if (!FaceScan) {
          out.note = "FaceScan not available (utils/faceScan.js not loaded). Returning metadata only.";
        } else {
          // Qualität (falls implementiert)
          if (wantQuality && typeof FaceScan.assessImageQuality === "function") {
            try {
              out.quality = await FaceScan.assessImageQuality(buf);
            } catch (e) {
              out.quality = { ok: false, error: e.message };
            }
          }

          // Embedding (falls implementiert)
          if (wantEmbedding && typeof FaceScan.extractSingleEmbedding === "function") {
            try {
              const emb = await FaceScan.extractSingleEmbedding(buf);
              if (emb?.ok) {
                out.embedding = {
                  ok: true,
                  box: emb.box || null,
                  descriptorSample: Array.isArray(emb.descriptor)
                    ? emb.descriptor.slice(0, 8)
                    : null,
                  descriptorB64: FaceScan.descriptorToBase64
                    ? FaceScan.descriptorToBase64(emb.descriptor)
                    : null,
                };
              } else {
                out.embedding = { ok: false, reason: emb?.reason || "unknown" };
              }
            } catch (e) {
              out.embedding = { ok: false, error: e.message };
            }
          }
        }
      }

      return res.json(out);
    } catch (e) {
      return res.status(500).json({ ok: false, message: e.message });
    }
  }
);

// -----------------------------------------------------------------------------
export default router;