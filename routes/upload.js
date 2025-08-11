// routes/upload.js
import express from "express";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const router = express.Router();

// ---- Verzeichnisse/Paths vorbereiten (ESM-kompatibel) ----
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const UPLOAD_DIR = path.join(__dirname, "..", "uploads");

// uploads/ sicherstellen
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ---- Multer-Konfiguration ----
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    const base = path
      .basename(file.originalname, ext)
      .replace(/\s+/g, "_")
      .replace(/[^a-zA-Z0-9_\-]/g, "");
    cb(null, `${base}-${Date.now()}${ext.toLowerCase()}`);
  },
});

const fileFilter = (_req, file, cb) => {
  // nur Bilder erlauben (png,jpg,jpeg,gif,webp)
  if (file.mimetype?.startsWith("image/")) return cb(null, true);
  cb(new Error("Only image uploads are allowed"));
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
});

// ---- Helper zum Bauen einer öffentlichen URL ----
function publicUrl(req, filename) {
  const base = `${req.protocol}://${req.get("host")}`;
  return `${base}/uploads/${filename}`;
}

// ---- POST /api/upload  (einzelnes Bild, Feldname: "file") ----
router.post("/", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No file uploaded" });

  return res.status(201).json({
    ok: true,
    filename: req.file.filename,
    originalName: req.file.originalname,
    size: req.file.size,
    mimetype: req.file.mimetype,
    path: `/uploads/${req.file.filename}`,
    url: publicUrl(req, req.file.filename),
  });
});

// ---- POST /api/upload/multi  (mehrere Bilder, Feldname: "files") ----
router.post("/multi", upload.array("files", 6), (req, res) => {
  const files = (req.files || []).map((f) => ({
    filename: f.filename,
    originalName: f.originalname,
    size: f.size,
    mimetype: f.mimetype,
    path: `/uploads/${f.filename}`,
    url: publicUrl(req, f.filename),
  }));
  if (!files.length) return res.status(400).json({ message: "No files uploaded" });
  return res.status(201).json({ ok: true, files });
});

// ---- GET /api/upload  (Liste der vorhandenen Dateien) ----
router.get("/", (_req, res) => {
  try {
    const entries = fs.readdirSync(UPLOAD_DIR);
    const files = entries
      .filter((n) => !n.startsWith("."))
      .map((name) => ({
        name,
        path: `/uploads/${name}`,
      }));
    return res.json({ ok: true, count: files.length, files });
  } catch (e) {
    return res.status(500).json({ message: "Cannot read uploads directory" });
  }
});

// ---- DELETE /api/upload/:name  (Datei löschen) ----
// Achtung: :name wird auf Basename beschränkt (keine Pfad-Tricks).
router.delete("/:name", (req, res) => {
  const safe = path.basename(req.params.name || "");
  if (!safe) return res.status(400).json({ message: "Invalid filename" });

  const full = path.join(UPLOAD_DIR, safe);
  if (!fs.existsSync(full)) return res.status(404).json({ message: "Not found" });

  try {
    fs.unlinkSync(full);
    return res.json({ ok: true, deleted: safe });
  } catch (e) {
    return res.status(500).json({ message: "Delete failed" });
  }
});

export default router;