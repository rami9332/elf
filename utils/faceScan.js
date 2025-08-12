// utils/faceScan.js
// -------------------------------------------------------------------------------------------------
// Face-Scanning / Embedding / Matching für Node.js (Server-Side)
// Verwendet: @vladmandic/face-api, @tensorflow/tfjs-node, node-canvas, optional sharp
// -------------------------------------------------------------------------------------------------
//
// WICHTIG (Dependencies):
//   npm i @tensorflow/tfjs-node @vladmandic/face-api canvas sharp node-fetch
//
// Model-Dateien: (am besten in: ./models/face-api)
//   - face_recognition_model-weights_manifest.json (+ bin-Dateien)
//   - face_landmark_68_model-weights_manifest.json (+ bin-Dateien)
//   - ssd_mobilenetv1_model-weights_manifest.json (+ bin-Dateien)
//   Alternativ kannst Du die Modelle via face-api automatisch laden, wenn sie im Pfad liegen.
//   ENV-Var für Modellpfad: FACE_MODELS_DIR (default: ./models/face-api)
//
// Hinweise zu Einsatzgrenzen:
//   - Das ist kein "Liveness" Proof (keine Spoof-Detection, kein echter 3D-Check).
//   - Gesichtserkennung unterliegt Datenschutz, Einwilligung der Nutzer ist notwendig.
//   - Mobile "Infrarot/Satellit/Bluetooth"-Dinge sind hier NICHT enthalten (unrealistisch / OS-abhängig).
//   - Für Passkey/OS-Scanner (FaceID/TouchID) brauchst Du OS-spezifische APIs (Client-seitig).
//
// -------------------------------------------------------------------------------------------------

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import * as tf from '@tensorflow/tfjs-node';
import * as faceapi from '@vladmandic/face-api';
import { createCanvas, Image, loadImage } from 'canvas';
import sharp from 'sharp';
import fetch from 'node-fetch';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ----------------------------- Konfiguration / Defaults ------------------------------------------

const DEFAULTS = {
  MODEL_DIR: process.env.FACE_MODELS_DIR || path.join(process.cwd(), 'models', 'face-api'),
  MIN_CONFIDENCE: 0.5,         // Mindestkonfidenz für SSD Mobilenet
  MAX_RESULTS: 5,              // max. Gesichter die wir analysieren
  MIN_FACE_SIZE: 64,           // minimale Seitenlänge in Pixeln für vernünftige Embeddings
  SIMILARITY_THRESHOLD: 0.6,   // Daumenwert für Cosine-Ähnlichkeit (niedriger = strenger)
  QUALITY: {
    MIN_BRIGHTNESS: 0.15,      // 0..1
    MAX_BRIGHTNESS: 0.90,      // 0..1
    MIN_CONTRAST: 0.05,        // heuristisch
    MIN_SHARPNESS: 10,         // heuristisch (Kantendichte)
  },
};

let _modelsLoaded = false;
let _modelDir = DEFAULTS.MODEL_DIR;

// ----------------------------- Hilfen: Canvas / Image --------------------------------------------

/**
 * Erzeugt ein Canvas für face-api (benötigt, weil face-api in Node keine DOM hat).
 */
function getCanvasForFaceApi(width, height) {
  const canvas = createCanvas(width, height);
  return canvas;
}

/**
 * Lädt ein Bild aus Buffer, Datei oder URL in ein Canvas-kompatibles Image-Objekt.
 */
async function loadAnyImage(input) {
  if (Buffer.isBuffer(input)) {
    return await loadImage(input);
  }
  if (typeof input === 'string') {
    if (input.startsWith('http://') || input.startsWith('https://')) {
      const res = await fetch(input);
      if (!res.ok) throw new Error(`HTTP ${res.status} beim Laden der URL: ${input}`);
      const buf = Buffer.from(await res.arrayBuffer());
      return await loadImage(buf);
    }
    // Dateipfad
    const filePath = path.isAbsolute(input) ? input : path.join(process.cwd(), input);
    const buf = await fs.promises.readFile(filePath);
    return await loadImage(buf);
  }
  throw new Error('Unsupported image input: expected Buffer | filePath | http(s) URL');
}

// ----------------------------- Model-Loading ------------------------------------------------------

/**
 * Lädt die Face-API-Modelle (einmalig).
 * Setze FACE_MODELS_DIR in .env, wenn Du den Pfad ändern willst.
 */
export async function initFaceApi(options = {}) {
  if (_modelsLoaded) return true;

  _modelDir = options.modelDir || _modelDir;

  // Prüfen, ob die Dateien existieren (simple Heuristik)
  const checkFiles = [
    'ssd_mobilenetv1_model-weights_manifest.json',
    'face_landmark_68_model-weights_manifest.json',
    'face_recognition_model-weights_manifest.json',
  ];
  for (const f of checkFiles) {
    const full = path.join(_modelDir, f);
    if (!fs.existsSync(full)) {
      console.warn(`[faceScan] ⚠️ Modelldatei fehlt: ${full} — Stelle sicher, dass alle Modelle im Verzeichnis liegen.`);
    }
  }

  // FaceAPI an Canvas binden
  const faceApiEnv = faceapi.env;
  faceApiEnv.monkeyPatch({
    Canvas: createCanvas,
    Image,
    ImageData: global.ImageData,
  });

  // Modelle laden
  await faceapi.nets.ssdMobilenetv1.loadFromDisk(_modelDir);
  await faceapi.nets.faceLandmark68Net.loadFromDisk(_modelDir);
  await faceapi.nets.faceRecognitionNet.loadFromDisk(_modelDir);

  _modelsLoaded = true;
  return true;
}

export function modelsLoaded() {
  return _modelsLoaded;
}

// ----------------------------- Qualitätschecks (heuristisch) -------------------------------------

/**
 * Einfache Helligkeits-/Kontrast-Schätzung (0..1); Sharp nutzt Y-Chrominanz nicht direkt,
 * deshalb nutzen wir eine sehr simple Heuristik auf Luma-Approx (0.2126 R + 0.7152 G + 0.0722 B).
 */
async function estimateBrightnessContrast(buffer) {
  try {
    const { data, info } = await sharp(buffer).raw().ensureAlpha().toBuffer({ resolveWithObject: true });
    // data = RGBA RGBA ...
    const pixels = info.width * info.height;
    let sum = 0;
    let sumSq = 0;

    for (let i = 0; i < data.length; i += 4) {
      const r = data[i] / 255;
      const g = data[i + 1] / 255;
      const b = data[i + 2] / 255;
      const luma = 0.2126 * r + 0.7152 * g + 0.0722 * b; // 0..1
      sum += luma;
      sumSq += luma * luma;
    }
    const mean = sum / pixels;
    const variance = Math.max(0, sumSq / pixels - mean * mean);
    const contrast = Math.sqrt(variance); // grobe Heuristik
    return { brightness: mean, contrast };
  } catch {
    return { brightness: 0.5, contrast: 0.1 };
  }
}

/**
 * Sehr einfache Unschärfe-Heuristik: wir zählen Kanten-Anteile über Sobel auf stark verkleinertem Bild.
 * (Performancefreundlich, nicht superpräzise – für "grobe" Filterung okay.)
 */
async function estimateSharpness(buffer) {
  try {
    const resized = await sharp(buffer).greyscale().resize(128, 128, { fit: 'inside' }).raw().toBuffer({ resolveWithObject: false });
    // Sobel-Kernel
    const w = 128, h = 128;
    const gx = [-1, 0, 1, -2, 0, 2, -1, 0, 1];
    const gy = [-1, -2, -1, 0, 0, 0, 1, 2, 1];

    const get = (x, y) => {
      if (x < 0 || y < 0 || x >= w || y >= h) return 0;
      return resized[y * w + x];
    };

    let edges = 0;
    let total = 0;
    for (let y = 1; y < h - 1; y++) {
      for (let x = 1; x < w - 1; x++) {
        let sx = 0;
        let sy = 0;
        let k = 0;
        for (let j = -1; j <= 1; j++) {
          for (let i = -1; i <= 1; i++) {
            const v = get(x + i, y + j);
            sx += v * gx[k];
            sy += v * gy[k];
            k++;
          }
        }
        const mag = Math.sqrt(sx * sx + sy * sy); // 0..(~1k)
        if (mag > 60) edges++; // willkürliche Schwelle
        total++;
      }
    }
    const ratio = (edges / total) * 1000; // skalieren damit ~10-80
    return ratio;
  } catch {
    return 20;
  }
}

/**
 * Führt alle Qualitätschecks aus und gibt ein Detail-Objekt zurück.
 */
export async function assessImageQuality(bufOrImg) {
  let buffer;
  if (Buffer.isBuffer(bufOrImg)) {
    buffer = bufOrImg;
  } else if (typeof bufOrImg === 'string') {
    if (bufOrImg.startsWith('http')) {
      const res = await fetch(bufOrImg);
      if (!res.ok) throw new Error(`HTTP ${res.status} beim Laden: ${bufOrImg}`);
      buffer = Buffer.from(await res.arrayBuffer());
    } else {
      buffer = await fs.promises.readFile(bufOrImg);
    }
  } else {
    throw new Error('assessImageQuality: expected Buffer | filePath | URL');
  }

  const [bc, sharpness] = await Promise.all([
    estimateBrightnessContrast(buffer),
    estimateSharpness(buffer),
  ]);

  const okBrightness = bc.brightness >= DEFAULTS.QUALITY.MIN_BRIGHTNESS && bc.brightness <= DEFAULTS.QUALITY.MAX_BRIGHTNESS;
  const okContrast = bc.contrast >= DEFAULTS.QUALITY.MIN_CONTRAST;
  const okSharp = sharpness >= DEFAULTS.QUALITY.MIN_SHARPNESS;

  return {
    ok: okBrightness && okContrast && okSharp,
    brightness: bc.brightness,
    contrast: bc.contrast,
    sharpness,
    thresholds: { ...DEFAULTS.QUALITY },
  };
}

// ----------------------------- Embedding / Detection ---------------------------------------------

/**
 * Erkennt Gesichter und liefert BoundingBoxes + Embeddings (128‑Dim).
 */
export async function detectFacesAndEmbeddings(input, opts = {}) {
  if (!_modelsLoaded) {
    await initFaceApi();
  }

  const minConfidence = opts.minConfidence ?? DEFAULTS.MIN_CONFIDENCE;
  const maxResults = opts.maxResults ?? DEFAULTS.MAX_RESULTS;

  const img = await loadAnyImage(input);
  const canvas = getCanvasForFaceApi(img.width, img.height);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0);

  const detections = await faceapi
    .detectAllFaces(canvas, new faceapi.SsdMobilenetv1Options({ minConfidence }))
    .withFaceLandmarks()
    .withFaceDescriptors();

  // Begrenze Ergebnisse
  const results = detections.slice(0, maxResults).map(d => {
    const box = d.detection.box; // { x, y, width, height }
    const descriptor = d.descriptor; // Float32Array(128)
    return {
      box: { x: box.x, y: box.y, width: box.width, height: box.height },
      descriptor: new Float32Array(descriptor),
      score: d.detection.score,
    };
  });

  return {
    count: results.length,
    width: img.width,
    height: img.height,
    faces: results,
  };
}

/**
 * Extrahiert das "beste" Gesicht (größte Box) und gibt Embedding zurück.
 */
export async function extractSingleEmbedding(input, opts = {}) {
  const det = await detectFacesAndEmbeddings(input, opts);
  if (det.count === 0) return { ok: false, reason: 'NO_FACE' };

  // größtes Gesicht
  const best = det.faces.reduce((acc, f) => {
    const a = f.box.width * f.box.height;
    return a > acc.area ? { area: a, item: f } : acc;
  }, { area: 0, item: null }).item;

  const size = Math.min(best.box.width, best.box.height);
  if (size < (opts.minFaceSize ?? DEFAULTS.MIN_FACE_SIZE)) {
    return { ok: false, reason: 'FACE_TOO_SMALL', size };
  }

  return {
    ok: true,
    descriptor: best.descriptor, // Float32Array(128)
    box: best.box,
    score: best.score,
    image: { width: det.width, height: det.height },
  };
}

// ----------------------------- Embedding Utilities ------------------------------------------------

export function l2Normalize(vec) {
  const v = Array.isArray(vec) ? Float32Array.from(vec) : new Float32Array(vec);
  let sum = 0;
  for (let i = 0; i < v.length; i++) sum += v[i] * v[i];
  const norm = Math.sqrt(sum) || 1;
  const out = new Float32Array(v.length);
  for (let i = 0; i < v.length; i++) out[i] = v[i] / norm;
  return out;
}

export function cosineSimilarity(a, b) {
  const A = Array.isArray(a) ? a : Array.from(a);
  const B = Array.isArray(b) ? b : Array.from(b);
  if (A.length !== B.length) throw new Error('cosineSimilarity: size mismatch');
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < A.length; i++) {
    dot += A[i] * B[i];
    na += A[i] * A[i];
    nb += B[i] * B[i];
  }
  return dot / (Math.sqrt(na) * Math.sqrt(nb) || 1);
}

export function euclideanDistance(a, b) {
  const A = Array.isArray(a) ? a : Array.from(a);
  const B = Array.isArray(b) ? b : Array.from(b);
  if (A.length !== B.length) throw new Error('euclideanDistance: size mismatch');
  let sum = 0;
  for (let i = 0; i < A.length; i++) {
    const d = A[i] - B[i];
    sum += d * d;
  }
  return Math.sqrt(sum);
}

export function descriptorToBase64(desc) {
  const buf = Buffer.from(new Float32Array(desc).buffer);
  return buf.toString('base64');
}

export function base64ToDescriptor(b64) {
  const buf = Buffer.from(b64, 'base64');
  return new Float32Array(buf.buffer, buf.byteOffset, buf.byteLength / 4);
}

// ----------------------------- Galerie-Matching ---------------------------------------------------

/**
 * Kandidatenstruktur:
 * [
 *   { id: 'userId1', name: 'Alice', descriptor: Float32Array(128) | Base64, meta?: {...} },
 *   ...
 * ]
 */
export function matchAgainstGallery(queryDescriptor, gallery, opts = {}) {
  const threshold = opts.threshold ?? DEFAULTS.SIMILARITY_THRESHOLD;
  const useCosine = opts.metric !== 'euclid';
  const q = l2Normalize(queryDescriptor);

  const scored = gallery.map(item => {
    let d = item.descriptor;
    if (!(d instanceof Float32Array)) {
      // Base64?
      d = typeof d === 'string' ? base64ToDescriptor(d) : Float32Array.from(d);
    }
    const v = l2Normalize(d);
    const sim = useCosine ? cosineSimilarity(q, v) : 1 / (1 + euclideanDistance(q, v)); // map 0..∞ → ~0..1
    return {
      id: item.id,
      name: item.name,
      score: sim,
      meta: item.meta || null,
      raw: item,
    };
  }).sort((a, b) => b.score - a.score);

  const top = scored[0] || null;
  const isMatch = !!top && top.score >= threshold;
  return {
    isMatch,
    top,
    scored,
    threshold,
    metric: useCosine ? 'cosine' : 'euclid->similarity',
  };
}

// ----------------------------- High-Level Helper --------------------------------------------------

/**
 * Vollpipeline:
 * 1) Qualität prüfen
 * 2) Gesicht extrahieren
 * 3) Gegen Galerie matchen
 */
export async function scanAndMatch(input, gallery, options = {}) {
  // 1) Qualität
  let quality = null;
  try {
    quality = await assessImageQuality(input);
  } catch {
    // Qualität fehlschlägt -> wir laufen weiter, aber markieren
    quality = { ok: false, reason: 'QUALITY_CHECK_FAILED' };
  }

  // 2) Embedding
  const emb = await extractSingleEmbedding(input, options);
  if (!emb.ok) {
    return {
      ok: false,
      stage: 'EMBEDDING',
      reason: emb.reason || 'UNKNOWN',
      quality,
    };
  }

  // 3) Matching
  const match = matchAgainstGallery(emb.descriptor, gallery, {
    threshold: options.threshold,
    metric: options.metric,
  });

  return {
    ok: true,
    quality,
    embedding: descriptorToBase64(emb.descriptor), // zum Speichern
    box: emb.box,
    score: emb.score,
    image: emb.image,
    match,
  };
}

// ----------------------------- Beispiel-Nutzung ---------------------------------------------------

/*
  // 1) Einmalig beim App-Start:
  await initFaceApi({ modelDir: path.join(process.cwd(), 'models/face-api') });

  // 2) Nutzer registrieren: Referenz-Embedding speichern (z. B. in MongoDB)
  const ref = await extractSingleEmbedding('/path/to/user1.jpg');
  if (ref.ok) {
    const save = descriptorToBase64(ref.descriptor);
    await db.users.updateOne({ _id: userId }, { $set: { faceTemplate: save } });
  }

  // 3) Beim Matching:
  const userDocs = await db.users.find({ faceTemplate: { $exists: true } }).toArray();
  const gallery = userDocs.map(u => ({ id: u._id, name: u.name, descriptor: u.faceTemplate }));
  const result = await scanAndMatch('/path/to/live.jpg', gallery, { threshold: 0.65 });
  if (result.ok && result.match.isMatch) {
    console.log('Top match:', result.match.top);
  }
*/

// ----------------------------- Export als Default-Objekt ------------------------------------------

const FaceScan = {
  initFaceApi,
  modelsLoaded,
  assessImageQuality,
  detectFacesAndEmbeddings,
  extractSingleEmbedding,
  l2Normalize,
  cosineSimilarity,
  euclideanDistance,
  descriptorToBase64,
  base64ToDescriptor,
  matchAgainstGallery,
  scanAndMatch,
  defaults: DEFAULTS,
};

export default FaceScan;