// utils/fingerprint.js
// Fingerprint pipeline: normalization, feature extraction (hash-based stand‑in),
// similarity scoring, basic liveness checks, throttling hooks, and storage adapter.
// ESM module.

// --------------------------- Imports & Types ---------------------------
import crypto from "crypto";

// Helpers
const now = () => Date.now();
const clamp01 = (x) => Math.max(0, Math.min(1, x));
const toBase64Url = (buf) =>
  Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// --------------------------- Config -----------------------------------
export const FP_CONFIG = Object.freeze({
  minImageBytes: 2_000,            // ~2 KB minimale Bildgröße (reine Heuristik gegen leer/zu klein)
  maxImageBytes: 8 * 1024 * 1024,  // 8 MB
  minDpiGuess: 200,                // Fingerabdrucksensor meist 300–500 dpi – Heuristik
  liveness: {
    enabled: true,
    minVariations: 2,              // z. B. zwei leicht unterschiedliche Frames nötig
    maxStaticSimilarity: 0.995,    // zu gleich -> möglicherweise Foto/Kopie
  },
  similarity: {
    acceptThreshold: 0.86,         // Accept wenn >=
    reviewThreshold: 0.78,         // Manuelle Review wenn zwischen review und accept
  },
  throttle: {
    windowMs: 10 * 60 * 1000,      // 10 Minuten
    maxAttemptsPerUser: 10,
    maxAttemptsPerIp: 40,
  },
});

// --------------------------- Errors -----------------------------------
export class FingerprintError extends Error {
  constructor(message, code = "FP_ERROR", status = 400, extra = {}) {
    super(message);
    this.name = "FingerprintError";
    this.code = code;
    this.status = status;
    this.extra = extra;
  }
}

// --------------------------- Storage Port ------------------------------
// Plug‑in store so you can swap DBs easily (Mongo, Redis, etc.)
export class IFingerprintStore {
  /** @param {string} userId */
  async getTemplates(userId) { throw new Error("not implemented"); }
  /** @param {string} userId @param {object} tpl */
  async addTemplate(userId, tpl) { throw new Error("not implemented"); }
  /** @param {string} userId @param {string} templateId */
  async removeTemplate(userId, templateId) { throw new Error("not implemented"); }
  /** @param {string} key @param {number} windowMs */
  async getAttempts(key, windowMs) { throw new Error("not implemented"); }
  /** @param {string} key */
  async addAttempt(key) { throw new Error("not implemented"); }
}

// In‑Memory default (for dev). Replace with DB impl in prod.
export class MemoryFingerprintStore extends IFingerprintStore {
  constructor() {
    super();
    this.templates = new Map(); // userId -> [{id, featuresHash, createdAt, meta}]
    this.attempts = new Map();  // key -> [timestamps]
  }
  async getTemplates(userId) {
    return this.templates.get(userId) || [];
  }
  async addTemplate(userId, tpl) {
    const cur = this.templates.get(userId) || [];
    cur.push({ ...tpl, createdAt: now() });
    this.templates.set(userId, cur);
  }
  async removeTemplate(userId, templateId) {
    const cur = this.templates.get(userId) || [];
    this.templates.set(userId, cur.filter(x => x.id !== templateId));
  }
  async getAttempts(key, windowMs) {
    const list = this.attempts.get(key) || [];
    const cutoff = now() - windowMs;
    const pruned = list.filter(t => t >= cutoff);
    this.attempts.set(key, pruned);
    return pruned.length;
  }
  async addAttempt(key) {
    const list = this.attempts.get(key) || [];
    list.push(now());
    this.attempts.set(key, list);
  }
}

// --------------------------- Preprocess --------------------------------
// Simple checks to avoid garbage input. Real systems should decode image,
// check resolution, finger area, ridge clarity, etc.
export function basicIntegrityCheck(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new FingerprintError("Invalid input: expected binary buffer", "FP_INPUT", 400);
  }
  if (buffer.length < FP_CONFIG.minImageBytes) {
    throw new FingerprintError("Image too small", "FP_SIZE_MIN", 422);
  }
  if (buffer.length > FP_CONFIG.maxImageBytes) {
    throw new FingerprintError("Image too large", "FP_SIZE_MAX", 413);
  }
  // quick magic header sniff (PNG/JPEG fallback ok; scanners often give bitmap-like)
  const hex2 = buffer.subarray(0, 2).toString("hex");
  const isJpeg = hex2 === "ffd8";
  const isPng = buffer.subarray(0, 8).toString("hex") === "89504e470d0a1a0a";
  if (!isJpeg && !isPng) {
    // we allow anyway, just warn by flag
    return { ok: true, format: "unknown" };
  }
  return { ok: true, format: isJpeg ? "jpeg" : "png" };
}

// --------------------------- Feature Extraction (Stand‑in) -------------
// Hash‑based representation. Real system would compute minutiae map/orientation field.
export function extractFeaturesHash(buffer, salt = "") {
  const h = crypto.createHash("sha3-256");
  h.update(buffer);
  if (salt) h.update(String(salt));
  const digest = h.digest();
  // produce stable feature string
  return toBase64Url(digest);
}

// derive a pseudo “ridge” vector from the same digest to enable a cosine‑like similarity
function digestToVec(b64) {
  const bin = Buffer.from(b64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const vec = new Float64Array(Math.ceil(bin.length / 8));
  for (let i = 0; i < vec.length; i++) {
    const slice = bin.subarray(i * 8, i * 8 + 8);
    const int = slice.reduce((acc, v, k) => acc + (v << (k * 1)), 0); // rough
    vec[i] = int % 9973; // prime mod to keep bounded
  }
  // normalize
  const norm = Math.sqrt(vec.reduce((s, x) => s + x * x, 0)) || 1;
  for (let i = 0; i < vec.length; i++) vec[i] /= norm;
  return vec;
}

function cosine(a, b) {
  const L = Math.min(a.length, b.length);
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < L; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb) || 1;
  return clamp01((dot / denom + 1) / 2); // map [-1,1] to [0,1]
}

// --------------------------- Liveness (Heuristics) ---------------------
// Dummy checks: entropy, variation across frames, "too static" blocklist.
export function estimateEntropy(buffer) {
  // simple byte histogram entropy
  const hist = new Array(256).fill(0);
  for (const v of buffer) hist[v]++;
  const N = buffer.length || 1;
  let H = 0;
  for (let i = 0; i < 256; i++) {
    const p = hist[i] / N;
    if (p > 0) H -= p * Math.log2(p);
  }
  // 0..8 (bytes). Higher is "richer"
  return H / 8;
}

export function livenessCheckSingle(buffer) {
  const ent = estimateEntropy(buffer);
  // Arbitrary heuristic: very low entropy suggests printed/flat image
  const pass = ent > 0.35;
  return { pass, entropy: ent };
}

export function livenessCheckMulti(buffers) {
  if (!Array.isArray(buffers) || buffers.length < FP_CONFIG.liveness.minVariations) {
    return { pass: false, reason: "INSUFFICIENT_FRAMES" };
  }
  const hashes = buffers.map(b => extractFeaturesHash(b));
  const vecs = hashes.map(digestToVec);
  // compute max similarity between frames; if too high -> probably exact copy
  let maxSim = 0;
  for (let i = 0; i < vecs.length; i++) {
    for (let j = i + 1; j < vecs.length; j++) {
      maxSim = Math.max(maxSim, cosine(vecs[i], vecs[j]));
    }
  }
  if (maxSim >= FP_CONFIG.liveness.maxStaticSimilarity) {
    return { pass: false, reason: "STATIC_DUPLICATE", maxSimilarity: maxSim };
  }
  // all singles must pass basic entropy
  const singles = buffers.map(livenessCheckSingle);
  const allPass = singles.every(s => s.pass);
  return { pass: allPass, maxSimilarity: maxSim, singles };
}

// --------------------------- Throttling --------------------------------
async function ensureNotThrottled(store, userKey, ipKey) {
  const w = FP_CONFIG.throttle.windowMs;
  const userAttempts = await store.getAttempts(`user:${userKey}`, w);
  const ipAttempts = await store.getAttempts(`ip:${ipKey}`, w);
  if (userAttempts >= FP_CONFIG.throttle.maxAttemptsPerUser) {
    throw new FingerprintError("Too many attempts (user). Try later.", "FP_RATELIMIT_USER", 429, { userAttempts });
  }
  if (ipAttempts >= FP_CONFIG.throttle.maxAttemptsPerIp) {
    throw new FingerprintError("Too many attempts (ip). Try later.", "FP_RATELIMIT_IP", 429, { ipAttempts });
  }
  await store.addAttempt(`user:${userKey}`);
  await store.addAttempt(`ip:${ipKey}`);
}

// --------------------------- Public API --------------------------------
/**
 * Enroll a new fingerprint template for a user.
 * @param {Buffer|Uint8Array} imageBuffer
 * @param {Object} ctx { userId, ip, device }
 * @param {IFingerprintStore} store
 */
export async function fingerprintEnroll(imageBuffer, ctx, store = new MemoryFingerprintStore()) {
  basicIntegrityCheck(imageBuffer);
  const { userId = "anonymous", ip = "0.0.0.0" } = ctx || {};
  await ensureNotThrottled(store, userId, ip);

  if (FP_CONFIG.liveness.enabled) {
    const live = livenessCheckSingle(imageBuffer);
    if (!live.pass) {
      throw new FingerprintError("Liveness failed", "FP_LIVENESS_FAIL", 422, { details: live });
    }
  }

  const featuresHash = extractFeaturesHash(Buffer.from(imageBuffer));
  const template = {
    id: crypto.randomUUID(),
    featuresHash,
    meta: { format: "generic", device: ctx?.device || "unknown" },
  };
  await store.addTemplate(String(userId), template);
  return { ok: true, templateId: template.id, featuresHash };
}

/**
 * Verify a presented finger against enrolled templates.
 * @param {Buffer|Uint8Array} imageBuffer
 * @param {Object} ctx { userId, ip }
 * @param {IFingerprintStore} store
 */
export async function fingerprintVerify(imageBuffer, ctx, store = new MemoryFingerprintStore()) {
  basicIntegrityCheck(imageBuffer);
  const { userId = "anonymous", ip = "0.0.0.0" } = ctx || {};
  await ensureNotThrottled(store, userId, ip);

  const templates = await store.getTemplates(String(userId));
  if (!templates.length) {
    throw new FingerprintError("No templates enrolled", "FP_NO_TEMPLATES", 404);
  }

  // Optional multi-frame liveness could be used here if available.
  if (FP_CONFIG.liveness.enabled) {
    const live = livenessCheckSingle(imageBuffer);
    if (!live.pass) {
      throw new FingerprintError("Liveness failed", "FP_LIVENESS_FAIL", 422, { details: live });
    }
  }

  const probeHash = extractFeaturesHash(Buffer.from(imageBuffer), "verify");
  const probeVec = digestToVec(probeHash);

  let best = { templateId: null, score: 0 };
  for (const tpl of templates) {
    const vec = digestToVec(tpl.featuresHash);
    const sim = cosine(probeVec, vec);
    if (sim > best.score) best = { templateId: tpl.id, score: sim };
  }

  const { acceptThreshold, reviewThreshold } = FP_CONFIG.similarity;
  const decision =
    best.score >= acceptThreshold ? "ACCEPT" :
    best.score >= reviewThreshold ? "REVIEW" : "REJECT";

  return {
    ok: decision !== "REJECT",
    decision,
    score: Number(best.score.toFixed(4)),
    matchedTemplateId: best.templateId,
  };
}