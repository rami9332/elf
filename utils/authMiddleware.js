// utils/authMiddleware.js
// ============================================================================
// Zentrale Authentifizierungs- und Sicherheits-Middleware für CYP
// ---------------------------------------------------------------------------
// Enthält:
//   • Token-Parsing (Bearer / Cookies) + Access-JWT verifizieren
//   • optionales/erzwungenes Login (optionalAuth / requireAuth)
//   • Rollen-Check (requireRoles)
//   • Refresh-Flow (rotateRefreshToken) mit Gerätebindung
//   • Kontext-Erfassung (IP, UA, Device-ID) & Audit-Logs
//   • Rate-Limiter (allgemein + empfindliche Routen)
//   • Biometrische Guards (Face/Fingerprint – mit Stubs)
//   • Psychologischer Guard (Scoring – mit Stub)
//   • Hilfsfunktionen (Token erstellen, Cookies setzen, …)
// ---------------------------------------------------------------------------

import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import User from "../models/User.js";

// RefreshToken ist optional – nur importieren, wenn Datei existiert
// Falls du (noch) kein Refresh-Model nutzt, lass die Datei einfach weg;
// alle Funktionen sind defensiv gebaut und funktionieren auch ohne.
let RefreshToken = null;
try {
  const mod = await import("../models/refreshToken.js");
  RefreshToken = mod.default || mod;
} catch {
  // kein Refresh-Model vorhanden – Funktionen verhalten sich "soft"
}

// optionales Logging
let logAuthAttempt = (_data) => {};
try {
  const mod = await import("./logger.js");
  logAuthAttempt = mod.logAuthAttempt || ((_d) => {});
} catch {
  // logger.js fehlt -> still
}

// Fingerprint- & Psychologie-Stubs (deine utils)
let runFingerprintStub = async () => ({ ok: true, score: 1.0, reason: "stub" });
try {
  const mod = await import("./fingerprint.js");
  runFingerprintStub = mod.runFingerprintStub || runFingerprintStub;
} catch {}

let runPsychologyCheckStub = async () => ({ ok: true, score: 1.0, traits: {}, reason: "stub" });
try {
  const mod = await import("./psychology.js");
  runPsychologyCheckStub = mod.runPsychologyCheckStub || runPsychologyCheckStub;
} catch {}

// Face-Stub direkt hier (bis echte Face‑API bereit ist)
const runFaceRecognitionStub = async () => ({
  ok: true,
  score: 0.98, // Ähnlichkeit 0..1
  reason: "stub",
});

// ---------------------------------------------------------------------------
// Konfiguration / Defaults
// ---------------------------------------------------------------------------

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const ACCESS_EXPIRES = process.env.ACCESS_EXPIRES || "1h";

const REFRESH_SECRET = process.env.REFRESH_SECRET || "dev_refresh_secret_change_me";
const REFRESH_EXPIRES_DAYS = Number(process.env.REFRESH_EXPIRY_DAYS || 30);

const COOKIE_SECURE = /^true$/i.test(process.env.COOKIE_SECURE || "false"); // prod: true
const COOKIE_SAME_SITE = (process.env.COOKIE_SAMESITE || "lax").toLowerCase(); // lax/strict/none

// Header-Namen für Gerätebindung & Kontext
const HDR_DEVICE_ID = process.env.HDR_DEVICE_ID || "x-device-id";
const HDR_APP_VERSION = process.env.HDR_APP_VERSION || "x-app-version";

// ---------------------------------------------------------------------------
// Rate-Limiter (exportieren, damit du sie pro Route einsetzen kannst)
// ---------------------------------------------------------------------------

export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 900,
  standardHeaders: true,
  legacyHeaders: false,
});

export const sensitiveLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "Too many requests. Try again later." },
});

// ---------------------------------------------------------------------------
// Hilfsfunktionen: Token lesen/schreiben
// ---------------------------------------------------------------------------

function getTokenFromReq(req) {
  // 1) Authorization: Bearer <token>
  const authHeader =
    req.headers?.authorization ||
    req.headers?.Authorization ||
    "";

  if (authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7).trim();
  }

  // 2) Cookie (falls du Access-Token als Cookie setzt)
  const cookieToken = req.cookies?.access_token;
  if (cookieToken) return cookieToken;

  return null;
}

export function setAuthCookies(res, { accessToken, refreshToken }) {
  if (accessToken) {
    res.cookie("access_token", accessToken, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAME_SITE,
      maxAge: 1000 * 60 * 60, // 1h default
      path: "/",
    });
  }
  if (refreshToken) {
    // refresh lieber als httpOnly Cookie – längere Lebensdauer
    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAME_SITE,
      maxAge: 1000 * 60 * 60 * 24 * REFRESH_EXPIRES_DAYS,
      path: "/api/auth", // z.B. nur unter /api/auth gültig
    });
  }
}

export function clearAuthCookies(res) {
  res.clearCookie("access_token", { path: "/" });
  res.clearCookie("refresh_token", { path: "/api/auth" });
}

// ---------------------------------------------------------------------------
// JWT erstellen / prüfen
// ---------------------------------------------------------------------------

export function signAccessToken(user, extra = {}) {
  const payload = {
    sub: String(user._id),
    role: user.role || "user",
    // hilfreiche Claims
    name: user.name,
    email: user.email,
    ...extra,
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_EXPIRES });
}

export function signRefreshToken(user, device = {}) {
  const payload = {
    sub: String(user._id),
    deviceId: device.id || "unknown",
    platform: device.platform || "unknown",
    app: device.version || "unknown",
  };
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: `${REFRESH_EXPIRES_DAYS}d` });
}

function verifyAccessToken(token) {
  try {
    return { ok: true, payload: jwt.verify(token, JWT_SECRET) };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

function verifyRefreshToken(token) {
  try {
    return { ok: true, payload: jwt.verify(token, REFRESH_SECRET) };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

// ---------------------------------------------------------------------------
// Kontext-Middleware: IP / UA / Device in req.context ablegen
// ---------------------------------------------------------------------------

export function contextCapture(req, _res, next) {
  const forwarded = req.headers["x-forwarded-for"];
  const ip = Array.isArray(forwarded)
    ? forwarded[0]
    : (forwarded || req.socket?.remoteAddress || "").split(",")[0].trim();

  req.context = {
    ip,
    ua: req.headers["user-agent"] || "",
    deviceId: req.headers[HDR_DEVICE_ID] || "",
    appVersion: req.headers[HDR_APP_VERSION] || "",
  };

  next();
}

// ---------------------------------------------------------------------------
// optionalAuth: hänge user an req, wenn Token gültig – sonst nur weiter
// ---------------------------------------------------------------------------

export async function optionalAuth(req, res, next) {
  const token = getTokenFromReq(req);
  if (!token) return next();

  const vr = verifyAccessToken(token);
  if (!vr.ok) return next();

  try {
    const user = await User.findById(vr.payload.sub).lean();
    if (!user) return next();
    req.user = user;
    req.auth = vr.payload;
    next();
  } catch (e) {
    next();
  }
}

// ---------------------------------------------------------------------------
// requireAuth: Zugriff nur mit gültigem Access-Token
// ---------------------------------------------------------------------------

export const authed = requireAuth;
export async function requireAuth(req, res, next) {
  const token = getTokenFromReq(req);
  if (!token) {
    return res.status(401).json({ ok: false, message: "Missing access token" });
  }
  const vr = verifyAccessToken(token);
  if (!vr.ok) {
    return res.status(401).json({ ok: false, message: "Invalid or expired token" });
  }

  try {
    const user = await User.findById(vr.payload.sub);
    if (!user) return res.status(401).json({ ok: false, message: "User not found" });

    req.user = user;
    req.auth = vr.payload;
    next();
  } catch (e) {
    next(e);
  }
}

// ---------------------------------------------------------------------------
// requireRoles: erfordert eine Rolle aus der Liste
// ---------------------------------------------------------------------------

export function requireRoles(...roles) {
  const allowed = new Set(roles.map(String));
  return (req, res, next) => {
    const role = req.auth?.role || req.user?.role || "user";
    if (!allowed.has(role)) {
      return res.status(403).json({ ok: false, message: "Insufficient permissions" });
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// Refresh‑Flow: Refresh-Token prüfen & rotieren (optional mit DB)
// ---------------------------------------------------------------------------

export async function rotateRefreshToken(req, res, next) {
  try {
    const incoming =
      req.body?.refreshToken ||
      req.cookies?.refresh_token ||
      req.headers["x-refresh-token"];

    if (!incoming) {
      return res.status(400).json({ ok: false, message: "Missing refresh token" });
    }

    const vr = verifyRefreshToken(incoming);
    if (!vr.ok) {
      return res.status(401).json({ ok: false, message: "Invalid refresh token" });
    }

    const user = await User.findById(vr.payload.sub);
    if (!user) return res.status(401).json({ ok: false, message: "User not found" });

    // Optional: gegen DB prüfen (revoked / Rotation / Device-Bindung)
    if (RefreshToken) {
      const rtDoc = await RefreshToken.findOne({ token: incoming, user: user._id });
      if (!rtDoc || rtDoc.revoked) {
        return res.status(401).json({ ok: false, message: "Refresh token revoked" });
      }
      // sofort rotieren: altes invalidieren
      rtDoc.revoked = true;
      rtDoc.revokedAt = new Date();
      await rtDoc.save();
    }

    const device = {
      id: req.headers[HDR_DEVICE_ID] || "unknown",
      platform: req.headers["x-platform"] || "",
      version: req.headers[HDR_APP_VERSION] || "",
    };

    const newAccess = signAccessToken(user);
    const newRefresh = signRefreshToken(user, device);

    if (RefreshToken) {
      await RefreshToken.create({
        user: user._id,
        token: newRefresh,
        deviceId: device.id,
        ip: req.context?.ip || "",
        userAgent: req.context?.ua || "",
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000 * REFRESH_EXPIRES_DAYS),
      });
    }

    setAuthCookies(res, { accessToken: newAccess, refreshToken: newRefresh });

    res.json({
      ok: true,
      accessToken: newAccess,
      refreshToken: newRefresh,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role || "user",
      },
    });
  } catch (e) {
    next(e);
  }
}

// ---------------------------------------------------------------------------
// Biometrische Guards (Face / Fingerprint) – Stubs, bis echte Modelle dran sind
// ---------------------------------------------------------------------------

/**
 * requireFaceMatch:
 * - Erwartet: Bild in `req.file` (multer memory) ODER URL in `req.body.imageUrl`
 * - Optional: `req.body.threshold` (0..1), default 0.6
 * - Optional: Nutzer muss `user.faceTemplate` besitzen (vom Enrollment)
 */
export async function requireFaceMatch(req, res, next) {
  try {
    const threshold = req.body?.threshold ? Number(req.body.threshold) : 0.6;
    const hasPhoto = !!(req.file?.buffer || req.body?.imageUrl);

    if (!hasPhoto) {
      return res.status(400).json({ ok: false, message: "Missing face image" });
    }
    if (!req.user?.faceTemplate) {
      return res.status(400).json({ ok: false, message: "User has no enrolled face template" });
    }

    // STUB: nutzt eingebauten Dummy
    const result = await runFaceRecognitionStub();

    logAuthAttempt({
      kind: "face",
      userId: String(req.user?._id || ""),
      score: result.score,
      ok: result.ok,
      ip: req.context?.ip,
      ua: req.context?.ua,
    });

    if (!result.ok || result.score < threshold) {
      return res.status(401).json({ ok: false, message: "Face match failed", score: result.score });
    }

    next();
  } catch (e) {
    next(e);
  }
}

/**
 * requireFingerprintMatch: analog zu Face
 */
export async function requireFingerprintMatch(req, res, next) {
  try {
    const threshold = req.body?.threshold ? Number(req.body.threshold) : 0.8;
    const result = await runFingerprintStub();

    logAuthAttempt({
      kind: "finger",
      userId: String(req.user?._id || ""),
      score: result.score,
      ok: result.ok,
      ip: req.context?.ip,
      ua: req.context?.ua,
    });

    if (!result.ok || result.score < threshold) {
      return res.status(401).json({ ok: false, message: "Fingerprint match failed", score: result.score });
    }
    next();
  } catch (e) {
    next(e);
  }
}

// ---------------------------------------------------------------------------
// Psychologie‑Guard (z. B. Mindestscore / bestimmte Traits erforderlich)
// ---------------------------------------------------------------------------

/**
 * requirePsychologyScore:
 *  - Options:
 *     minScore: 0..1 (default 0.5)
 *     requireTraits: { empathy: [0.6, 1], openness: [0.4, 1] } (Ranges)
 */
export function requirePsychologyScore(options = {}) {
  const { minScore = 0.5, requireTraits = {} } = options;

  return async (req, res, next) => {
    try {
      const result = await runPsychologyCheckStub(req.user);

      if (!result.ok) {
        return res.status(400).json({ ok: false, message: "Psychology check failed" });
      }

      if (typeof result.score === "number" && result.score < minScore) {
        return res.status(403).json({
          ok: false,
          message: "Psychology score too low",
          score: result.score,
        });
      }

      // Traits prüfen
      const traits = result.traits || {};
      for (const [trait, [min, max]] of Object.entries(requireTraits)) {
        const v = Number(traits[trait] ?? 0);
        if (Number.isFinite(min) && v < min) {
          return res.status(403).json({ ok: false, message: `Trait ${trait} below minimum` });
        }
        if (Number.isFinite(max) && v > max) {
          return res.status(403).json({ ok: false, message: `Trait ${trait} above maximum` });
        }
      }

      // Ergebnis an req hängen (für spätere Routen)
      req.psychology = result;
      next();
    } catch (e) {
      next(e);
    }
  };
}

// ---------------------------------------------------------------------------
// Kleine Helpers, die oft praktisch sind
// ---------------------------------------------------------------------------

/**
 * attachUser: lädt (optional) den User anhand von req.auth.sub
 */
export async function attachUser(req, _res, next) {
  try {
    if (req.auth?.sub && !req.user) {
      const u = await User.findById(req.auth.sub);
      if (u) req.user = u;
    }
  } catch {}
  next();
}

/**
 * audit: einfaches Audit-Log (kannst du per logger.js an externe Systeme schicken)
 */
export function audit(userOrId, action, details = {}) {
  const userId = typeof userOrId === "object" ? String(userOrId?._id || "") : String(userOrId || "");
  logAuthAttempt({
    kind: "audit",
    userId,
    action,
    details,
    at: new Date().toISOString(),
  });
}

// ---------------------------------------------------------------------------
// Export als Default-Bundle (Bequemlichkeit)
// ---------------------------------------------------------------------------

export default {
  contextCapture,
  optionalAuth,
  requireAuth,
  requireRoles,
  rotateRefreshToken,
  requireFaceMatch,
  requireFingerprintMatch,
  requirePsychologyScore,
  attachUser,
  audit,

  // Tokens/Cookies:
  signAccessToken,
  signRefreshToken,
  setAuthCookies,
  clearAuthCookies,

  // Limiter:
  generalLimiter,
  sensitiveLimiter,
};