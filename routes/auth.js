// routes/auth.js
/**
 * @file Auth Routes – Registration, Login, Refresh, Logout, Password Reset,
 *       Social logins (Google/Apple stubs), WebAuthn skeleton.
 *       Vollständig dokumentiert mit OpenAPI (Swagger JSDoc).
 */

import { Router } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import User from "../models/User.js";
import PasswordReset from "../models/PasswordReset.js";
import RefreshToken from "../models/refreshToken.js";

// Social (Stubs – echte Token kommen vom Client)
import { OAuth2Client } from "google-auth-library";
import appleSignin from "apple-signin-auth";

// WebAuthn (Skeleton – echte Ceremony im Client)
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

const router = Router();
const googleClient = process.env.GOOGLE_CLIENT_ID
  ? new OAuth2Client(process.env.GOOGLE_CLIENT_ID)
  : null;

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "dev_refresh_secret_change_me";
const ACCESS_EXPIRES = process.env.ACCESS_EXPIRES || "15m";
const REFRESH_EXPIRES = process.env.REFRESH_EXPIRES || "30d";

const RP_ID = process.env.RP_ID || "localhost";
const RP_NAME = process.env.RP_NAME || "CYP";

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

function signAccessToken(userId) {
  return jwt.sign({ sub: String(userId) }, JWT_SECRET, { expiresIn: ACCESS_EXPIRES });
}

function signRefreshToken(userId, tokenId) {
  // jti = Token ID (in DB wiederfindbar)
  return jwt.sign({ sub: String(userId), jti: tokenId }, REFRESH_SECRET, {
    expiresIn: REFRESH_EXPIRES,
  });
}

async function issueTokenPair(user) {
  // Refresh-Token in DB vermerken (Revocation möglich)
  const tokenId = crypto.randomUUID();
  const rt = await RefreshToken.create({
    user: user._id,
    tokenId,
    userAgent: "server-issued",
    ip: "server-issued",
    expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30), // 30 Tage
  });

  const accessToken = signAccessToken(user._id);
  const refreshToken = signRefreshToken(user._id, rt.tokenId);

  return { accessToken, refreshToken };
}

// kleine Rate-Limiter gegen bruteforce
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

/* ------------------------------------------------------------------ *
 * OpenAPI – Tag
 * ------------------------------------------------------------------ */
/**
 * @openapi
 * tags:
 *   - name: Auth
 *     description: Registrierung, Login, Tokens & Social
 */

/* ------------------------------------------------------------------ *
 * POST /api/auth/register
 * ------------------------------------------------------------------ */
/**
 * @openapi
 * /api/auth/register:
 *   post:
 *     tags: [Auth]
 *     summary: Benutzer registrieren
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, email, password]
 *             properties:
 *               name: { type: string, example: "Rami" }
 *               email: { type: string, example: "rami@example.com" }
 *               password: { type: string, example: "Cyp2025SecureDB" }
 *     responses:
 *       201:
 *         description: Erfolgreich registriert
 *       409:
 *         description: E-Mail existiert bereits
 *       400:
 *         description: Ungültige Eingabe
 */
router.post("/register", authLimiter, async (req, res, next) => {
  try {
    const name = (req.body.name || "").trim();
    const email = (req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Missing name, email or password" });
    }

    const existing = await User.findOne({ email }).lean();
    if (existing) return res.status(409).json({ message: "Email already registered" });

    const user = new User({ name, email });
    await user.setPassword(password);
    await user.save();

    const tokens = await issueTokenPair(user);

    res.status(201).json({
      ok: true,
      ...tokens,
      user: { id: user._id, name: user.name, email: user.email, role: user.role || "user" },
    });
  } catch (e) {
    next(e);
  }
});

/* ------------------------------------------------------------------ *
 * POST /api/auth/login
 * ------------------------------------------------------------------ */
/**
 * @openapi
 * /api/auth/login:
 *   post:
 *     tags: [Auth]
 *     summary: Login mit E-Mail & Passwort
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email: { type: string, example: "rami@example.com" }
 *               password: { type: string, example: "Cyp2025SecureDB" }
 *     responses:
 *       200:
 *         description: Token-Paar
 *       401:
 *         description: Ungültige Zugangsdaten
 */
router.post("/login", authLimiter, async (req, res, next) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!email || !password) return res.status(400).json({ message: "Missing email or password" });

    const user = await User.findOne({ email });
    if (!user || !user.passwordHash) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await user.comparePassword(password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const tokens = await issueTokenPair(user);
    res.json({
      ok: true,
      ...tokens,
      user: { id: user._id, name: user.name, email: user.email, role: user.role || "user" },
    });
  } catch (e) {
    next(e);
  }
});

/* ------------------------------------------------------------------ *
 * POST /api/auth/refresh
 * ------------------------------------------------------------------ */
/**
 * @openapi
 * /api/auth/refresh:
 *   post:
 *     tags: [Auth]
 *     summary: Access Token mit Refresh Token erneuern
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [refreshToken]
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: Neues Token-Paar
 *       401:
 *         description: Ungültiger Refresh Token
 */
router.post("/refresh", authLimiter, async (req, res, next) => {
  try {
    const refreshToken = String(req.body.refreshToken || "");
    if (!refreshToken) return res.status(400).json({ message: "Missing refreshToken" });

    let payload;
    try {
      payload = jwt.verify(refreshToken, REFRESH_SECRET);
    } catch {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    const rt = await RefreshToken.findOne({ tokenId: payload.jti, user: payload.sub, revokedAt: null });
    if (!rt) return res.status(401).json({ message: "Refresh token not found or revoked" });
    if (rt.expiresAt && rt.expiresAt.getTime() < Date.now()) {
      return res.status(401).json({ message: "Refresh token expired" });
    }

    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ message: "User not found" });

    const accessToken = signAccessToken(user._id);
    // Optional: rotierende Refresh-Tokens (hier gleich bleiben)
    res.json({
      ok: true,
      accessToken,
      refreshToken, // du kannst hier auch neu ausstellen und alten revoken
      user: { id: user._id, name: user.name, email: user.email, role: user.role || "user" },
    });
  } catch (e) {
    next(e);
  }
});

/* ------------------------------------------------------------------ *
 * POST /api/auth/logout
 * ------------------------------------------------------------------ */
/**
 * @openapi
 * /api/auth/logout:
 *   post:
 *     tags: [Auth]
 *     summary: Refresh Token invalidieren (Logout)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [refreshToken]
 *             properties:
 *               refreshToken: { type: string }
 *     responses:
 *       200:
 *         description: Erfolgreich ausgeloggt
 */
router.post("/logout", async (req, res, next) => {
  try {
    const refreshToken = String(req.body.refreshToken || "");
    if (!refreshToken) return res.status(400).json({ message: "Missing refreshToken" });

    try {
      const payload = jwt.verify(refreshToken, REFRESH_SECRET);
      await RefreshToken.findOneAndUpdate({ tokenId: payload.jti, user: payload.sub }, { revokedAt: new Date() });
    } catch {
      // egal – wir antworten ok, um Infos nicht zu leaken
    }
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

/* ------------------------------------------------------------------ *
 * Passwort Reset
 * ------------------------------------------------------------------ */
/**
 * @openapi
 * /api/auth/request-password-reset:
 *   post:
 *     tags: [Auth]
 *     summary: Passwort-Reset anfordern (E-Mail mit Reset-Link wird gesendet – hier console.log)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email]
 *             properties:
 *               email: { type: string, example: "rami@example.com" }
 *     responses:
 *       200:
 *         description: Immer OK (keine User-Existenz leaken)
 */
router.post("/request-password-reset", authLimiter, async (req, res, next) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ message: "Missing email" });

    const user = await User.findOne({ email }).lean();
    if (!user) return res.json({ ok: true });

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

    await PasswordReset.create({
      userId: user._id,
      tokenHash,
      expiresAt: new Date(Date.now() + 1000 * 60 * 15), // 15 Min
    });

    const base = (process.env.CLIENT_URL || "http://localhost:3000").replace(/\/$/, "");
    const resetUrl = `${base}/reset-password?token=${rawToken}`;
    console.log("🔗 Password reset link:", resetUrl);

    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

/**
 * @openapi
 * /api/auth/reset-password:
 *   post:
 *     tags: [Auth]
 *     summary: Passwort mit Reset-Token setzen
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [token, password]
 *             properties:
 *               token: { type: string }
 *               password: { type: string }
 *     responses:
 *       200:
 *         description: Passwort aktualisiert
 *       400:
 *         description: Token ungültig/abgelaufen
 */
router.post("/reset-password", authLimiter, async (req, res, next) => {
  try {
    const rawToken = String(req.body.token || "");
    const newPassword = String(req.body.password || "");
    if (!rawToken || !newPassword) return res.status(400).json({ message: "Missing token or password" });

    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const entry = await PasswordReset.findOne({ tokenHash, used: false, expiresAt: { $gt: new Date() } });
    if (!entry) return res.status(400).json({ message: "Invalid or expired token" });

    const user = await User.findById(entry.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    await user.setPassword(newPassword);
    await user.save();

    entry.used = true;
    await entry.save();

    res.json({ ok: true, message: "Password updated" });
  } catch (e) {
    next(e);
  }
});

/* ------------------------------------------------------------------ *
 * Social Logins (Stubs)
 * ------------------------------------------------------------------ */

/**
 * @openapi
 * /api/auth/google:
 *   post:
 *     tags: [Auth]
 *     summary: Google Login (ID Token vom Client)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [idToken]
 *             properties:
 *               idToken: { type: string }
 *     responses:
 *       200:
 *         description: Token-Paar
 */
router.post("/google", async (req, res, next) => {
  try {
    if (!googleClient) return res.status(501).json({ message: "Google not configured" });

    const idToken = String(req.body.idToken || "");
    if (!idToken) return res.status(400).json({ message: "Missing idToken" });

    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload?.email) return res.status(401).json({ message: "Invalid Google token" });

    const email = payload.email.toLowerCase();
    const googleId = payload.sub;
    const name = payload.name || email.split("@")[0];

    let user = await User.findOne({ email });
    if (!user) user = await User.create({ name, email, googleId });
    else if (!user.googleId) {
      user.googleId = googleId;
      await user.save();
    }

    const tokens = await issueTokenPair(user);
    res.json({ ok: true, ...tokens, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    next(e);
  }
});

/**
 * @openapi
 * /api/auth/apple:
 *   post:
 *     tags: [Auth]
 *     summary: Apple Login (Identity Token vom Client)
 */
router.post("/apple", async (req, res, next) => {
  try {
    const identityToken = String(req.body.identityToken || "");
    if (!identityToken) return res.status(400).json({ message: "Missing identityToken" });

    const resp = await appleSignin.verifyIdToken(identityToken, {
      audience: process.env.APPLE_CLIENT_ID,
    });

    const email = (resp.email || "").toLowerCase();
    const appleId = resp.sub;
    const name = req.body.name || email.split("@")[0];
    if (!email) return res.status(401).json({ message: "Invalid Apple token" });

    let user = await User.findOne({ email });
    if (!user) user = await User.create({ name, email, appleId });
    else if (!user.appleId) {
      user.appleId = appleId;
      await user.save();
    }

    const tokens = await issueTokenPair(user);
    res.json({ ok: true, ...tokens, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    next(e);
  }
});

/* ------------------------------------------------------------------ *
 * WebAuthn – Skeleton (Passkeys)
 * ------------------------------------------------------------------ */

const pending = new Map(); // userId -> { challenge }

router.get("/webauthn/registration/options", async (req, res, next) => {
  try {
    const email = (req.query.email || "").toString().toLowerCase();
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const options = generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: String(user._id),
      userName: email,
      attestationType: "none",
      excludeCredentials: (user.webAuthn?.credentialId
        ? [{ id: Buffer.from(user.webAuthn.credentialId, "base64url"), type: "public-key" }]
        : []),
    });

    pending.set(String(user._id), { challenge: options.challenge });
    res.json(options);
  } catch (e) {
    next(e);
  }
});

router.post("/webauthn/registration/verify", async (req, res, next) => {
  try {
    const { userId, attestationResponse } = req.body;
    const pend = pending.get(String(userId));
    if (!pend) return res.status(400).json({ message: "No registration in progress" });

    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge: pend.challenge,
      expectedOrigin: req.headers.origin || `http://${RP_ID}:3000`,
      expectedRPID: RP_ID,
    });

    if (!verification.verified) return res.status(400).json({ message: "Verification failed" });

    const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

    const user = await User.findById(userId);
    user.webAuthn = {
      credentialId: Buffer.from(credentialID).toString("base64url"),
      publicKey: Buffer.from(credentialPublicKey).toString("base64url"),
      signCount: counter,
    };
    await user.save();

    pending.delete(String(userId));
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

router.get("/webauthn/authentication/options", async (req, res, next) => {
  try {
    const email = (req.query.email || "").toString().toLowerCase();
    const user = await User.findOne({ email });
    if (!user?.webAuthn?.credentialId) return res.status(404).json({ message: "No passkeys" });

    const options = generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: [
        { id: Buffer.from(user.webAuthn.credentialId, "base64url"), type: "public-key" },
      ],
      userVerification: "preferred",
    });

    pending.set(String(user._id), { challenge: options.challenge });
    res.json({ ...options, userId: String(user._id) });
  } catch (e) {
    next(e);
  }
});

router.post("/webauthn/authentication/verify", async (req, res, next) => {
  try {
    const { userId, assertionResponse } = req.body;
    const pend = pending.get(String(userId));
    if (!pend) return res.status(400).json({ message: "No authentication in progress" });

    const user = await User.findById(userId);
    if (!user?.webAuthn?.credentialId) return res.status(400).json({ message: "No passkeys" });

    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: pend.challenge,
      expectedOrigin: req.headers.origin || `http://${RP_ID}:3000`,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: Buffer.from(user.webAuthn.credentialId, "base64url"),
        credentialPublicKey: Buffer.from(user.webAuthn.publicKey, "base64url"),
        counter: user.webAuthn.signCount,
        transports: assertionResponse?.response?.transports || [],
      },
    });

    if (!verification.verified) return res.status(400).json({ message: "Verification failed" });
    user.webAuthn.signCount = verification.authenticationInfo.newCounter;
    await user.save();

    pending.delete(String(userId));

    const tokens = await issueTokenPair(user);
    res.json({ ok: true, ...tokens, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    next(e);
  }
});

export default router;