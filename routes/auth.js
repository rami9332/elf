// routes/auth.js
import { Router } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import User from "../models/User.js";
import PasswordReset from "../models/passwordReset.js";

// Social
import { OAuth2Client } from "google-auth-library";
import appleSignin from "apple-signin-auth";

// WebAuthn
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

const router = Router();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ----------------- Helpers -----------------
function signToken(userId) {
  const secret = process.env.JWT_SECRET || "dev_secret_change_me";
  return jwt.sign({ sub: String(userId) }, secret, { expiresIn: "7d" });
}
const RP_ID = process.env.RP_ID || "localhost";
const RP_NAME = process.env.RP_NAME || "CYP Demo";

// ----------------- Register ----------------
router.post("/register", async (req, res, next) => {
  try {
    const name = (req.body.name || "").trim();
    const email = (req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Missing name, email or password" });
    }
    const existing = await User.findOne({ email }).lean();
    if (existing) return res.status(409).json({ message: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hash });

    const token = signToken(user._id);
    res.status(201).json({ ok: true, token, user: { id: user._id, name, email } });
  } catch (e) {
    next(e);
  }
});

// ----------------- Login -------------------
router.post("/login", async (req, res, next) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!email || !password) return res.status(400).json({ message: "Missing email or password" });

    const user = await User.findOne({ email });
    if (!user || !user.password) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = signToken(user._id);
    res.json({ ok: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    next(e);
  }
});

// ======================================================================
//                      PASSWORD RESET
// ======================================================================

// 1) Reset anfordern
router.post("/request-password-reset", async (req, res, next) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ message: "Missing email" });

    const user = await User.findOne({ email }).lean();
    // Keine Information leaken, ob es den User gibt:
    if (!user) return res.json({ ok: true });

    // Token generieren & als Hash speichern
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

    await PasswordReset.create({
      userId: user._id,
      tokenHash,
      expiresAt: new Date(Date.now() + 1000 * 60 * 15), // 15 Min
    });

    const resetUrl = `${process.env.CLIENT_URL?.replace(/\/$/, "") || "http://localhost:3000"}/reset-password?token=${rawToken}`;
    // TODO: E-Mail versenden – jetzt erstmal in die Konsole:
    console.log("🔗 Password reset link:", resetUrl);

    res.json({ ok: true, message: "If the email exists, a reset link was sent." });
  } catch (e) {
    next(e);
  }
});

// 2) Passwort setzen
router.post("/reset-password", async (req, res, next) => {
  try {
    const rawToken = String(req.body.token || "");
    const newPassword = String(req.body.password || "");
    if (!rawToken || !newPassword) return res.status(400).json({ message: "Missing token or password" });

    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const entry = await PasswordReset.findOne({ tokenHash, used: false, expiresAt: { $gt: new Date() } });
    if (!entry) return res.status(400).json({ message: "Invalid or expired token" });

    const user = await User.findById(entry.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    entry.used = true;
    await entry.save();

    res.json({ ok: true, message: "Password updated" });
  } catch (e) {
    next(e);
  }
});

// ======================================================================
//                      SOCIAL LOGINS
// ======================================================================

// Google: Client liefert ein ID Token (Google One Tap / Client OAuth)
router.post("/google", async (req, res, next) => {
  try {
    const idToken = String(req.body.idToken || "");
    if (!idToken) return res.status(400).json({ message: "Missing idToken" });

    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload || !payload.email) return res.status(401).json({ message: "Invalid Google token" });

    const email = payload.email.toLowerCase();
    const providerId = payload.sub;
    const name = payload.name || email.split("@")[0];

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ name, email, provider: "google", providerId });
    } else if (!user.provider) {
      user.provider = "google";
      user.providerId = providerId;
      await user.save();
    }

    const token = signToken(user._id);
    res.json({ ok: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    next(e);
  }
});

// Apple (Platzhalter – brauchst Team-ID, Key-ID, private key etc.)
router.post("/apple", async (req, res, next) => {
  try {
    const identityToken = String(req.body.identityToken || "");
    if (!identityToken) return res.status(400).json({ message: "Missing identityToken" });

    // Doku: https://github.com/ananay/apple-signin-auth
    const resp = await appleSignin.verifyIdToken(identityToken, {
      audience: process.env.APPLE_CLIENT_ID, // Bundle ID / Service ID
    });

    const email = (resp.email || "").toLowerCase();
    const providerId = resp.sub;
    const name = req.body.name || email.split("@")[0];

    if (!email) return res.status(401).json({ message: "Invalid Apple token" });

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ name, email, provider: "apple", providerId });
    } else if (!user.provider) {
      user.provider = "apple";
      user.providerId = providerId;
      await user.save();
    }

    const token = signToken(user._id);
    res.json({ ok: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    next(e);
  }
});

// ======================================================================
//                      WEBAuthn / PASSKEYS (Skeleton)
// ======================================================================

// In-Memory Challenge-Store für Demo (in Prod z.B. Redis)
const pending = new Map(); // key: userId -> { challenge }

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
      // existierende Credentials ausschließen:
      excludeCredentials: user.passkeys.map(pk => ({ id: Buffer.from(pk.credId, "base64url"), type: "public-key" })),
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
    user.passkeys.push({
      credId: Buffer.from(credentialID).toString("base64url"),
      publicKey: Buffer.from(credentialPublicKey).toString("base64url"),
      counter,
      transports: attestationResponse?.response?.transports || [],
    });
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
    if (!user || !user.passkeys.length) return res.status(404).json({ message: "No passkeys" });

    const options = generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: user.passkeys.map(pk => ({
        id: Buffer.from(pk.credId, "base64url"),
        type: "public-key",
      })),
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
    const cred = user.passkeys.find(pk => pk.credId === assertionResponse.id);
    if (!cred) return res.status(400).json({ message: "Unknown credential" });

    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: pend.challenge,
      expectedOrigin: req.headers.origin || `http://${RP_ID}:3000`,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: Buffer.from(cred.credId, "base64url"),
        credentialPublicKey: Buffer.from(cred.publicKey, "base64url"),
        counter: cred.counter,
        transports: cred.transports || [],
      },
    });

    if (!verification.verified) return res.status(400).json({ message: "Verification failed" });

    cred.counter = verification.authenticationInfo.newCounter;
    await user.save();

    pending.delete(String(userId));

    const token = signToken(user._id);
    res.json({ ok: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    next(e);
  }
});

export default router;