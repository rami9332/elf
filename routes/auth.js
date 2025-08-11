// routes/auth.js
import { Router } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs"; // für Reset
import crypto from "crypto";
import User from "../models/User.js";
import PasswordReset from "../models/PasswordReset.js"; // <-- Wichtig: großes P!

// Social
import { OAuth2Client } from "google-auth-library";
import appleSignin from "apple-signin-auth";

// WebAuthn (Passkeys)
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

const router = Router();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ---------- Helpers ----------
function signToken(userId) {
  const secret = process.env.JWT_SECRET || "dev_secret_change_me";
  return jwt.sign({ sub: String(userId) }, secret, { expiresIn: "7d" });
}

const CLIENT_ORIGIN = (process.env.CLIENT_URL || "http://localhost:3000").replace(/\/$/, "");
const RP_ID = process.env.RP_ID || (CLIENT_ORIGIN.startsWith("http") ? new URL(CLIENT_ORIGIN).hostname : "localhost");
const RP_NAME = process.env.RP_NAME || "CYP";

// ======================================================================
// REGISTER
// ======================================================================
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

    const user = new User({ name, email });
    await user.setPassword(password); // setzt passwordHash
    await user.save();

    const token = signToken(user._id);
    res.status(201).json({ ok: true, token, user: { id: user._id, name, email } });
  } catch (e) {
    next(e);
  }
});

// ======================================================================
// LOGIN
// ======================================================================
router.post("/login", async (req, res, next) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!email || !password) return res.status(400).json({ message: "Missing email or password" });

    const user = await User.findOne({ email });
    if (!user || !user.passwordHash) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await user.comparePassword(password); // vergleicht passwordHash
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = signToken(user._id);
    res.json({ ok: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    next(e);
  }
});

// ======================================================================
// PASSWORD RESET
// ======================================================================
router.post("/request-password-reset", async (req, res, next) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ message: "Missing email" });

    const user = await User.findOne({ email }).lean();
    // kein User? trotzdem ok (nichts leaken)
    if (!user) return res.json({ ok: true });

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

    await PasswordReset.create({
      userId: user._id,
      tokenHash,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 Min
    });

    const resetUrl = `${CLIENT_ORIGIN}/reset-password?token=${rawToken}`;
    console.log("🔗 Password reset link:", resetUrl);

    res.json({ ok: true, message: "If the email exists, a reset link was sent." });
  } catch (e) {
    next(e);
  }
});

router.post("/reset-password", async (req, res, next) => {
  try {
    const rawToken = String(req.body.token || "");
    const newPassword = String(req.body.password || "");
    if (!rawToken || !newPassword) return res.status(400).json({ message: "Missing token or password" });

    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const entry = await PasswordReset.findOne({
      tokenHash,
      used: false,
      expiresAt: { $gt: new Date() },
    });
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

// ======================================================================
// GOOGLE LOGIN
// ======================================================================
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
    const googleId = payload.sub;
    const name = payload.name || email.split("@")[0];

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ name, email, googleId });
    } else if (!user.googleId) {
      user.googleId = googleId;
      await user.save();
    }

    const token = signToken(user._id);
    res.json({ ok: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    next(e);
  }
});

// ======================================================================
// APPLE LOGIN (Platzhalter – benötigt Apple Keys/Konfiguration)
// ======================================================================
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
    if (!user) {
      user = await User.create({ name, email, appleId });
    } else if (!user.appleId) {
      user.appleId = appleId;
      await user.save();
    }

    const token = signToken(user._id);
    res.json({ ok: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    next(e);
  }
});

// ======================================================================
// WEBAuthn (Passkeys) – an dein Model `webAuthn` angepasst
// ======================================================================

// Mini-Store für Challenges (in Prod: Redis/DB)
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
      excludeCredentials: user.webAuthn?.credentialId
        ? [
            {
              id: Buffer.from(user.webAuthn.credentialId, "base64url"),
              type: "public-key",
            },
          ]
        : [],
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
      expectedOrigin: CLIENT_ORIGIN,
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
    if (!user || !user.webAuthn?.credentialId) return res.status(404).json({ message: "No passkey for user" });

    const options = generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: [
        {
          id: Buffer.from(user.webAuthn.credentialId, "base64url"),
          type: "public-key",
        },
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
    if (!user?.webAuthn?.credentialId) return res.status(400).json({ message: "No credential stored" });

    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: pend.challenge,
      expectedOrigin: CLIENT_ORIGIN,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: Buffer.from(user.webAuthn.credentialId, "base64url"),
        credentialPublicKey: Buffer.from(user.webAuthn.publicKey, "base64url"),
        counter: user.webAuthn.signCount || 0,
        transports: assertionResponse?.response?.transports || [],
      },
    });

    if (!verification.verified) return res.status(400).json({ message: "Verification failed" });

    user.webAuthn.signCount = verification.authenticationInfo.newCounter || user.webAuthn.signCount;
    await user.save();

    pending.delete(String(userId));

    const token = signToken(user._id);
    res.json({ ok: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    next(e);
  }
});

export default router;