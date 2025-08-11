// middleware/auth.js
import jwt from "jsonwebtoken";
import User from "../models/User.js";

/**
 * Liest den Bearer-Token aus dem Authorization-Header,
 * verifiziert ihn und hängt den User an req.user.
 */
export default async function requireAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const [, token] = auth.split(" ");

    if (!token) {
      return res.status(401).json({ message: "Missing bearer token" });
    }

    const secret = process.env.JWT_SECRET || "dev_secret_change_me";
    const payload = jwt.verify(token, secret); // { sub: <userId>, iat, exp }

    const user = await User.findById(payload.sub).lean();
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    req.user = user; // steht in nachfolgenden Handlern bereit
    next();
  } catch (err) {
    console.error("Auth middleware error:", err.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}