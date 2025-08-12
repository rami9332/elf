// utils/logger.js
// Kleine, unaufdringliche Logging-Helfer für Auth, Requests & Errors.
// Benannte Exports, damit `import { logAuthAttempt } from "./logger.js"` funktioniert.

import os from "os";

// ISO Zeitstempel
function ts() {
  return new Date().toISOString();
}

// IP aus Request ziehen (X-Forwarded-For berücksichtigen)
export function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length > 0) {
    // erster Eintrag ist Origin-IP
    return xf.split(",")[0].trim();
  }
  return req.ip || req.connection?.remoteAddress || "unknown";
}

/**
 * Auth-Versuche protokollieren (Login/Refresh/Blocked usw.)
 * Beispiel-Aufruf:
 * logAuthAttempt({
 *   outcome: "success" | "failure" | "blocked",
 *   reason: "invalid-password",
 *   userId: "abc123",
 *   email: "user@example.com",
 *   ip: getClientIp(req),
 *   ua: req.headers["user-agent"]
 * })
 */
export function logAuthAttempt({
  outcome,
  reason = "",
  userId = "",
  email = "",
  ip = "",
  ua = "",
  extra = {},
}) {
  const line = {
    type: "auth-attempt",
    time: ts(),
    outcome,         // success|failure|blocked
    reason,          // frei wählbar
    userId,
    email,
    ip,
    ua,
    host: os.hostname(),
    ...extra,
  };
  // aktuell Konsole; später an Log-Backend (ELK, Datadog, Sentry Breadcrumb) senden
  console.log(JSON.stringify(line));
}

/** Allgemeines Request-Logging (kann in server.js via app.use genutzt werden) */
export function logRequest(req, res, next) {
  const start = Date.now();
  const ip = getClientIp(req);
  const ua = req.headers["user-agent"] || "";
  res.on("finish", () => {
    const ms = Date.now() - start;
    const rec = {
      type: "http",
      time: ts(),
      method: req.method,
      url: req.originalUrl || req.url,
      status: res.statusCode,
      ms,
      ip,
      ua,
    };
    console.log(JSON.stringify(rec));
  });
  next();
}

/** Fehler-Logger (kann in zentralem Error-Handler verwendet werden) */
export function logError(err, ctx = {}) {
  const rec = {
    type: "error",
    time: ts(),
    name: err?.name || "Error",
    message: err?.message || String(err),
    stack: err?.stack || "",
    ...ctx,
  };
  console.error(JSON.stringify(rec));
}

/** Kleine Helper zum strukturierten Loggen beliebiger Events */
export function logEvent(event, payload = {}) {
  console.log(JSON.stringify({ type: event, time: ts(), ...payload }));
}

export default {
  getClientIp,
  logAuthAttempt,
  logRequest,
  logError,
  logEvent,
};