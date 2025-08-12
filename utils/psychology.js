// utils/psychology.js
// Psychological signal engine: linguistics, temporal patterns,
// friction analysis, trust/risk scoring, with bias guards and audit trail.
// Designed to be explainable and adjustable. No clinical claims.

// -------------------------- Config --------------------------
export const PSY_CONFIG = Object.freeze({
    weights: {
      // feature group weights (sum not required to be 1; normalized internally)
      linguistics: 0.35,
      temporal: 0.2,
      interaction: 0.2,
      device: 0.1,
      security: 0.15,
    },
    // score boundaries
    caps: {
      min: -1.0,
      max: +1.0,
    },
    // smoothing factor for rolling score
    smoothing: 0.6,
    // risk thresholds
    thresholds: {
      caution: 0.15,
      highRisk: -0.25,
    },
    // sensitive/bias features to **exclude** from signals
    bannedSignals: [
      "geo_country", "name_ethnicity", "gender_guess", "age_guess",
      "religion_guess", "politics_guess", "disability_guess",
    ],
  });
  
  // -------------------------- Utilities ------------------------
  const clamp = (x, lo, hi) => Math.max(lo, Math.min(hi, x));
  
  function zscore(x, mean = 0, std = 1) {
    const s = std <= 0 ? 1 : std;
    return (x - mean) / s;
  }
  
  function normalizeWeighted(parts, weights) {
    const entries = Object.entries(parts).map(([k, v]) => {
      const w = weights[k] ?? 0;
      return [k, w * v];
    });
    const total = entries.reduce((s, [, v]) => s + v, 0);
    const maxAbs = Math.max(1, ...entries.map(([, v]) => Math.abs(v)));
    return clamp(total / maxAbs, PSY_CONFIG.caps.min, PSY_CONFIG.caps.max);
  }
  
  // -------------------------- Feature Extractors ------------------------
  // Linguistic cues (very simplistic; replace by real NLP later).
  export function linguisticSignals(text = "") {
    const t = (text || "").trim();
    if (!t) return { clarity: 0, sentiment: 0, urgency: 0, toxicity: 0, length: 0 };
  
    const length = clamp(Math.log10(1 + t.length) / 3, 0, 1); // 0..~1
    const exclam = (t.match(/!/g) || []).length;
    const caps = (t.match(/[A-ZÄÖÜ]{3,}/g) || []).length;
    const urgentWords = /(dringend|sofort|jetzt|!!!|eilig|notfall)/i.test(t) ? 1 : 0;
  
    // naive sentiment proxy
    const pos = (t.match(/\b(gut|super|danke|top|freu|cool)\b/gi) || []).length;
    const neg = (t.match(/\b(schlecht|hilfe|problem|fehler|wütend|hasse)\b/gi) || []).length;
    const sentiment = clamp((pos - neg) / Math.max(1, pos + neg), -1, 1);
  
    // toxicity proxy
    const tox = /\b(idiot|dumm|schei|fuck|hate)\b/i.test(t) ? 1 : 0;
  
    return {
      clarity: 1 - Math.min(1, (exclam + caps) / 10), // more shouting -> less clarity
      sentiment,
      urgency: clamp(0.3 * urgentWords + 0.05 * exclam, 0, 1),
      toxicity: tox,
      length,
    };
  }
  
  // Temporal patterns: response latency, session cadence, hour‑of‑day variance.
  export function temporalSignals(events = []) {
    // events: [{ts, type}] sorted or not
    if (!Array.isArray(events) || events.length < 2) {
      return { rhythm: 0, nocturnal: 0, rushy: 0 };
    }
    const sorted = [...events].sort((a, b) => a.ts - b.ts);
    const deltas = [];
    for (let i = 1; i < sorted.length; i++) {
      deltas.push(Math.max(1, sorted[i].ts - sorted[i - 1].ts));
    }
    // lower variance => better rhythm
    const mean = deltas.reduce((s, x) => s + x, 0) / deltas.length;
    const variance = deltas.reduce((s, x) => s + Math.pow(x - mean, 2), 0) / deltas.length;
    const rhythm = clamp(1 - Math.tanh(Math.sqrt(variance) / (mean || 1)), 0, 1);
  
    const nocturnal = clamp(
      sorted.filter(e => {
        const h = new Date(e.ts).getHours();
        return h <= 5 || h >= 23;
      }).length / sorted.length,
      0, 1
    );
  
    const rushy = clamp(
      deltas.filter(d => d < 2_000).length / deltas.length,
      0, 1
    );
  
    return { rhythm, nocturnal, rushy };
  }
  
  // Interaction friction: retries, backtracks, errors.
  export function interactionSignals(metrics = {}) {
    const {
      retries = 0,
      backtracks = 0,
      errors = 0,
      steps = 1,
    } = metrics || {};
    const retryRate = clamp(retries / Math.max(1, steps), 0, 1);
    const backtrackRate = clamp(backtracks / Math.max(1, steps), 0, 1);
    const errorRate = clamp(errors / Math.max(1, steps), 0, 1);
  
    return {
      efficiency: 1 - 0.6 * retryRate - 0.4 * backtrackRate,
      stability: 1 - errorRate,
      perseverance: clamp(1 - 0.3 * (retryRate + backtrackRate), 0, 1),
    };
  }
  
  // Device/Context: switching, jitter, known/trusted device.
  export function deviceSignals(ctx = {}) {
    const {
      deviceChanges = 0,
      isTrustedDevice = false,
      networkJitterMs = 0,
      vpnOrProxy = false,
    } = ctx || {};
    return {
      consistency: clamp(1 - deviceChanges / 5, 0, 1),
      trust: isTrustedDevice ? 1 : 0.3,
      network: clamp(1 - zscore(networkJitterMs, 120, 1000), 0, 1),
      proxyPenalty: vpnOrProxy ? 0.2 : 0,
    };
  }
  
  // Security posture: 2FA usage, passkey presence, recent auth events.
  export function securitySignals(sec = {}) {
    const {
      twoFAEnabled = false,
      passkeysRegistered = 0,
      recentLockouts = 0,
    } = sec || {};
    return {
      multiFactor: twoFAEnabled ? 1 : 0,
      passkey: clamp(passkeysRegistered / 3, 0, 1),
      incidents: clamp(1 - recentLockouts / 3, 0, 1),
    };
  }
  
  // -------------------------- Bias Guard --------------------------------
  // Drop banned features from any ad‑hoc inputs.
  export function stripBannedSignals(obj = {}) {
    const out = { ...obj };
    for (const k of PSY_CONFIG.bannedSignals) {
      if (k in out) delete out[k];
    }
    return out;
  }
  
  // -------------------------- Main Engine -------------------------------
  /**
   * Build a psychological trust/risk score with explainability.
   * Returns { score: -1..+1, trust: 0..1, risk: 0..1, reasons: [], breakdown: {...}, nextActions: [] }
   */
  export function buildPsyProfile(input) {
    const {
      text = "",
      events = [],
      metrics = {},
      context = {},
      security = {},
      prevScore = 0,
    } = input || {};
  
    // Extract signals
    const ling = linguisticSignals(text);
    const temp = temporalSignals(events);
    const inter = interactionSignals(metrics);
    const dev = deviceSignals(context);
    const sec = securitySignals(security);
  
    // Aggregate by groups to reduce noise
    const parts = {
      linguistics: (
        +0.35 * ling.clarity +
        +0.25 * ling.sentiment +
        +0.15 * (1 - ling.toxicity) +
        +0.25 * (1 - Math.min(1, ling.urgency * 0.7))
      ), // higher is calmer/clearer
      temporal: (
        +0.6 * temp.rhythm +
        -0.2 * temp.nocturnal +
        -0.2 * temp.rushy
      ),
      interaction: (
        +0.6 * inter.efficiency +
        +0.3 * inter.stability +
        +0.1 * inter.perseverance
      ),
      device: (
        +0.5 * dev.consistency +
        +0.4 * dev.trust +
        +0.1 * dev.network -
        0.2 * dev.proxyPenalty
      ),
      security: (
        +0.5 * sec.multiFactor +
        +0.4 * sec.passkey +
        +0.1 * sec.incidents
      ),
    };
  
    // Normalize with weights
    const scoreRaw = normalizeWeighted(parts, PSY_CONFIG.weights);
    // Smooth with previous
    const score = clamp(
      PSY_CONFIG.smoothing * prevScore + (1 - PSY_CONFIG.smoothing) * scoreRaw,
      PSY_CONFIG.caps.min,
      PSY_CONFIG.caps.max
    );
  
    // Trust & risk mapping (simple)
    const trust = clamp((score + 1) / 2, 0, 1);  // -1..+1 -> 0..1
    const risk = 1 - trust;
  
    // Reasons and actions
    const reasons = [];
    if (ling.toxicity > 0) reasons.push("toxic_language");
    if (ling.urgency > 0.6) reasons.push("high_urgency");
    if (temp.nocturnal > 0.5) reasons.push("nocturnal_activity");
    if (inter.efficiency < 0.5) reasons.push("low_efficiency");
    if (security.twoFAEnabled === false) reasons.push("no_2fa");
    if (context.vpnOrProxy) reasons.push("proxy_or_vpn");
  
    const nextActions = [];
    if (risk > 0.6) {
      nextActions.push("require_passkey_or_2fa");
      nextActions.push("limit_sensitive_actions");
    } else if (risk > 0.35) {
      nextActions.push("passive_liveness_check");
      nextActions.push("extra_review_for_payments");
    } else {
      nextActions.push("allow_normal_flow");
    }
  
    return {
      score,
      trust,
      risk,
      reasons,
      breakdown: { ling, temp, inter, dev, sec, parts },
      nextActions,
      version: "psy-1.0",
    };
  }
  
  // -------------------------- Audit Trail -------------------------------
  export function explainProfile(profile) {
    const { score, trust, risk, reasons, nextActions } = profile;
    return {
      summary: {
        score,
        trust,
        risk,
        flags: reasons,
        actions: nextActions,
      },
      policy: {
        thresholds: PSY_CONFIG.thresholds,
        weights: PSY_CONFIG.weights,
        smoothing: PSY_CONFIG.smoothing,
        caps: PSY_CONFIG.caps,
      },
    };
  }