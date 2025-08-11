// models/PasswordReset.js
import mongoose from "mongoose";

const passwordResetSchema = new mongoose.Schema(
  {
    userId:    { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    tokenHash: { type: String, required: true }, // SHA-256 des Reset-Tokens
    expiresAt: { type: Date,   required: true }, // Ablaufzeit
    used:      { type: Boolean, default: false }, // schon benutzt?
  },
  { timestamps: true }
);

// TTL-Index: löscht Dokumente automatisch nach Ablauf
passwordResetSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
passwordResetSchema.index({ tokenHash: 1 });

export default mongoose.model("PasswordReset", passwordResetSchema);