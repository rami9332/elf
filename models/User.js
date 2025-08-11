// models/User.js
import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema(
  {
    name:   { type: String, required: true, trim: true },
    email:  { type: String, required: true, unique: true, lowercase: true, index: true },
    passwordHash: { type: String, required: true },

    // optional für Social Logins / Passkeys
    googleId:   { type: String, index: true, sparse: true },
    appleId:    { type: String, index: true, sparse: true },
    webAuthn: {
      credentialId:   { type: String },   // base64url
      publicKey:      { type: String },   // base64url
      signCount:      { type: Number, default: 0 },
    },
  },
  { timestamps: true }
);

// Passwort setzen (Hashen)
userSchema.methods.setPassword = async function setPassword(plain) {
  const salt = await bcrypt.genSalt(10);
  this.passwordHash = await bcrypt.hash(plain, salt);
};

// Passwort prüfen
userSchema.methods.comparePassword = async function comparePassword(plain) {
  if (!this.passwordHash) return false;
  return bcrypt.compare(plain, this.passwordHash);
};

export default mongoose.model("User", userSchema);