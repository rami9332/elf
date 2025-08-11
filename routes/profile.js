// routes/profile.js
import { Router } from "express";
import requireAuth from "../middleware/auth.js";

const router = Router();

/**
 * GET /api/profile/me
 * Gibt die Daten des eingeloggten Users zurück.
 */
router.get("/me", requireAuth, async (req, res) => {
  const u = req.user;
  return res.json({
    ok: true,
    user: {
      id: u._id,
      name: u.name,
      email: u.email,
      createdAt: u.createdAt,
      updatedAt: u.updatedAt,
    },
  });
});

export default router;
