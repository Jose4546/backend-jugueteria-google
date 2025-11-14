// routes/authRoutes.js
import express from "express";
import passport from "passport";
import { registerUser, loginUser } from "../controllers/authController.js";

const router = express.Router();

/* ============================
   🔐 AUTH NORMAL (EMAIL/PASS)
   ============================ */
router.post("/register", registerUser);
router.post("/login", loginUser);

/* ============================
   🔵 LOGIN CON GOOGLE
   ============================ */

// 1️⃣ Redirige al login de Google
router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

// 2️⃣ Google redirige aquí después del login
router.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: "http://localhost:5173/login",
  }),
  (req, res) => {
    // SUCCESS ✔
    res.redirect("http://localhost:5173/cliente");
  }
);

export default router;

