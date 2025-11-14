// routes/PasswordRoutes.js

import { Router } from "express";
import passwordController from "../controllers/passwordController.js";

export default function resetPasswordRoutes(db, transporter) {
  const router = Router();
  const controller = passwordController(db, transporter);

  // 📩 Enviar correo de recuperación
  router.post("/forgot-password", controller.forgotPassword);

  // 🔍 Validar token de recuperación
  router.get("/validate-reset-token", controller.validateToken);

  // 🔑 Restablecer contraseña
  router.post("/reset-password", controller.resetPassword);

  return router;
}
