// controllers/passwordController.js
import crypto from "crypto";
import bcrypt from "bcryptjs";

export default function passwordController(db, transporter) {

  return {

    // ==========================================
    // 📩 1. Solicitar recuperación de contraseña
    // ==========================================
    forgotPassword: async (req, res) => {
      const { email } = req.body;

      try {
        const [rows] = await db.query("SELECT * FROM usuarios WHERE email = ?", [email]);

        if (rows.length === 0) {
          return res.status(400).json({ message: "El correo no está registrado." });
        }

        const token = crypto.randomBytes(32).toString("hex");
        const expires = new Date(Date.now() + 1000 * 60 * 15); // 15 minutos

        // 👉 Usa el nombre correcto de la columna en tu BD
        await db.query(
          "UPDATE usuarios SET reset_token = ?, reset_token_expires = ? WHERE email = ?",
          [token, expires, email]
        );

        // 👉 URL correcta para Vite + tu frontend
        const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

        await transporter.sendMail({
          from: `"Juguetería Martínez" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: "Restablecer contraseña",
          html: `
            <h3>Solicitud de restablecimiento de contraseña</h3>
            <p>Haz clic en el siguiente enlace:</p>
            <a href="${resetLink}">Restablecer contraseña</a>
            <p>Este enlace es válido por 15 minutos.</p>
          `,
        });

        res.json({ message: "Correo enviado. Revisa tu bandeja de entrada." });

      } catch (err) {
        console.error("❌ Error en forgotPassword:", err);
        res.status(500).json({ message: "Error en el servidor." });
      }
    },


    // ==========================================
    // 🔍 2. Validar token
    // ==========================================
    validateToken: async (req, res) => {
      const { token } = req.query;

      try {
        const [rows] = await db.query(
          "SELECT * FROM usuarios WHERE reset_token = ? AND reset_token_expires > NOW()",
          [token]
        );

        if (rows.length === 0) {
          return res.status(400).json({ message: "Token inválido o expirado." });
        }

        res.json({ message: "Token válido." });

      } catch (err) {
        console.error("❌ Error en validateToken:", err);
        res.status(500).json({ message: "Error en el servidor." });
      }
    },


    // ==========================================
    // 🔑 3. Restablecer contraseña
    // ==========================================
    resetPassword: async (req, res) => {
      const { token, password } = req.body;

      try {
        const [rows] = await db.query(
          "SELECT * FROM usuarios WHERE reset_token = ? AND reset_token_expires > NOW()",
          [token]
        );

        if (rows.length === 0) {
          return res.status(400).json({ message: "Token inválido o expirado." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await db.query(
          "UPDATE usuarios SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE reset_token = ?",
          [hashedPassword, token]
        );

        res.json({ message: "Contraseña restablecida correctamente." });

      } catch (err) {
        console.error("❌ Error en resetPassword:", err);
        res.status(500).json({ message: "Error en el servidor." });
      }
    }
  };
}

