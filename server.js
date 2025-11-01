// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mysql from "mysql2/promise"; // ✅ Usamos versión con promesas
import nodemailer from "nodemailer";
import crypto from "crypto";
import bcrypt from "bcryptjs";



dotenv.config();
const app = express();

app.use(cors({
  origin: "http://localhost:5173",
  credentials: true
}));
app.use(express.json());

// ✅ Conexión a base de datos (con promesas)
const db = await mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  connectionLimit: 10,
});

try {
  const conn = await db.getConnection();
  console.log("✅ Conectado a MySQL");
  conn.release();
} catch (err) {
  console.error("❌ Error al conectar a MySQL:", err);
  process.exit(1);
}

// ✅ Configuración del transporte de correo
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ✅ Ruta de registro con contraseña encriptada
app.post("/register", async (req, res) => {
  try {
    const { nombre, email, password, tipo_usuario = "Cliente" } = req.body;

    // 🔐 Encriptar contraseña
    const hashedPassword = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString("hex");

    const sql =
      "INSERT INTO usuarios (nombre, email, password, verificado, token, tipo_usuario) VALUES (?, ?, ?, ?, ?, ?)";
    await db.query(sql, [nombre, email, hashedPassword, 0, token, tipo_usuario]);

    // 📧 Enlace de verificación
    const verifyLink = `http://localhost:5000/verify?token=${token}`;
    const mailOptions = {
      from: `"Juguetería Martínez" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Verifica tu cuenta - Juguetería Martínez",
      html: `
        <h2>¡Hola ${nombre}!</h2>
        <p>Gracias por registrarte en <b>Juguetería Martínez</b>.</p>
        <p>Por favor, verifica tu cuenta haciendo clic en el siguiente enlace:</p>
        <a href="${verifyLink}" target="_blank"
          style="background:#F93B9A;color:white;padding:10px 20px;text-decoration:none;border-radius:6px;">
          Verificar mi cuenta
        </a>
        <p>Si tú no realizaste este registro, ignora este mensaje.</p>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.send("✅ Registro exitoso. Revisa tu correo para verificar tu cuenta.");
  } catch (err) {
    console.error("❌ Error en /register:", err);
    res.status(500).send("Error al registrar usuario");
  }
});

// ✅ Ruta de verificación de cuenta
app.get("/verify", async (req, res) => {
  try {
    const { token } = req.query;
    const [result] = await db.query("UPDATE usuarios SET verificado = 1 WHERE token = ?", [token]);

    if (result.affectedRows === 0) {
      return res.status(400).send("<h2>❌ Token inválido o ya usado</h2>");
    }

    res.send("<h2>✅ Tu cuenta ha sido verificada con éxito. Ya puedes iniciar sesión.</h2>");
  } catch (err) {
    console.error("❌ Error en /verify:", err);
    res.status(500).send("Error al verificar usuario");
  }
});

// ✅ Ruta de inicio de sesión
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.query("SELECT * FROM usuarios WHERE email = ?", [email]);
    if (rows.length === 0) {
      return res.status(400).json({ success: false, message: "Usuario no encontrado" });
    }

    const user = rows[0];

    // 🔐 Comparar contraseña encriptada
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ success: false, message: "Contraseña incorrecta" });
    }

    // ✅ Enviar tipo_usuario correctamente al frontend
// Normalizar tipo de usuario y devolver status 200
    const tipoUsuario = (user.tipo_usuario || "").toString().trim();
    res.status(200).json({
      success: true,
      message: "Inicio de sesión exitoso",
      tipo_usuario: tipoUsuario,
      verificado: !!user.verificado,
      email: user.email,
    });


  } catch (err) {
    console.error("❌ Error en /login:", err);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// ✅ Obtener todos los usuarios
app.get("/usuarios", async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, nombre, email, tipo_usuario, estado, verificado FROM usuarios"
    );
    res.json(rows);
  } catch (err) {
    console.error("❌ Error en /usuarios:", err);
    res.status(500).json({ message: "Error al obtener usuarios" });
  }
});

// ✅ Cambiar tipo de usuario (Cliente <-> Empleado)
app.put("/usuarios/:id/rol", async (req, res) => {
  const { id } = req.params;
  const { tipo_usuario } = req.body;

  try {
    await db.query("UPDATE usuarios SET tipo_usuario = ? WHERE id = ?", [
      tipo_usuario,
      id,
    ]);
    res.json({ success: true, message: "Rol actualizado correctamente" });
  } catch (err) {
    console.error("❌ Error en PUT /usuarios/:id/rol:", err);
    res.status(500).json({ message: "Error al actualizar rol" });
  }
});

// ✅ Bloquear / Desbloquear usuario
app.put("/usuarios/:id/estado", async (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;

  try {
    await db.query("UPDATE usuarios SET estado = ? WHERE id = ?", [estado, id]);
    res.json({ success: true, message: "Estado actualizado correctamente" });
  } catch (err) {
    console.error("❌ Error en PUT /usuarios/:id/estado:", err);
    res.status(500).json({ message: "Error al actualizar estado" });
  }
});

// ✅ Eliminar usuario
app.delete("/usuarios/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await db.query("DELETE FROM usuarios WHERE id = ?", [id]);
    res.json({ success: true, message: "Usuario eliminado correctamente" });
  } catch (err) {
    console.error("❌ Error en DELETE /usuarios/:id:", err);
    res.status(500).json({ message: "Error al eliminar usuario" });
  }
});


// 🚀 Iniciar servidor
app.listen(5000, () => {
  console.log("🚀 Servidor backend corriendo en http://localhost:5000");
});
