// controllers/authController.js
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";
import sql from "mssql"; // si usas SQL Server
import dotenv from "dotenv";

dotenv.config();

// Configuración de conexión SQL Server
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  server: process.env.DB_HOST,
  database: process.env.DB_NAME,
  options: {
    encrypt: true,
    trustServerCertificate: true,
  },
};

// 👉 REGISTRO DE USUARIO
export const registerUser = async (req, res) => {
  const { nombre, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await sql.connect(dbConfig);
    const result = await sql.query`SELECT * FROM Usuarios WHERE email = ${email}`;
    if (result.recordset.length > 0)
      return res.status(400).send("El correo ya está registrado.");

    await sql.query`
      INSERT INTO Usuarios (nombre, email, password)
      VALUES (${nombre}, ${email}, ${hashedPassword})
    `;

    // Enviar correo de verificación
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const verifyLink = `http://localhost:5000/verify?email=${encodeURIComponent(email)}`;
    await transporter.sendMail({
      from: `"Juguetería Martínez" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Verifica tu cuenta",
      html: `<h3>Hola ${nombre}!</h3>
             <p>Haz clic en el siguiente enlace para verificar tu cuenta:</p>
             <a href="${verifyLink}">Verificar cuenta</a>`,
    });

    res.send("Registro exitoso. Verifica tu correo electrónico.");
  } catch (err) {
    console.error("❌ Error en registerUser:", err);
    res.status(500).send("Error al registrar usuario.");
  }
};

// 👉 LOGIN DE USUARIO
export const loginUser = async (req, res) => {
  const { email, password } = req.body;
  try {
    await sql.connect(dbConfig);
    const result = await sql.query`SELECT * FROM Usuarios WHERE email = ${email}`;
    if (result.recordset.length === 0)
      return res.status(400).send("Usuario no encontrado.");

    const user = result.recordset[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).send("Contraseña incorrecta.");

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({ message: "Inicio de sesión exitoso", token });
  } catch (err) {
    console.error("❌ Error en loginUser:", err);
    res.status(500).send("Error al iniciar sesión.");
  }
};
