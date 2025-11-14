import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

export default function setupGooglePassport(db) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:5000/api/auth/google/callback",
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails[0].value;

          // Buscar usuario
          const [rows] = await db.query(
            "SELECT * FROM usuarios WHERE email = ?",
            [email]
          );

          // Crear si no existe
          if (rows.length === 0) {
            await db.query(
              "INSERT INTO usuarios (email, nombre) VALUES (?, ?)",
              [email, profile.displayName]
            );
          }

          return done(null, profile);
        } catch (err) {
          return done(err, null);
        }
      }
    )
  );

  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((obj, done) => done(null, obj));
}
