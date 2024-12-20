import { TOKEN_SECRET } from "../config.js";
import jwt from 'jsonwebtoken';

export function createAccessToken(payload) {
  return new Promise((resolve, reject) => {
    if (!TOKEN_SECRET) {
      return reject(new Error("TOKEN_SECRET is not defined"));
    }

    jwt.sign(
      payload, // Datos del usuario
      TOKEN_SECRET, // Clave secreta
      {
        expiresIn: "1d", // Tiempo de expiración del token
      },
      (err, token) => {
        if (err) {
          console.error("Error al crear el token:", err);
          reject(err);
        } else {
          resolve(token);
        }
      }
    );
  });
}
