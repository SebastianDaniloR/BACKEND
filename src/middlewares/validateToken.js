import jwt from 'jsonwebtoken';
import { TOKEN_SECRET } from '../config.js';

export const authRequired = (req, res, next) => {
  const { token } = req.cookies;
  
  if (!token) {
    return res.status(401).json({ message: "No token, authorization denied" });
  }

  // Verificar el token y extraer el usuario
  jwt.verify(token, TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }

    // Asignar el usuario decodificado al request
    req.user = user; // Guardamos el usuario en `req.user`
    req.idUsuario = user.id; // Asignamos el id del usuario al campo `req.idUsuario`

    next();
  });
};
