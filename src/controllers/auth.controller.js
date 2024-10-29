import User from '../models/user.model.js';
import bcrypt from 'bcryptjs';
import { createAccessToken } from '../libs/jwt.js';
import jwt from 'jsonwebtoken';
import { TOKEN_SECRET } from '../config.js';

// Registro de usuario
export const register = async (req, res) => {
  const { email, password, username, cedula, cargo, ciudad, role = 'user' } = req.body;
  try {
    console.log('Datos recibidos:', { email, password, username, cedula, cargo, ciudad, role });

    const emailFound = await User.findOne({ email });
    const usernameFound = await User.findOne({ username });

    if (emailFound) {
      console.log('El email ya está en uso');
      return res.status(400).json(["El email ya está en uso"]);
    }

    if (usernameFound) {
      console.log('El nombre de usuario ya está en uso');
      return res.status(400).json(["El nombre de usuario ya está en uso"]);
    }

    const passwordHash = await bcrypt.hash(password, 10);
    console.log('Password hash generado:', passwordHash);

    const newUser = new User({
      username,
      email,
      password: passwordHash,
      cedula,
      cargo,
      ciudad,
      role,
    });

    const userSaved = await newUser.save();
    console.log('Usuario guardado:', userSaved);

    const token = await createAccessToken({ id: userSaved._id });
    console.log('Token creado:', token);

    // Configuración de la cookie para dominios cruzados
    res.cookie("token", token, {
      httpOnly: true, // Protege el token contra el acceso desde JavaScript (mejora la seguridad)
      secure: process.env.NODE_ENV === 'production', // Solo enviar en HTTPS en producción
      sameSite: 'None', // Permite el envío de cookies en diferentes dominios
      domain: 'tu-dominio-principal.com', // Configura el dominio principal
    });

    res.json({
      id: userSaved._id,
      username: userSaved.username,
      email: userSaved.email,
      cedula: userSaved.cedula,
      cargo: userSaved.cargo,
      ciudad: userSaved.ciudad,
      role: userSaved.role,
      createdAt: userSaved.createdAt,
      updatedAt: userSaved.updatedAt,
    });
  } catch (error) {
    console.error('Error en el registro:', error);
    res.status(500).json({ message: error.message });
  }
};

// Inicio de sesión
export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const userFound = await User.findOne({ email });
    if (!userFound) return res.status(400).json({ message: "Usuario no encontrado" });

    const isMatch = await bcrypt.compare(password, userFound.password);
    if (!isMatch) return res.status(400).json({ message: "Contraseña incorrecta" });

    const token = await createAccessToken({ id: userFound._id });
    
    // Configuración de la cookie para dominios cruzados
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'None',
      domain: 'opalsasasapp.netlify.app', // Configura el dominio principal
    });

    res.json({
      id: userFound._id,
      username: userFound.username,
      email: userFound.email,
      role: userFound.role,
      createdAt: userFound.createdAt,
      updatedAt: userFound.updatedAt,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Cierre de sesión
export const logout = (req, res) => {
  res.cookie('token', "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'None',
    domain: 'opalsasasapp.netlify.app', // Configura el dominio principal
    expires: new Date(0), // Expira la cookie
  });
  return res.sendStatus(200);
};

// Perfil de usuario
export const profile = async (req, res) => {
  const userFound = await User.findById(req.user.id);
  if (!userFound) return res.status(400).json({ message: "Usuario no encontrado" });
  return res.json({
    id: userFound._id,
    username: userFound.username,
    email: userFound.email,
    cedula: userFound.cedula,
    cargo: userFound.cargo,
    ciudad: userFound.ciudad,
    role: userFound.role,
    createdAt: userFound.createdAt,
    updatedAt: userFound.updatedAt,
  });
};

// Contar usuarios
export const getUserCount = async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    res.status(200).json({ count: userCount });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Verificar token
export const verifyToken = async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Token no proporcionado" });

    jwt.verify(token, TOKEN_SECRET, async (err, decoded) => {
      if (err) return res.status(401).json({ message: "No autorizado" });

      const user = await User.findById(decoded.id);
      if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

      res.json(user);
    });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor' });
  }
};
