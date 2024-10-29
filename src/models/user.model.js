import mongoose from "mongoose";
import bcrypt from 'bcryptjs';

// Definición del esquema de usuario
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true,
    unique: true
  },
  email: {
    type: String,
    required: true,
    trim: true,
    unique: true
  },
  password: {
    type: String,
    required: true,
  },
  cedula: {
    type: Number,
    required: true,
    unique: true
  },
  cargo: {
    type: String,
    required: true
  },
  ciudad: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    required: true,
    enum: ['admin', 'user'],  // Puedes añadir más roles según tus necesidades
    default: 'user'
  }
}, {
  timestamps: true
});

// Método para comparar contraseñas
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

export default User;
