import User from '../models/user.model.js'; // Asegúrate de importar tu modelo de usuario

export const getUsers = async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const deleteUsers = async (req, res) => {
    try {
      const { id } = req.params;
      await User.findByIdAndDelete(id);
      res.status(200).json({ message: "Usuario eliminado correctamente" });
    } catch (error) {
      res.status(500).json({ message: "Error al eliminar el usuario" });
    }
  };

  export const updateProfile = async (req, res) => {
    const { id } = req.params;
    const { username, email, ciudad, cargo } = req.body;
  
    try {
      const user = await User.findByIdAndUpdate(
        id,
        { username, email, ciudad, cargo },
        { new: true, runValidators: true }
      );
  
      if (!user) {
        return res.status(404).json({ message: 'Usuario no encontrado' });
      }
  
      res.status(200).json(user);
    } catch (error) {
      res.status(500).json({ message: 'Error al actualizar el perfil', error });
    }
  };

  export const updateUserRole = async (req, res) => {
    const { id } = req.params;
    const { role } = req.body;
  
    console.log(`Actualizando rol del usuario con ID: ${id} a ${role}`);
  
    try {
      const user = await User.findByIdAndUpdate(
        id,
        { role },
        { new: true, runValidators: true }
      );
  
      if (!user) {
        console.log('Usuario no encontrado');
        return res.status(404).json({ message: 'Usuario no encontrado' });
      }
  
      console.log('Usuario actualizado:', user);
      res.status(200).json(user);
    } catch (error) {
      console.error('Error al actualizar el rol:', error);
      res.status(500).json({ message: 'Error al actualizar el rol', error });
    }
  };

// Controlador de obtención de usuario por ID
export const getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findById(id); // Asegúrate de que el modelo User esté importado

    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.status(200).json(user); // Devuelve el usuario encontrado
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener el usuario', error });
  }
};

