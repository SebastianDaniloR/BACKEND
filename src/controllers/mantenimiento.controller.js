import Mantenimiento from '../models/mantenimiento.model.js';
import Maquina from '../models/maquina.model.js';
import fs from 'fs-extra'; // Utilizamos fs-extra para la eliminación de archivos
import path from 'path';
import { fileURLToPath } from 'url';
import { uploadFile, deleteFile } from '../libs/cloudinary.js'; // Importa las funciones de Cloudinary

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const getMantenimientos = async (req, res) => {
  try {
    const { page = 1, limit = 8, nroSerieMaquina, fechaMantenimiento } = req.query;

    let filter = {};
    
    // Filtro por número de serie
    if (nroSerieMaquina) {
      filter.nroSerieMaquina = { $regex: new RegExp(nroSerieMaquina, "i") };
    }

    // Filtro por fecha de mantenimiento (filtramos solo el día completo)
    if (fechaMantenimiento) {
      const startOfDay = new Date(`${fechaMantenimiento}T00:00:00`);
      const endOfDay = new Date(`${fechaMantenimiento}T23:59:59`);
      filter.fechaMantenimiento = { $gte: startOfDay, $lte: endOfDay };
    }

    const totalMantenimientos = await Mantenimiento.countDocuments(filter); // Contar los documentos filtrados
    const mantenimientos = await Mantenimiento.find(filter)
      .sort({ fechaMantenimiento: -1 }) // Ordenar por fecha más reciente
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .lean(); // Usar lean para convertir a objetos simples

    const mantenimientosWithType = mantenimientos.map((mantenimiento) => ({
      ...mantenimiento,
      type: "mantenimiento",
    }));

    res.json({
      totalPages: Math.ceil(totalMantenimientos / limit),
      currentPage: Number(page),
      mantenimientos: mantenimientosWithType, // Devuelve los mantenimientos con el campo 'type'
    });
  } catch (error) {
    res.status(500).json({ message: "Error al obtener los mantenimientos", error });
  }
};



export const createMantenimiento = async (req, res) => {
  try {
    const { tipoMantenimiento, fechaMantenimiento, descripcion, nroSerieMaquina, nombreMaquina, ubicacionMaquina } = req.body;
    const archivo = req.files ? req.files.archivo : null;

    // Buscar la máquina por número de serie
    const maquina = await Maquina.findOne({ nroSerieMaquina });
    if (!maquina) {
      return res.status(404).json({ message: 'Máquina no encontrada' });
    }

    let archivoData = null;
    if (archivo) {
      // Subir archivo a Cloudinary
      const result = await uploadFile(archivo.tempFilePath, 'Mantenimientos');
      // Eliminar archivo de la carpeta local
      await fs.remove(archivo.tempFilePath);
      archivoData = {
        url: result.secure_url,
        public_id: result.public_id,
      };
    }

    // Asegurarse de que la fecha se almacene correctamente
    const nuevoMantenimiento = new Mantenimiento({
      tipoMantenimiento,
      fechaMantenimiento: new Date(`${fechaMantenimiento}T00:00:00`), // Convertir la cadena de fecha en un objeto Date sin afectar la zona horaria
      descripcion,
      nroSerieMaquina,
      nombreMaquina,
      ubicacionMaquina,
      archivo: archivoData,
    });

    await nuevoMantenimiento.save();
    res.status(201).json(nuevoMantenimiento);
  } catch (error) {
    return res.status(500).json({ message: 'Error al crear el mantenimiento', error });
  }
};



export const deleteMantenimiento = async (req, res) => {
  try {
    const { id } = req.params;
    const mantenimiento = await Mantenimiento.findByIdAndDelete(id);

    if (!mantenimiento) {
      return res.status(404).json({ message: 'Mantenimiento no encontrado' });
    }

    // Si hay un archivo asociado, eliminarlo de Cloudinary
    if (mantenimiento.archivo && mantenimiento.archivo.public_id) {
      await deleteFile(mantenimiento.archivo.public_id);
    }

    res.status(200).json({ message: 'Mantenimiento eliminado correctamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al eliminar el mantenimiento', error });
  }
};
 
