import Recordatorio from "../models/recordatorio.model.js";
import User from '../models/user.model.js';
import { uploadFile, deleteFile } from "../libs/cloudinary.js";
import fs from 'fs-extra';

export const createRecordatorio = async (req, res) => {
  try {
    const { titulo, descripcion, fechaRecordatorio, usuario } = req.body;

    // Buscar el ObjectId del usuario
    const usuarioObj = await User.findOne({ username: usuario });
    if (!usuarioObj) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    let documentoRecordatorio = [];

    // Manejo del archivo documentoRecordatorio
    if (req.files && req.files.documentoRecordatorio) {
      const result = await uploadFile(req.files.documentoRecordatorio.tempFilePath, 'Documentos');
      await fs.remove(req.files.documentoRecordatorio.tempFilePath);
      documentoRecordatorio.push({
        url: result.secure_url,
        public_id: result.public_id,
      });
    }

    const newRecordatorio = new Recordatorio({
      titulo,
      descripcion,
      fechaRecordatorio,
      usuario: usuarioObj._id,
      documentoRecordatorio,
    });

    await newRecordatorio.save();
    res.status(201).json(newRecordatorio);
  } catch (error) {
    console.error("Error al crear recordatorio:", error);
    res.status(500).json({ message: "Error al crear el recordatorio." });
  }
};

// Controlador para obtener todos los recordatorios
export const getRecordatorios = async (req, res) => {
  try {
    const { page = 1, limit = 8, fechaRecordatorio } = req.query;
    const skip = (page - 1) * limit;

    // Filtro dinámico basado en la fecha proporcionada
    const filter = {};
    if (fechaRecordatorio) {
      const startDate = new Date(fechaRecordatorio);
      const endDate = new Date(startDate);
      endDate.setDate(endDate.getDate() + 1); // Sumamos un día para abarcar todo el día

      filter.fechaRecordatorio = {
        $gte: startDate,
        $lt: endDate,
      };
    }

    const recordatorios = await Recordatorio.find(filter)
      .sort({ fechaRecordatorio: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('usuario', 'username');

    const totalRecordatorios = await Recordatorio.countDocuments(filter);

    res.status(200).json({
      recordatorios,
      totalPages: Math.ceil(totalRecordatorios / limit),
    });
  } catch (error) {
    console.error("Error al obtener recordatorios:", error);
    res.status(500).json({ message: "Error al obtener los recordatorios." });
  }
};

export const getUltimos10Recordatorios = async (req, res) => {
  try {
    const fechaActual = new Date(); // Obtener la fecha actual
    const recordatorios = await Recordatorio.find({
      fechaRecordatorio: { $gte: fechaActual }  // Filtrar solo recordatorios con fecha futura o igual a hoy
    })
      .sort({ fechaRecordatorio: 1 })  // Ordenar por fecha más cercana
      .limit(10)  // Limitar a los 10 más próximos
      .populate('usuario', 'username');  // Popular el usuario relacionado si es necesario

    res.status(200).json(recordatorios);
  } catch (error) {
    console.error("Error al obtener los últimos 10 recordatorios:", error);
    res.status(500).json({ message: "Error al obtener los recordatorios." });
  }
};
// Controlador para eliminar un recordatorio
export const deleteRecordatorio = async (req, res) => {
  try {
    const { id } = req.params;
    const recordatorio = await Recordatorio.findById(id);

    if (!recordatorio) {
      return res.status(404).json({ message: "Recordatorio no encontrado." });
    }

    // Eliminar el archivo de Cloudinary si existe
    if (recordatorio.documentoRecordatorio && recordatorio.documentoRecordatorio.length > 0) {
      for (const doc of recordatorio.documentoRecordatorio) {
        await deleteFile(doc.public_id);
      }
    }

    // Eliminar el recordatorio
    await Recordatorio.findByIdAndDelete(id);
    res.status(200).json({ message: "Recordatorio eliminado correctamente" });
  } catch (error) {
    console.error("Error al eliminar el recordatorio:", error);
    res.status(500).json({ message: "Error al eliminar el recordatorio." });
  }
};

// Controlador para actualizar el estado "visto"
export const updateVisto = async (req, res) => {
  try {
    const { id } = req.params;
    const { visto } = req.body;

    // Verificar si el recordatorio existe
    const recordatorio = await Recordatorio.findById(id);
    if (!recordatorio) {
      return res.status(404).json({ message: "Recordatorio no encontrado." });
    }

    // Actualizar el campo "visto"
    recordatorio.visto = visto;
    await recordatorio.save();

    // Enviar respuesta con el recordatorio actualizado
    res.status(200).json(recordatorio);
  } catch (error) {
    console.error("Error al actualizar el estado de visto:", error);
    res.status(500).json({ message: "Error al actualizar el estado de visto." });
  }
};
