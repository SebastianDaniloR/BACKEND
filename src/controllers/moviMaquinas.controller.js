import MovimientosM from '../models/movimientosM.model.js';
import mongoose from 'mongoose';
import Casinos from '../models/casino.model.js'; // Asumiendo que tienes un modelo de Casino

export const getMovimientosM = async (req, res) => {
  try {
    const { page = 1, limit = 8, serialMaquina = '', fechaTransferencia = '' } = req.query; // Parámetros de paginación, búsqueda y filtro
    const skip = (page - 1) * limit;

    // Crear objeto de filtro dinámico
    const query = {};

    // Filtrar por coincidencias parciales en el número de serie de la máquina
    if (serialMaquina) {
      query.serialMaquina = { $regex: serialMaquina, $options: 'i' }; // Coincidencias parciales y case-insensitive
    }

    // Filtrar por fecha de transferencia si existe
    if (fechaTransferencia) {
      const startDate = new Date(fechaTransferencia);
      const endDate = new Date(startDate);
      endDate.setDate(startDate.getDate() + 1); // Considerar todo el día

      query.fechaTransferencia = { $gte: startDate, $lt: endDate };
    }

    // Consultamos los movimientos con filtros y paginación
    const movimientosMaquina = await MovimientosM.find(query)
      .populate('maquinaId')
      .populate('oldCasinoId')
      .populate('newCasinoId')
      .sort({ fechaTransferencia: -1 }) // Ordenar por fecha más reciente
      .skip(skip)
      .limit(parseInt(limit));

    // Calculamos el total de documentos que coinciden con los filtros
    const totalMovimientos = await MovimientosM.countDocuments(query);

    res.status(200).json({
      movimientosMaquina,
      totalPages: Math.ceil(totalMovimientos / limit), // Total de páginas
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al obtener los movimientos' });
  }
};

export const addMovimientosM = async (req, res) => {
  try {
    console.log('Datos recibidos:', req.body); // Log de los datos recibidos

    const { maquinaId, oldCasinoNombre, newCasinoNombre, marcaMaquina, serialMaquina } = req.body;

    // Validar que todos los campos requeridos están presentes
    if (!maquinaId || !oldCasinoNombre || !newCasinoNombre || !marcaMaquina || !serialMaquina) {
      return res.status(400).json({ message: 'Todos los campos son requeridos' });
    }

    // Convertir el ID de la máquina a ObjectId
    const maquinaObjectId = new mongoose.Types.ObjectId(maquinaId);

    // Buscar IDs de los casinos
    const oldCasino = await Casinos.findOne({ nombreCasino: oldCasinoNombre });
    const newCasino = await Casinos.findOne({ nombreCasino: newCasinoNombre });

    if (!oldCasino || !newCasino) {
      return res.status(404).json({ message: 'Casino no encontrado' });
    }

    const nuevoMovimiento = new MovimientosM({
      maquinaId: maquinaObjectId,
      oldCasinoId: oldCasino._id,
      oldCasinoNombre,
      newCasinoId: newCasino._id,
      newCasinoNombre,
      marcaMaquina,
      serialMaquina,
      fechaTransferencia: new Date()
    });

    console.log('Nuevo movimiento de máquina:', nuevoMovimiento); // Log del nuevo objeto de movimiento

    await nuevoMovimiento.save();
    res.status(201).json(nuevoMovimiento);
  } catch (error) {
    console.error('Error al añadir el movimiento:', error);
    res.status(500).json({ message: 'Error al añadir el movimiento' });
  }
};

export const deleteMovimientoM = async (req, res) => {
  try {
    const { id } = req.params;
    await MovimientosM.findByIdAndDelete(id);
    res.status(200).json({ message: 'Transacción eliminada correctamente' });
  } catch (error) {
    console.error('Error al eliminar la transacción:', error); // Log de error
    res.status(500).json({ message: 'Error al eliminar la transacción' });
  }
};
