// controllers/movimientosC.controller.js
import MovimientosC from '../models/movimientosC.model.js';
import Maquinas from '../models/maquina.model.js'; // Asegúrate de que la ruta es correcta
import Componente from '../models/componente.model.js'; // Asegúrate de que la ruta es correcta

// Controller (Backend)
export const getMovimientosC = async (req, res) => {
  try {
    const { page = 1, limit = 8, serialComponente = '', fechaTransferencia = '' } = req.query; // Parámetros de paginación y filtro
    const skip = (page - 1) * limit;

    // Crear objeto de filtro dinámico
    const query = {};

    // Filtrar por coincidencias parciales en el número de serie
    if (serialComponente) {
      query.serialComponente = { $regex: serialComponente, $options: 'i' }; // 'i' para que sea case-insensitive
    }

    // Filtrar por fecha de transferencia si existe
    if (fechaTransferencia) {
      const startDate = new Date(fechaTransferencia);
      const endDate = new Date(startDate);
      endDate.setDate(startDate.getDate() + 1); // Considerar todo el día

      query.fechaTransferencia = { $gte: startDate, $lt: endDate };
    }

    // Consultamos los movimientos con filtros y paginación
    const movimientos = await MovimientosC.find(query)
      .populate('componenteId')
      .populate('oldMaquinaId')
      .populate('newMaquinaId')
      .sort({ fechaTransferencia: -1 }) // Ordenar por fecha más reciente
      .skip(skip)
      .limit(parseInt(limit));

    // Calculamos el total de documentos que coinciden con los filtros
    const totalMovimientos = await MovimientosC.countDocuments(query);

    res.status(200).json({
      movimientos,
      totalPages: Math.ceil(totalMovimientos / limit), // Total de páginas
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al obtener los movimientos' });
  }
};


export const addMovimientosC = async (req, res) => {
  try {
    console.log("Datos recibidos:", req.body); // Log de los datos recibidos

    const { componenteId, oldMaquinaId, oldMaquinaSerial, newMaquinaId, newMaquinaSerial, nombreComponente, serialComponente } = req.body;

    // Validar que todos los campos requeridos están presentes
    if (!componenteId || !oldMaquinaId || !oldMaquinaSerial || !newMaquinaId || !newMaquinaSerial || !nombreComponente || !serialComponente) {
      return res.status(400).json({ message: 'Todos los campos son requeridos' });
    }

    const nuevoMovimiento = new MovimientosC({
      componenteId,
      oldMaquinaId,
      oldMaquinaSerial,
      newMaquinaId,
      newMaquinaSerial,
      nombreComponente,
      serialComponente,
      fechaTransferencia: new Date()
    });

    await nuevoMovimiento.save();
    res.status(201).json(nuevoMovimiento);
  } catch (error) {
    console.error("Error al añadir el movimiento:", error);
    res.status(500).json({ message: 'Error al añadir el movimiento' });
  }
};

export const deleteMovimiento = async (req, res) => {
  try {
    const { id } = req.params;
    await MovimientosC.findByIdAndDelete(id);
    res.status(200).json({ message: "Transaccion eliminado correctamente" });
  } catch (error) {
    console.error("Error al eliminar el Transaccion:", error); // Log de error
    res.status(500).json({ message: "Error al eliminar la Transaccion" });
  }
};
