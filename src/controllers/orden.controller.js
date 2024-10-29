import User from '../models/user.model.js';
import Orden from '../models/orden.model.js';
import Maquina from '../models/maquina.model.js';
import Componente from "../models/componente.model.js";
import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid'; // Para generar números de orden únicos

// Obtener todas las órdenes
export const getOrdenes = async (req, res) => {
  try {
    const { page = 1, limit = 8, estadoOrden, searchTerm } = req.query; // Recibimos el término de búsqueda
    const skip = (page - 1) * limit;

    // Construir un filtro dinámico basado en el estado de la orden si se proporciona
    const filter = {};

    // Añadir filtro por estado de la orden
    if (estadoOrden) {
      filter.estadoOrden = estadoOrden;
    }

    // Si existe searchTerm, filtrar por número de orden o usuario.username
    if (searchTerm) {
      const searchRegex = new RegExp(searchTerm, "i"); // Expresión regular para búsqueda
      filter.$or = [
        { numeroOrden: { $regex: searchRegex } },  // Buscar por número de orden
        { "usuario.username": { $regex: searchRegex } } // Buscar por nombre de usuario
      ];
    }

    const ordenes = await Orden.find(filter)
      .sort({ fechaOrden: -1 }) // Ordenar por la fecha más reciente
      .skip(skip)
      .limit(parseInt(limit));

    const totalOrdenes = await Orden.countDocuments(filter); // Contar el total de órdenes basado en el filtro

    res.status(200).json({
      ordenes,
      totalPages: Math.ceil(totalOrdenes / limit),
    });
  } catch (error) {
    console.error("Error al obtener las órdenes:", error.message);
    res.status(500).json({ message: "Error al obtener las órdenes", error: error.message });
  }
};

// Obtener órdenes del usuario autenticado con paginación
export const getOrdenesUsuarioAutenticado = async (req, res) => {
  try {
    const userId = req.idUsuario;

    // Verificamos que el ID del usuario es un ObjectId válido
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Usuario inválido" });
    }

    const { page = 1, limit = 8, estadoOrden, numeroOrden } = req.query;
    const skip = (page - 1) * limit;

    // Filtro básico para órdenes del usuario
    const filter = { idUsuario: userId };

    // Añadir filtro por estado si se proporciona
    if (estadoOrden) {
      filter.estadoOrden = estadoOrden;
    }

    // Añadir filtro por número de orden si se proporciona
    if (numeroOrden) {
      filter.numeroOrden = { $regex: numeroOrden, $options: 'i' }; // Búsqueda insensible a mayúsculas
    }

    // Consulta con paginación
    const ordenes = await Orden.find(filter)
      .sort({ fechaOrden: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    // Contar el total de órdenes del usuario
    const totalOrdenes = await Orden.countDocuments(filter);

    // Devolver las órdenes paginadas y el total de páginas
    res.status(200).json({
      ordenes,
      totalPages: Math.ceil(totalOrdenes / limit),
    });
  } catch (error) {
    console.error('Error al obtener las órdenes del usuario:', error.message);
    res.status(500).json({ message: 'Error al obtener las órdenes del usuario', error: error.message });
  }
};




export const getOrdenesByUser = async (req, res) => {
  try {
    // Obtén el ID del usuario autenticado
    const userId = req.idUsuario;

    // Busca las órdenes que pertenezcan a ese usuario
    const ordenes = await Orden.find({ usuario: userId }).populate('usuario').populate('componentes');

    res.json(ordenes);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener las órdenes', error });
  }
};



// Obtener una orden por ID
export const obtenerOrdenPorId = async (req, res) => {
  try {
    const { id } = req.params;
    const orden = await Orden.findById(id)
      .populate('elementoOrden')
      .populate('elementoOrdenSobrantes')
      .populate('componentesAsignados')
      .populate('componentesSobrantes');
    
    if (!orden) {
      return res.status(404).json({ message: 'Orden no encontrada' });
    }
    
    res.status(200).json(orden);
  } catch (error) {
    console.error('Error al obtener la orden:', error.message);
    res.status(500).json({ message: 'Error al obtener la orden', error: error.message });
  }
};

// Crear una nueva orden
export const createOrden = async (req, res) => {
  try {
    console.log('Datos recibidos:', req.body);

    const { descripcionOrden, nroSerieMaquina, marcaMaquina, ubicacionMaquina, usuario, tipoDeMantenimiento, componentesAsignados = [], componentesSobrantes = [] } = req.body;

    if (!descripcionOrden || !nroSerieMaquina || !ubicacionMaquina || !usuario) {
      return res.status(400).json({ message: 'Faltan campos requeridos' });
    }

    const fechaOrden = new Date();
    // Formato de fecha: ddmmaaaa
    const day = fechaOrden.getDate().toString().padStart(2, '0');
    const month = (fechaOrden.getMonth() + 1).toString().padStart(2, '0');
    const year = fechaOrden.getFullYear();
    const fechaStr = `${day}${month}${year}`;

    // Generar parte única basada en UUID (una porción más pequeña y legible)
    const shortUuid = uuidv4().split('-')[0]; // Usar solo una parte del UUID

    // Formato del número de orden mejorado
    const numeroOrden = `ORD-${fechaStr}-${shortUuid}`; // Por ejemplo: "ORD-08102023-5f2c"

    // Verificar que el usuario exista
    const usuarioObj = await User.findOne({ username: usuario });
    if (!usuarioObj) {
      console.log('Usuario no encontrado');
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    console.log('Usuario encontrado:', usuarioObj);

    // Guardar los detalles de la máquina directamente desde la solicitud
    const maquinaInfo = {
      nroSerieMaquina,
      marcaMaquina,
      ubicacionMaquina,
    };

    const nuevaOrden = new Orden({
      fechaOrden,
      descripcionOrden,
      maquina: maquinaInfo,
      usuario: {
        username: usuarioObj.username,
        email: usuarioObj.email,
        cargo: usuarioObj.cargo,
      },
      idUsuario: usuarioObj._id,
      numeroOrden,
      tipoDeMantenimiento,
      componentesAsignados,
      componentesSobrantes,
      elementoOrden: [],
      elementoOrdenSobrantes: [],
      fechaCumplimiento: null,
    });

    await nuevaOrden.save();
    res.status(201).json(nuevaOrden);
  } catch (error) {
    console.error('Error al crear la orden:', error.message);
    res.status(500).json({ message: 'Error al crear la orden', error: error.message });
  }
};

// Actualizar una orden (tarea realizada y elementos)
export const updateOrdenAsignados = async (req, res) => {
  try {
    const { id } = req.params;
    const { estadoOrden = 'Orden en solicitud', elementoOrden = [], tareaRealizada = '', componentesAsignados = [], componentesSobrantes = [] } = req.body;

    // Actualiza la orden
    const ordenActualizada = await Orden.findByIdAndUpdate(
      id,
      { 
        estadoOrden,
        elementoOrden,
        tareaRealizada,
        componentesAsignados,
        componentesSobrantes
      },
      { new: true }
    )
    .populate('elementoOrden')
    .populate('elementoOrdenSobrantes')
    .populate('componentesAsignados')
    .populate('componentesSobrantes');

    if (!ordenActualizada) {
      return res.status(404).json({ message: 'Orden no encontrada' });
    }

    // Itera sobre los componentes asignados para actualizar el usuario encargado
    for (const componente of componentesAsignados) {
      const componenteActual = await Componente.findOne({ serialComponente: componente.serialComponente });

      if (componenteActual) {
        // Actualiza el campo usuarioEncargado con el idUsuario de la orden
        componenteActual.usuarioEncargado = ordenActualizada.idUsuario;
        await componenteActual.save();
      }
    }

    res.status(200).json(ordenActualizada);
  } catch (error) {
    console.error('Error al actualizar la orden y los componentes:', error.message);
    res.status(500).json({ message: 'Error al actualizar la orden y los componentes', error: error.message });
  }
};

// Eliminar una orden
export const deleteOrden = async (req, res) => {
  try {
    const { id } = req.params;
    const orden = await Orden.findByIdAndDelete(id);

    if (!orden) {
      return res.status(404).json({ message: 'Orden no encontrada' });
    }

    res.status(200).json({ message: 'Orden eliminada correctamente' });
  } catch (error) {
    console.error('Error al eliminar la orden:', error.message);
    res.status(500).json({ message: 'Error al eliminar la orden', error: error.message });
  }
};

// Actualizar el estado de aceptación
export const updateAceptar = async (req, res) => {
  try {
    const { id } = req.params;
    const { estadoOrden } = req.body; // Usar estadoOrden en lugar de aceptado

    const orden = await Orden.findById(id);
    if (!orden) {
      return res.status(404).json({ message: "Orden no encontrada." });
    }

    orden.estadoOrden = estadoOrden; // Actualizar con estadoOrden
    await orden.save();

    res.status(200).json(orden);
  } catch (error) {
    console.error("Error al actualizar el estado de aceptado:", error.message);
    res.status(500).json({ message: "Error al actualizar el estado de aceptado.", error: error.message });
  }
};


// Actualizar la orden incluyendo sobrantes, tarea realizada y fecha de cumplimiento
export const updateOrdenSobrantes = async (req, res) => {
  try {
    const { id } = req.params;
    const {
      estadoOrden = 'Orden en solicitud',
      elementoOrden = [],
      elementoOrdenSobrantes = [],
      tareaRealizada = '',
      componentesAsignados = [],
      componentesSobrantes = [],
      fechaCumplimiento = null // Incluye fechaCumplimiento
    } = req.body;

    // Validar que las cantidades sobrantes no excedan las asignadas
    elementoOrden.forEach((elemento) => {
      const sobrante = elementoOrdenSobrantes.find(s => s.nombre === elemento.nombre);
      if (sobrante && sobrante.cantidadSobrante > elemento.cantidad) {
        throw new Error(`La cantidad sobrante para el elemento ${elemento.nombre} excede la cantidad asignada.`);
      }
    });

    const ordenActualizada = await Orden.findById(id);
    if (!ordenActualizada) {
      return res.status(404).json({ message: 'Orden no encontrada' });
    }

    // Actualiza la orden con los datos proporcionados
    ordenActualizada.estadoOrden = estadoOrden;
    ordenActualizada.elementoOrden = elementoOrden;
    ordenActualizada.elementoOrdenSobrantes = elementoOrdenSobrantes;
    ordenActualizada.tareaRealizada = tareaRealizada;
    ordenActualizada.componentesAsignados = componentesAsignados;
    ordenActualizada.componentesSobrantes = componentesSobrantes;
    ordenActualizada.fechaCumplimiento = fechaCumplimiento;

    // Guardar la orden antes de actualizar los componentes
    await ordenActualizada.save();

    // Eliminar el usuarioEncargado de los componentes asignados
    for (const componente of componentesAsignados) {
      const componenteActual = await Componente.findOne({ serialComponente: componente.serialComponente });
      if (componenteActual) {
        componenteActual.usuarioEncargado = null;
        await componenteActual.save();
      }
    }

    res.status(200).json(ordenActualizada);
  } catch (error) {
    console.error('Error al actualizar la orden:', error.message);
    res.status(500).json({ message: 'Error al actualizar la orden', error: error.message });
  }
};