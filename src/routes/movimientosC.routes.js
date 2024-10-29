import { Router } from 'express';
import { getMovimientosC, addMovimientosC, deleteMovimiento } from '../controllers/movimientosC.controller.js';

const router = Router();

// Obtener el historial
router.get('/movimientos', getMovimientosC);

// Crear un nuevo registro en el historial
router.post('/movimientos', addMovimientosC);

// Eliminar  registro en el historial

router.delete('/movimientos/:id', deleteMovimiento);


export default router;
