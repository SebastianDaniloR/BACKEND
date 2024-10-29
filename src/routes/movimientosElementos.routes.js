import { Router } from 'express';
import { getMovimientosElementos, addMovimientosElementos, deleteMovimientoElemento } from '../controllers/movimientosElementos.controller.js';

const router = Router();

// Obtener todos los movimientos de elementos
router.get('/movimientos-elementos', getMovimientosElementos);

// Crear un nuevo movimiento de elemento
router.post('/movimientos-elementos', addMovimientosElementos);

// Eliminar un movimiento de elemento por ID
router.delete('/movimientos-elementos/:id', deleteMovimientoElemento);

export default router;
