import { Router } from 'express';
import {getMovimientosM,addMovimientosM,deleteMovimientoM} from '../controllers/moviMaquinas.controller.js';

const router = Router();

router.get('/moviMaquinas', getMovimientosM ); 
router.post('/moviMaquinas', addMovimientosM ); 
router.delete('/moviMaquinas/:id', deleteMovimientoM); 

export default router;
