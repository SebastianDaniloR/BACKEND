import {Router} from 'express';
import { getMantenimientos, createMantenimiento, deleteMantenimiento  } from '../controllers/mantenimiento.controller.js'; // Ajusta las rutas de los controladores según tu estructura

const router = Router();

router.get('/mantenimientos', getMantenimientos);
router.post('/mantenimientos', createMantenimiento);
router.delete('/mantenimientos/:id', deleteMantenimiento);


export default router;