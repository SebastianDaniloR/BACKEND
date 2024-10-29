import { Router } from "express";
import { authRequired } from '../middlewares/validateToken.js';
import {getOrdenes, createOrden, deleteOrden, updateOrdenAsignados, getOrdenesByUser, obtenerOrdenPorId, updateAceptar, updateOrdenSobrantes, getOrdenesUsuarioAutenticado} from "../controllers/orden.controller.js";

const router = Router();

// Obtener todas las ordenes

router.get("/ordenes", getOrdenes);

router.get('/ordenes/usuario-autenticado', authRequired, getOrdenesUsuarioAutenticado);

// Obtener órdenes del usuario autenticado

// Ruta para obtener una orden por ID
router.get('/ordenes/:id', obtenerOrdenPorId);

//filtrar ordenes solo para que aparezcan las del usuario que las creo
router.get('/ordenes', authRequired, getOrdenesByUser);





// Crear una nueva orden

router.post("/ordenes", createOrden);

// mandar componentes sobrantes

router.put("/ordenes/:id", updateOrdenAsignados);

// post la orden con los sobrantes

router.put('/ordenes/:id/sobrantes', updateOrdenSobrantes);

// Eliminar una orden

router.delete("/ordenes/:id", deleteOrden);

// Aceptar una orden

router.patch("/ordenes/:id/aceptar", updateAceptar);

export default router;