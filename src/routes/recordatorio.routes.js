import { Router } from "express";
import { createRecordatorio, getRecordatorios, deleteRecordatorio, updateVisto, getUltimos10Recordatorios } from "../controllers/recordatorio.controller.js";

const router = Router();

// Ruta para crear un nuevo recordatorio
router.post("/recordatorios", createRecordatorio);


// Ruta para obtener todos los recordatorios
router.get("/recordatorios", getRecordatorios);

// Ruta para obtener los últimos 10 recordatorios
router.get("/recordatorios/ultimos", getUltimos10Recordatorios);

// Ruta para eliminar un recordatorio por ID
router.delete("/recordatorios/:id", deleteRecordatorio);

// Ruta para marcar un recordatorio como visto
router.patch('/recordatorios/:id/visto', updateVisto);

export default router;
