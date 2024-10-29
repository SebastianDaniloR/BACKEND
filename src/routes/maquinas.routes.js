import { Router } from "express";
import { authRequired } from "../middlewares/validateToken.js";
import {
  traerMaquina,
  traerMaquinas,
  crearMaquina,
  eliminarMaquina,
  actualizarMaquina,
  traerMaquinasPorCasino,
  traerTodasMaquinas,
  buscarMaquinaPorNumeroDeSerie,
  buscarMaquinaPorSerieFlexible // Importar el nuevo controlador
} from "../controllers/maquinas.controller.js";
import { validateSchema } from "../middlewares/validator.js";
import { createMaquinaSchema } from "../schemas/maquinas.schema.js";

const router = Router();

// Rutas existentes
router.get("/maquina", traerMaquinas);
router.get("/maquina/all", traerTodasMaquinas);
router.get("/maquina/serial", buscarMaquinaPorNumeroDeSerie); // Búsqueda exacta
router.get("/maquina/casino",  traerMaquinasPorCasino);
router.get("/maquina/:id",  traerMaquina);

// Nueva ruta para la búsqueda flexible por número de serie
router.get("/maquina/buscar/serie-flexible",buscarMaquinaPorSerieFlexible); 

router.post(
  "/maquina",
  authRequired,
  validateSchema(createMaquinaSchema),
  crearMaquina
);
router.delete("/maquina/:id", authRequired, eliminarMaquina);
router.put("/maquina/:id", authRequired, actualizarMaquina);

export default router;
