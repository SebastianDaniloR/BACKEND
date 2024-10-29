import { Router } from "express";
import { authRequired } from "../middlewares/validateToken.js";
import {
  traerElemento,
  traerElementos,
  crearElemento,
  eliminarElemento,
  actualizarElemento,
  traerElementosPorCasino,
} from "../controllers/elementos.controller.js";
import { validateSchema } from "../middlewares/validator.js";
import { createElementoSchema } from "../schemas/elementos.schema.js";

const router = Router();

// Rutas para elementos
router.get("/elemento", authRequired, traerElementos);
router.get("/elemento/:id", authRequired, traerElemento);
router.post("/elemento",authRequired,validateSchema(createElementoSchema),crearElemento);
router.delete("/elemento/:id", authRequired, eliminarElemento);
router.put("/elemento/:id", authRequired, actualizarElemento);

// Ruta para obtener elementos por casino
router.get("/casinos/:casinoId/elemento", authRequired, traerElementosPorCasino);

export default router;
