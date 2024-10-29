import { Router } from "express";
import { authRequired } from "../middlewares/validateToken.js";
import {
  createComponente,
  getComponentes,
  getComponenteById,
  deleteComponenteById,
  updateComponenteById,
  getComponenteBySerial, // Nueva función
  uploadComponenteImage,
} from "../controllers/componentes.controller.js";
import { validateSchema } from "../middlewares/validator.js";
import { createComponenteSchema } from "../schemas/componente.schema.js";

const router = Router();

router.get("/componentes", authRequired, getComponentes);
router.get("/componentes/:id", authRequired, getComponenteById);
router.get("/componentes-serial", authRequired, getComponenteBySerial); // Nueva ruta para buscar por serial
router.post(
  "/componentes",
  authRequired,
  validateSchema(createComponenteSchema),
  createComponente
);
router.post("/componentes/:id/upload-image", authRequired, uploadComponenteImage); 
router.delete("/componentes/:id", authRequired, deleteComponenteById);
router.put("/componentes/:id", authRequired, updateComponenteById);

export default router;
