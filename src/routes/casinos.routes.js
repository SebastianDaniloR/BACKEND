import { Router } from "express";
import { authRequired } from "../middlewares/validateToken.js";
import {
  createCasino,
  getAllCasinos,
  updateCasino,
  deleteCasino,
  getCasinoById,
  deleteCasinoDocument,
} from "../controllers/casinos.controller.js";
import { validateSchema } from "../middlewares/validator.js";
import { getCasinoElementos } from "../controllers/casinos.controller.js";
import { createCasinoSchema } from "../schemas/casinos.schema.js";
const router = Router();

router.get("/casinos", authRequired, getAllCasinos);
router.get("/casinos/:id", authRequired, getCasinoById);
router.get("/casinos/:id/elementos", authRequired, getCasinoElementos);
router.post(
  "/casinos",
  authRequired,
  validateSchema(createCasinoSchema),
  createCasino
);
router.delete("/casinos/:id", authRequired, deleteCasino);
router.put("/casinos/:id", authRequired, updateCasino);
router.delete('/casinos/:casinoId/document', authRequired, deleteCasinoDocument);





export default router;
