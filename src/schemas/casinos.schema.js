import { z } from "zod";

export const createCasinoSchema = z.object({
  nombreCasino: z.string().min(1, { message: "El nombre del casino es obligatorio" }),
  imgCasino: z.object({
    url: z.string(),
    public_id: z.string()
  }).optional(),
  ciudadCasino: z.string().min(1, { message: "La ciudad del casino es obligatoria" }),
  direccionCasino: z.string().min(1, { message: "La direccion es obligatoria" }),
  documentacionCasino: z.object({
    url: z.string(),
    public_id: z.string()
  }).optional()
});
