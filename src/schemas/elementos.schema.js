import { z } from "zod";

export const createElementoSchema = z.object({
  nombreElemento: z.string().min(1, { message: "El nombre del elemento es obligatorio" }),
  codigoElemento: z.string().min(1, { message: "El código del elemento es obligatorio" }),  // Nuevo campo
  marcaElemento: z.string().optional(),
  tipoElemento: z.string().min(1, { message: "El tipo de elemento es obligatorio" }),
  imgElemento: z.object({
    url: z.string(),
    public_id: z.string(),
  }).optional(),
  documentacionElemento: z.object({
    url: z.string(),
    public_id: z.string(),
  }).optional(),
  date: z.string().datetime().optional(),
});
