import { z } from "zod";

export const createComponenteSchema = z.object({
  serialComponente: z.string().min(1, { message: "El serial del componente es obligatorio" }).optional(),
  nombreComponente: z.string().min(1, { message: "El nombre del componente es obligatorio" }).optional(),
  marcaComponente: z.string().min(1, { message: "La marca del componente es obligatoria" }).optional(),
  documentoComponente: z.object({
    url: z.string(),
    public_id: z.string()
  }).optional(),
  date: z.string().datetime().optional(),
  maquina: z.string().min(1, { message: "El ID de la máquina es obligatorio" }).optional()
});
