import mongoose from "mongoose";

const OrdenSchema = new mongoose.Schema({
  fechaOrden: { type: Date, required: true, default: Date.now }, // Establece la fecha y hora actual por defecto
  estadoOrden: { type: String, required: true, default: "Orden en solicitud" },
  descripcionOrden: { type: String, required: true },

  // Cambiar el campo "maquina" para que contenga los datos necesarios de la máquina directamente
  maquina: {
    nroSerieMaquina: { type: String, required: true },
    marcaMaquina: { type: String },
    ubicacionMaquina: { type: String, required: true },
  },
  idUsuario: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  }, // Agregas el campo de ID
  usuario: {
    username: { type: String, required: true },
    email: { type: String, required: true },
    cargo: { type: String, required: true },
  },
  tareaRealizada: { type: String },
  numeroOrden: { type: String, unique: true, required: true },
  elementoOrden: [
    {
      nombre: { type: String, required: true },
      cantidad: { type: Number, required: true },
    },
  ],
  elementoOrdenSobrantes: [
    {
      nombre: { type: String, required: true },
      cantidadSobrante: { type: Number, required: true },
    },
  ],
  tipoDeMantenimiento: [
    {
      type: String,
      enum: ["preventivo", "correctivo", "predictivo", "software", "estético"],
    },
  ],
  fechaCumplimiento: { type: Date }, // Campo para la fecha de cumplimiento

  componentesAsignados: [
    {
      serialComponente: { type: String, required: true },
      nombreComponente: { type: String, required: true },
    },
  ],
  componentesSobrantes: [
    {
      serialComponente: { type: String, required: true },
      nombreComponente: { type: String, required: true },
    },
  ],
});

export default mongoose.model("Orden", OrdenSchema);
