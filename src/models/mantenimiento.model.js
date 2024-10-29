import mongoose from 'mongoose';

const mantenimientoSchema = new mongoose.Schema({
  tipoMantenimiento: { type: String, required: true },
  fechaMantenimiento: { type: Date, required: true },
  descripcion: { type: String, required: true },
  archivo: {
    url: { type: String },
    public_id: { type: String },
  },
  nroSerieMaquina: { type: String, required: true },
  nombreMaquina: { type: String, required: true },
  ubicacionMaquina: { type: String, required: true },
});

export default mongoose.model('Mantenimiento', mantenimientoSchema);
