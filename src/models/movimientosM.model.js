import mongoose from 'mongoose';

const movimientosMSchema = new mongoose.Schema({
  maquinaId: { type: mongoose.Schema.Types.ObjectId, ref: 'Maquinas', required: true },
  oldCasinoId: { type: mongoose.Schema.Types.ObjectId, ref: 'Casinos', required: true },
  oldCasinoNombre: { type: String, required: true },
  newCasinoId: { type: mongoose.Schema.Types.ObjectId, ref: 'Casinos', required: true },
  newCasinoNombre: { type: String, required: true },
  marcaMaquina: { type: String, required: true },
  serialMaquina: { type: String, required: true },
  fechaTransferencia: { type: Date, default: Date.now }
});

export default mongoose.model('MovimientosM', movimientosMSchema);
