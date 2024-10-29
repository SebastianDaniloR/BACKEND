import mongoose from 'mongoose';

const movimientosCSchema = new mongoose.Schema({
  componenteId: { type: mongoose.Schema.Types.ObjectId, ref: 'Componente', required: true },
  oldMaquinaId: { type: mongoose.Schema.Types.ObjectId, ref: 'Maquinas', required: true },
  oldMaquinaSerial: { type: String, required: true },
  newMaquinaId: { type: mongoose.Schema.Types.ObjectId, ref: 'Maquinas', required: true },
  newMaquinaSerial: { type: String, required: true },
  nombreComponente: { type: String, required: true },
  serialComponente: { type: String, required: true },
  fechaTransferencia: { type: Date, default: Date.now }
});

export default mongoose.model('MovimientosC', movimientosCSchema);
