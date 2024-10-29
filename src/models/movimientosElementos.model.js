import mongoose from 'mongoose';

const movimientosElementosSchema = new mongoose.Schema({
  elementoId: { type: mongoose.Schema.Types.ObjectId, ref: 'Elementos', required: true },
  oldUbicacionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Casinos', required: true }, // O la colección que corresponda
  oldUbicacionNombre: { type: String, required: true },
  newUbicacionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Casinos', required: true }, // O la colección que corresponda
  newUbicacionNombre: { type: String, required: true },
  nombreElemento: { type: String, required: true },
  codigoElemento: { type: String, required: true },
  fechaTransferenciaElm: { type: Date, default: Date.now }
});

export default mongoose.model('MovimientosElementos', movimientosElementosSchema);
