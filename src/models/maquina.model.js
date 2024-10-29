import mongoose from "mongoose";

const maquinaSchema = new mongoose.Schema(
  {
    nroSerieMaquina: {
      type: String,
      required: true,
      trim: true,
    },
    modeloMaquina: {
      type: String,
      required: true,
      trim: true,
    },
    marcaMaquina: {
      type: String,
      required: true,
      trim: true,
    },
    precioMaquina: {
      type: String,
      required: true,
      trim: true,
    },
    juegoMaquina: {
      type: String,
      required: true,
      trim: true,
    },
    estadoMaquina: {
      type: String,
      required: true,
      trim: true,
    },
    imgMaquina: {
      url: String,
      public_id: String,
    },
    documentoMaquina: {
      url: String,
      public_id: String,
    },
    ubicacionMaquina: {
      type: String,
      required: true,
      trim: true,
    },
    fechaInstalacionMaquina: {
      type: String,
      required: true,
      trim: true,
    },
    proveedorMaquina: {
      type: String,
      required: true,
      trim: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    componentes: [{ type: mongoose.Schema.Types.ObjectId, ref: "Componente" }],
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("Maquinas", maquinaSchema);
