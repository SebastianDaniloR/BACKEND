import mongoose from "mongoose";

const elementoSchema = mongoose.Schema(
  {
    nombreElemento: {
      type: String,
      required: true,
      trim: true,
    },
    codigoElemento: {
      type: String,
      required: true,
      trim: true,
    },
    marcaElemento: {
      type: String,
      required: true,
      trim: true,
    },
    tipoElemento: {
      type: String,
      required: true,
      trim: true,
    },
    documentacionElemento: [
      {
        url: String,
        public_id: String,
      }
    ],
    imgElemento: {
      url: String,
      public_id: String,
    },
    ubicacionDeElemento: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Casinos",
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("Elementos", elementoSchema);
