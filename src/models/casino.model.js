import mongoose from "mongoose";

const casinoSchema = mongoose.Schema(
  {
    nombreCasino: {
      type: String,
      required: true,
      trim: true,
    },
    imgCasino: {
      url: String,
      public_id: String,
    },
    ciudadCasino: {
      type: String,
      required: true,
      trim: true,
    },
    direccionCasino: {
      type: String,
      required: true,
      trim: true,
    },
    documentacionLegal: [
      {
        url: String,
        public_id: String,
      }
    ],
    usoDeSuelos: [
      {
        url: String,
        public_id: String,
      }
    ],
    colJuegos: [
      {
        url: String,
        public_id: String,
      }
    ],
    otrosDocumentos: [
      {
        url: String,
        public_id: String,
      }
    ],
    maquinas: [{ type: mongoose.Schema.Types.ObjectId, ref: "Maquinas" }],
    elementos: [{ type: mongoose.Schema.Types.ObjectId, ref: "Elementos" }],
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("Casinos", casinoSchema);
