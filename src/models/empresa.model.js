import mongoose from "mongoose";

const empresaSchema = mongoose.Schema({
    nombreEmpresa: {
        type: String,
        required: true,
        trim: true
    },
    ciudadEmpresa: {
        type: String,
        required: true,
        trim: true
    },
    direccionEmpresa: {
        type: String,
        required: true,
        trim: true
    },
    imgEmpresa: {
        type: String,
        required: true,
        trim: true
    }
},{
    timestamps:true
})

export default mongoose.model('empresas', empresaSchema)