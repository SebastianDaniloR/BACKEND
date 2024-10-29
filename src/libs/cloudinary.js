import cloudinary from 'cloudinary';
import dotenv from 'dotenv';

// Cargar las variables del archivo .env
dotenv.config();

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

export const uploadImage = async (filePath) => {
    try {
        const result = await cloudinary.v2.uploader.upload(filePath, {
            folder: 'Imagenes',
            transformation: [
                { quality: 'auto:low' }, // Máxima compresión automática
                { fetch_format: 'auto' }  // Selecciona automáticamente el formato más ligero
            ]
        });
        return result;
    } catch (error) {
        console.error('Error al subir imagen a Cloudinary:', error);
        throw error;
    }
};

export const uploadFile = async (filePath, folderName) => {
    try {
        const result = await cloudinary.v2.uploader.upload(filePath, {
            folder: folderName,
            resource_type: 'auto', // Detecta automáticamente el tipo de archivo
            transformation: [
                { quality: 'auto:low' }, // Compresión automática
                { fetch_format: 'auto' }  // Selecciona el formato más eficiente
            ]
        });
        return result;
    } catch (error) {
        console.error('Error al subir archivo a Cloudinary:', error);
        throw error;
    }
};

export const deleteImage = async (publicId) => {
    try {
        const result = await cloudinary.v2.uploader.destroy(publicId);
        return result;
    } catch (error) {
        console.error('Error al eliminar imagen de Cloudinary:', error);
        throw error;
    }
};

export const deleteFile = async (publicId) => {
    try {
        const result = await cloudinary.v2.uploader.destroy(publicId);
        return result;
    } catch (error) {
        console.error('Error al eliminar archivo de Cloudinary:', error);
        throw error;
    }
};
