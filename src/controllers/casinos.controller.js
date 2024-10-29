import Casino from "../models/casino.model.js";
import { uploadImage, uploadFile, deleteImage } from "../libs/cloudinary.js";
import fs from "fs-extra";

// Obtener todos los casinos
export const getAllCasinos = async (req, res) => {
  try {
    const casinos = await Casino.find().populate("maquinas elementos");
    res.json(casinos);
  } catch (error) {
    res.status(500).json({
      message: "Error al recuperar los casinos",
      error: error.message,
    });
  }
};

// Obtener un casino por ID
export const getCasinoById = async (req, res) => {
  try {
    const casino = await Casino.findById(req.params.id).populate("maquinas");
    if (!casino)
      return res.status(404).json({ message: "Casino no encontrado" });
    res.json(casino);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error al obtener el casino", error: error.message });
  }
};

export const createCasino = async (req, res) => {
  const { nombreCasino, ciudadCasino, direccionCasino } = req.body;

  let imgCasino = {};
  let documentacionLegal = [];
  let usoDeSuelos = [];
  let colJuegos = [];
  let otrosDocumentos = [];

  try {
    // Manejo de la imagen del casino (si se provee)
    if (req.files && req.files.imgCasino) {
      const result = await uploadImage(req.files.imgCasino.tempFilePath);
      await fs.remove(req.files.imgCasino.tempFilePath);
      imgCasino = {
        url: result.secure_url,
        public_id: result.public_id,
      };
    }

    // Procesar los documentos con sus categorías (asegurarse de que todos se suban a Cloudinary)
    for (const [key, file] of Object.entries(req.files)) {
      if (key !== "imgCasino") {
        // Obtener la categoría del documento del cuerpo de la solicitud
        const category =
          req.body[`documents[${key.split("[")[1]?.split("]")[0]}][category]`];

        if (!category) {
          return res.status(400).json({ message: "Categoría de documento no especificada." });
        }

        // Subir el archivo a Cloudinary y remover el archivo temporal
        const result = await uploadFile(file.tempFilePath, category);
        await fs.remove(file.tempFilePath);

        // Crear la información del documento con URL y public_id de Cloudinary
        const docInfo = { url: result.secure_url, public_id: result.public_id };

        // Asignar el documento a su categoría correspondiente
        switch (category) {
          case "documentacionLegal":
            documentacionLegal.push(docInfo);
            break;
          case "usoDeSuelos":
            usoDeSuelos.push(docInfo);
            break;
          case "colJuegos":
            colJuegos.push(docInfo);
            break;
          case "otrosDocumentos":
            otrosDocumentos.push(docInfo);
            break;
          default:
            return res.status(400).json({ message: "Categoría de documento no válida." });
        }
      }
    }

    // Crear el nuevo casino con todos los datos proporcionados
    const newCasino = new Casino({
      nombreCasino,
      ciudadCasino,
      direccionCasino,
      imgCasino,
      documentacionLegal,
      usoDeSuelos,
      colJuegos,
      otrosDocumentos,
    });

    // Guardar el casino en la base de datos
    const casinoGuardado = await newCasino.save();
    res.json(casinoGuardado);
  } catch (error) {
    console.error("Error al guardar el casino:", error);
    res.status(500).json({
      message: "Error al guardar el casino",
      error: error.message,
    });
  }
};


export const updateCasino = async (req, res) => {
  try {
    const { nombreCasino, ciudadCasino, direccionCasino, maquinas } = req.body;

    let updatedFields = {
      nombreCasino,
      ciudadCasino,
      direccionCasino,
      maquinas,
    };

    const casino = await Casino.findById(req.params.id);
    if (!casino) {
      return res.status(404).json({ message: "Casino no encontrado" });
    }

    // Manejo de la imagen del casino
    if (req.files && req.files.imgCasino) {
      if (casino.imgCasino && casino.imgCasino.public_id) {
        await deleteImage(casino.imgCasino.public_id);
      }

      const result = await uploadImage(req.files.imgCasino.tempFilePath);
      await fs.remove(req.files.imgCasino.tempFilePath);
      updatedFields.imgCasino = {
        url: result.secure_url,
        public_id: result.public_id,
      };
    }

    // Manejo de los documentos de casino
    if (req.files) {
      for (const [key, file] of Object.entries(req.files)) {
        if (key !== "imgCasino") {
          const category =
            req.body[`documents[${key.split("[")[1]?.split("]")[0]}][category]`];

          if (!category) {
            return res
              .status(400)
              .json({ message: "Categoría de documento no especificada." });
          }

          const result = await uploadFile(file.tempFilePath, category);
          await fs.remove(file.tempFilePath);

          const docInfo = { url: result.secure_url, public_id: result.public_id };

          // Agregar el documento a la categoría correspondiente
          switch (category) {
            case "documentacionLegal":
              casino.documentacionLegal.push(docInfo);
              break;
            case "usoDeSuelos":
              casino.usoDeSuelos.push(docInfo);
              break;
            case "colJuegos":
              casino.colJuegos.push(docInfo);
              break;
            case "otrosDocumentos":
              casino.otrosDocumentos.push(docInfo);
              break;
            default:
              return res.status(400).json({ message: "Categoría de documento no válida." });
          }
        }
      }

      // Actualizamos los campos de documentos en updatedFields
      updatedFields.documentacionLegal = casino.documentacionLegal;
      updatedFields.usoDeSuelos = casino.usoDeSuelos;
      updatedFields.colJuegos = casino.colJuegos;
      updatedFields.otrosDocumentos = casino.otrosDocumentos;
    }

    // Actualizar el casino en la base de datos
    const updatedCasino = await Casino.findByIdAndUpdate(
      req.params.id,
      updatedFields,
      { new: true }
    );

    if (!updatedCasino) {
      return res.status(404).json({ message: "Casino no encontrado" });
    }

    // Log para verificar qué se está devolviendo
    console.log("Casino actualizado:", updatedCasino);

    res.json(updatedCasino); // Retornar el casino actualizado para reflejar los cambios
  } catch (error) {
    console.error("Error al actualizar el casino:", error);
    res
      .status(500)
      .json({ message: "Error al actualizar el casino", error: error.message });
  }
};




export const getCasinoElementos = async (req, res) => {
  try {
    const { id } = req.params;
    const casino = await Casino.findById(id).populate("elementos");

    if (!casino) {
      return res.status(404).json({ message: "Casino no encontrado" });
    }

    res.json(casino.elementos);
  } catch (error) {
    res.status(500).json({
      message: "Error al obtener los elementos del casino",
      error: error.message,
    });
  }
};

// Eliminar un casino
export const deleteCasino = async (req, res) => {
  try {
    const casino = await Casino.findByIdAndDelete(req.params.id);
    if (!casino)
      return res.status(404).json({ message: "Casino no encontrado" });

    // Eliminar la imagen del casino en Cloudinary si existe
    if (casino.imgCasino && casino.imgCasino.public_id) {
      await deleteImage(casino.imgCasino.public_id);
    }

    // Helper function para eliminar documentos de una categoría en Cloudinary
    const deleteDocuments = async (docsArray) => {
      for (let doc of docsArray) {
        if (doc.public_id) {
          await deleteImage(doc.public_id);
        }
      }
    };

    // Eliminar documentos de todas las categorías
    if (casino.documentacionLegal && casino.documentacionLegal.length) {
      await deleteDocuments(casino.documentacionLegal);
    }

    if (casino.usoDeSuelos && casino.usoDeSuelos.length) {
      await deleteDocuments(casino.usoDeSuelos);
    }

    if (casino.colJuegos && casino.colJuegos.length) {
      await deleteDocuments(casino.colJuegos);
    }

    if (casino.otrosDocumentos && casino.otrosDocumentos.length) {
      await deleteDocuments(casino.otrosDocumentos);
    }

    res.json({ message: "Casino eliminado con éxito" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error al eliminar el casino", error: error.message });
  }
};


export const deleteCasinoDocument = async (req, res) => {
  const { casinoId } = req.params;
  const { publicId, category } = req.body; // Public ID del documento en Cloudinary y la categoría a la que pertenece

  try {
    const casino = await Casino.findById(casinoId);
    if (!casino) {
      return res.status(404).json({ message: "Casino no encontrado" });
    }
    

    // Eliminar el documento de Cloudinary
    const result = await deleteImage(publicId);

    if (result.result !== "ok") {
      return res.status(500).json({ message: "Error al eliminar el documento en Cloudinary" });
    }

    // Eliminar el documento de la categoría correspondiente en la base de datos
    casino[category] = casino[category].filter((doc) => doc.public_id !== publicId);

    await casino.save(); // Guardar los cambios en la base de datos

    res.json({ message: "Documento eliminado correctamente" });
  } catch (error) {
    res.status(500).json({
      message: "Error al eliminar el documento",
      error: error.message,
    });
  }
};


