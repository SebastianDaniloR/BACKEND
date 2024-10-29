import express from 'express';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import fileUpload from 'express-fileupload';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import authRoutes from './routes/auth.routes.js';
import recordatorioRoutes from './routes/recordatorio.routes.js';
import userRoutes from './routes/user.routes.js';
import maquinaRoutes from './routes/maquinas.routes.js';
import casinosRoutes from './routes/casinos.routes.js';
import componenteRoutes from './routes/componente.routes.js';
import mantenimientoRoutes from './routes/mantenimiento.routes.js';
import movimientosCRoutes from './routes/movimientosC.routes.js';
import moviMaquinasRoutes from './routes/moviMaquinas.routes.js';
import ordenRoutes from './routes/orden.routes.js';
import elementosRoutes from './routes/elementos.routes.js'; 
import movimientosElementosRoutes from './routes/movimientosElementos.routes.js';

dotenv.config();

const app = express();

// Definir __dirname en ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Usar la variable de entorno para CORS
app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH' ,'DELETE', 'OPTIONS'], // Agrega otros métodos si es necesario
  allowedHeaders: ['Content-Type', 'Authorization'], // Especifica los encabezados permitidos
}));


app.use(morgan('dev'));
app.use(express.json());

// Usar la variable de entorno para el directorio temporal de archivos
app.use(fileUpload({
  useTempFiles: true,
  tempFileDir: process.env.TEMP_FILE_DIR || './upload', // Fallback si no está definida
}));

app.use(cookieParser());

// Rutas de la API
app.use('/api', authRoutes);
app.use('/api', recordatorioRoutes);
app.use('/api', userRoutes);
app.use('/api', maquinaRoutes);
app.use('/api', casinosRoutes);
app.use('/api', componenteRoutes);
app.use('/api', mantenimientoRoutes);
app.use('/api', movimientosCRoutes);
app.use('/api', moviMaquinasRoutes);
app.use('/api', ordenRoutes); 
app.use('/api', elementosRoutes);
app.use('/api', movimientosElementosRoutes);

// Middleware para servir archivos estáticos
app.use('/upload', express.static(path.join(__dirname, 'upload')));

export default app;
