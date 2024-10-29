import { Router } from 'express';
import { deleteUsers, getUsers, updateProfile , updateUserRole, getUserById} from '../controllers/user.controller.js';

const router = Router();

router.get('/users', getUsers);
// Asegúrate de que las rutas sean correctas
router.get('/users/:id', getUserById);
router.delete('/users/:id', deleteUsers);
router.put('/users/:id', updateProfile);
router.put('/users/:id/role', updateUserRole);


export default router;