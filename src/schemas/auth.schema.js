import {z} from 'zod';

export const registerSchema = z.object({
username:z.string({
    required_error: 'username es requerido'
}), 
email: z.string({
    required_error: 'email es requerido'
}).email({
    message: 'el email no es valido'
}),
password: z.string({
    required_error:'password es requerido'
}).min(6,{
    message: "la contraseña tiene que tener 6 caracteres minimo"
}),
cedula: z.string({
    required_error:'cedula es requerida'
}),
cargo:z.string({
required_error:'cargo es requerido'
})
});


export const loginSchema = z.object({
    email: z.string({
        required_error: 'email es requerido'
    }).email({
        message: 'el email no es valido'
    }),
    password: z.string({
        required_error:'password es requerido'
    }).min(6,{
        message: "la contraseña tiene que tener 6 caracteres minimo"
    }),
    });