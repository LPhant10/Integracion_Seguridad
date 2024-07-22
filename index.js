const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const port = 3000;

// Clave secreta para firmar el token
const secretKey = 'your-very-secret-key';

// Middleware para parsear JSON
app.use(express.json());

// Limitar solicitudes a la ruta de login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 3, // Límite de 5 solicitudes por IP
    message: 'Demasiadas solicitudes desde esta IP, por favor intente más tarde.'
});

app.use('/login', loginLimiter);

// Datos de usuarios (ejemplo en memoria)
const users = {
    llerena: {
        password: '1234',
        role: 'Marketing'
    },
    cardenas: {
        password: '123123',
        role: 'Administrador'
    }
};

// Ruta para generar el token
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users[username];

    // Validar credenciales
    if (!user || user.password !== password) {
        return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Tiempo de expiración del token: 1 hora
    const expiresIn = '1h'; // 1 hora
    const expirationTime = Math.floor(Date.now() / 1000) + 3600; // Expiración en segundos (1 hora)

    // Generar el token con información adicional
    const token = jwt.sign({
        userId: username,
        role: user.role
    }, secretKey, { expiresIn });

    // Enviar el token y tiempos de creación y expiración
    res.json({
        token,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(expirationTime * 1000).toISOString()
    });
});

// Middleware para verificar el token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ error: 'No se proporcionó ningún token' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Token expirado o inválido' });
        }

        // Si el token es válido, almacena la información en la solicitud
        req.userId = decoded.userId;
        req.role = decoded.role; // Guardar el rol del usuario
        req.tokenIssuedAt = decoded.iat; // Tiempo de emisión del token
        req.tokenExpiresAt = decoded.exp; // Tiempo de expiración del token
        next();
    });
};

// Middleware para verificar permisos de rol
const checkRole = (roles) => (req, res, next) => {
    if (!roles.includes(req.role)) {
        return res.status(403).json({ error: 'Acceso denegado' });
    }
    next();
};

// Limitar solicitudes a las rutas protegidas
const rateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minuto
    max: 2, // Límite de 10 solicitudes por IP
    message: 'Demasiadas solicitudes desde esta IP, por favor intente más tarde.'
});

app.use('/protected', rateLimiter);

// Ruta para listar clientes (accesible para todos los roles)
app.get('/clients', verifyToken, (req, res) => {
    res.json({ message: 'Listando clientes' });
});

// Ruta para editar clientes (solo para Administradores)
app.post('/clients/edit', verifyToken, checkRole(['Administrador']), (req, res) => {
    res.json({ message: 'Cliente editado' });
});

// Ruta protegida
app.get('/protected', verifyToken, (req, res) => {
    const currentTime = Math.floor(Date.now() / 1000); // Hora actual en segundos

    // Verifica si el token ha expirado
    const tokenExpired = currentTime > req.tokenExpiresAt;

    if (tokenExpired) {
        return res.status(401).json({ error: 'Token expirado' });
    }

    // Calcular el tiempo restante hasta la expiración
    const timeRemaining = req.tokenExpiresAt - currentTime;
    const minutesRemaining = Math.floor(timeRemaining / 60);
    const secondsRemaining = timeRemaining % 60;

    // Información del usuario extraída del token
    const userInfo = {
        userId: req.userId,
        role: req.role // Incluye el rol del usuario
    };

    res.json({
        message: 'Esta es una ruta protegida',
        user: userInfo,
        createdAt: new Date(req.tokenIssuedAt * 1000).toISOString(),
        expiresAt: new Date(req.tokenExpiresAt * 1000).toISOString(),
        timeRemaining: {
            totalSeconds: timeRemaining,
            minutes: minutesRemaining,
            seconds: secondsRemaining
        }
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});
