// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'inhumaJu4nC4m1l0T4b0rd4';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Para servir archivos estáticos

// Middleware de autenticación (similar a ActionFilter en .NET)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// Rutas de autenticación (equivalente a AccountController en .NET)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { usuario, contraseña } = req.body;

    // Validación básica
    if (!usuario || !contraseña) {
      return res.status(400).json({ 
        error: 'Usuario y contraseña son requeridos' 
      });
    }

    // Buscar usuario en la base de datos
    const user = await prisma.usuario.findUnique({
      where: { username: usuario }
    });

    if (!user) {
      return res.status(401).json({ 
        error: 'Credenciales inválidas' 
      });
    }

    // Verificar contraseña
    const validPassword = await bcrypt.compare(contraseña, user.password);
    if (!validPassword) {
      return res.status(401).json({ 
        error: 'Credenciales inválidas' 
      });
    }

    // Generar JWT token
    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username,
        rol: user.rol 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        rol: user.rol
      }
    });

  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Rutas de inhumaciones (equivalente a InhumacionController en .NET)
app.get('/api/inhumaciones', authenticateToken, async (req, res) => {
  try {
    const inhumaciones = await prisma.inhumacion.findMany({
      include: {
        usuario: {
          select: { username: true }
        }
      },
      orderBy: { fechaCreacion: 'desc' }
    });

    res.json(inhumaciones);
  } catch (error) {
    console.error('Error al obtener inhumaciones:', error);
    res.status(500).json({ error: 'Error al obtener inhumaciones' });
  }
});

app.post('/api/inhumaciones', authenticateToken, async (req, res) => {
  try {
    const { 
      nombreDifunto, 
      fechaDefuncion, 
      numeroLote, 
      observaciones 
    } = req.body;

    // Validación
    if (!nombreDifunto || !fechaDefuncion || !numeroLote) {
      return res.status(400).json({ 
        error: 'Datos incompletos' 
      });
    }

    const nuevaInhumacion = await prisma.inhumacion.create({
      data: {
        nombreDifunto,
        fechaDefuncion: new Date(fechaDefuncion),
        numeroLote,
        observaciones,
        usuarioId: req.user.id
      }
    });

    res.status(201).json(nuevaInhumacion);
  } catch (error) {
    console.error('Error al crear inhumación:', error);
    res.status(500).json({ error: 'Error al crear inhumación' });
  }
});

// Ruta para servir el HTML principal
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});

// Función para crear usuario administrador por defecto
async function crearUsuarioAdmin() {
  try {
    const adminExiste = await prisma.usuario.findUnique({
      where: { username: 'admin' }
    });

    if (!adminExiste) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await prisma.usuario.create({
        data: {
          username: 'admin',
          password: hashedPassword,
          rol: 'administrador'
        }
      });
      console.log('Usuario admin creado: admin/admin123');
    }
  } catch (error) {
    console.error('Error al crear usuario admin:', error);
  }
}

// Ejecutar al iniciar la aplicación
crearUsuarioAdmin();