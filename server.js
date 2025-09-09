const express = require('express');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs').promises;
const { PrismaClient } = require('@prisma/client');
const session = require('express-session');
const path = require('path');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const puppeteer = require('puppeteer');
const QRCode = require('qrcode');
const { Console } = require('console');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'inhumaJu4nC4m1l0T4b0rd4';

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
    },
  },
}));
app.use(express.json({ limit: '5mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: 'funeral-license-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// Servir archivos estáticos
app.use(express.static('public'));

//para debuggear, quitar en prod
/*app.use((req, res, next) => {
    console.log(`\n=== ${new Date().toISOString()} ===`);
    console.log(`${req.method} ${req.url}`);
    console.log('Headers:', req.headers);
    console.log('Body:', req.body);
    next();
});*/

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 3, // máximo 3 uploads por IP
  message: 'Demasiados uploads, intenta más tarde'
});

const ALLOWED_EXTENSIONS = ['.pdf', '.jpg', '.jpeg', '.png', '.gif'];
const ALLOWED_MIMETYPES = [
  'application/pdf',
  'image/jpeg',
  'image/jpg',
  'image/png',
  'image/gif'
];

function generateSecureFilename(originalName) {
  const ext = path.extname(originalName).toLowerCase();
  const timestamp = Date.now();
  const randomString = crypto.randomBytes(8).toString('hex');
  return `${timestamp}_${randomString}${ext}`;
}

// Función para validar nombre de archivo
function isValidFilename(filename) {
  // Evitar caracteres peligrosos y comandos
  const dangerousPatterns = [
    /\.\./g,           // Directory traversal
    /[;&|`$]/g,        // Command injection characters
    /\0/g,             // Null bytes
    /[<>:"|?*]/g,      // Windows reserved characters
    /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i // Windows reserved names
  ];
  
  return !dangerousPatterns.some(pattern => pattern.test(filename));
}

// Configuración de multer para almacenamiento seguro
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    try {
      await fs.access(uploadDir);
    } catch {
      await fs.mkdir(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generar nombre seguro
    const secureFilename = generateSecureFilename(file.originalname);
    cb(null, secureFilename);
  }
});

// Filtro de archivos con validaciones de seguridad
const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const mimetype = file.mimetype;
  
  // Validar extensión
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return cb(new Error(`Tipo de archivo no permitido: ${ext}`));
  }
  
  // Validar MIME type
  if (!ALLOWED_MIMETYPES.includes(mimetype)) {
    return cb(new Error(`MIME type no permitido: ${mimetype}`));
  }
  
  // Validar nombre de archivo
  if (!isValidFilename(file.originalname)) {
    return cb(new Error('Nombre de archivo contiene caracteres no permitidos'));
  }
  
  cb(null, true);
};

// Configuración de multer
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB máximo
    files: 3 // máximo 3 archivos por request
  },
  fileFilter: fileFilter
});

// Middleware para servir archivos estáticos
app.use(express.static('public'));

app.use('/api', (req, res, next) => {
    // Rutas públicas que no necesitan autenticación
    const privateRoutes = ['/api/inhumaciones','/api/menu'];
    
    if (privateRoutes.includes(req.path)) {
        authenticateToken(req, res, next);
    }
    else{
      console.log('✅ Ruta pública, saltando autenticación');
      return next();
    }
    
    // Aplicar autenticación para todas las demás rutas /api/*
    
});

app.get('/api/health', (req, res) => {
    console.log('=== HEALTH CHECK ===');
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString() 
    });
});

// Middleware de autenticación
const requireAuth = (req, res, next) => {
    // Verificar si el usuario está autenticado
    if (req.session && req.session.user) {
        return next(); // Usuario autenticado, continuar
    } else {
        // Usuario no autenticado, redirigir al login
        return res.redirect('index.html');
    }
};

//cargue menu principal
app.get('/api/menuadmin', authenticateToken, (req, res) => {
    console.log('Usuario autenticado:', req.user);
    const { rol } = req.user;

    const htmlFormulario = `
    <div class="form-title">Administración de Usuarios</div>
        <!-- Formulario para crear usuario -->
        <div class="crear-usuario-section">
            <h3>Crear Nuevo Usuario</h3>
                <div class="form-group">
                    <label for="usuario">Usuario:</label>
                    <input type="text" id="user" name="usuario" required 
                           placeholder="Ingrese el nombre de usuario">
                </div>
                
                <div class="form-group">
                    <label for="contraseña">Contraseña:</label>
                    <input type="password" id="password" name="contraseña" required 
                           placeholder="Ingrese la contraseña">
                </div>
                
                <div class="form-group">
                    <label for="rol">Rol:</label>
                    <select id="rol" name="rol" required>
                        <option value="">Seleccione un rol</option>
                        <option value="funeraria">Funeraria</option>
                        <option value="autorizador">Autorizador</option>
                        <option value="administrador">Administrador</option>
                    </select>
                </div>
                
                <div class="form-actions">
                    <button id="crear" class="btn-agregar">Crear Usuario</button>
                    <button type="reset" class="btn-agregar">Limpiar</button>
                </div>
        </div>
        
        <!-- Sección para mostrar mensajes -->
        <div id="mensajes" class="mensajes"></div>
    </div>
    `;
    
    res.send(htmlFormulario);
});

//cargue menu principal
app.get('/api/menu', authenticateToken, (req, res) => {
    console.log('Usuario autenticado:', req.user);
    const { rol } = req.user;

    const menuPorRol = {
        administrador: [
            { section: 'visualizar', label: 'Visualizar Autorizaciones pendientes', clase: 'menu-item' },
            { section: 'generar', label: 'Generar/ Solicitar Licencias', clase: 'menu-item' },
            { section: 'consultar', label: 'Consultar Licencias', clase: 'menu-item' },
            { section: 'admin', label: 'Administración de Usuarios', clase: 'active' }
        ],
        autorizador: [
            { section: 'visualizar', label: 'Visualizar Autorizaciones pendientes', clase: 'active' },
            { section: 'generar', label: 'Generar/ Solicitar Licencias', clase: 'menu-item' },
            { section: 'consultar', label: 'Consultar Licencias', clase: 'menu-item' }
        ],
        funeraria: [
            { section: 'generar', label: 'Generar/ Solicitar Licencias', clase: 'active' },
            { section: 'consultar', label: 'Consultar Licencias', clase: 'menu-item' }
        ]
    };

    if (!rol || !menuPorRol[rol]) {
        return res.status(400).json({ error: 'Rol inválido o no definido' });
    }

    res.json(menuPorRol[rol] || []);
});
//cargue botones
app.get('/api/user-buttons', authenticateToken, (req, res) => {
    console.log('Usuario autenticado:', req.user);
    const { rol } = req.user;

    const menuPorRol = {
        administrador: [
            {"id": "solicitarLicencia", "text": "Solicitar Licencia", "class": "btn-agregar", "action": "solicitarLicencia", "path": "/api/inhumaciones/solicitar" },
            {"id": "generarLicencia", "text": "Generar Licencia", "class": "btn-agregar", "action": "generarLicencia", "path": "/api/inhumaciones/generar" }
        ],
        autorizador: [
            {"id": "generarLicencia", "text": "Generar Licencia", "class": "btn-agregar", "action": "generarLicencia", "path": "/api/inhumaciones/generar" }
        ],
        funeraria: [
            {"id": "solicitarLicencia", "text": "Solicitar Licencia", "class": "btn-agregar", "action": "solicitarLicencia", "path": "/api/inhumaciones/solicitar" },
        ]
    };

    if (!rol || !menuPorRol[rol]) {
        return res.status(400).json({ error: 'Rol inválido o no definido' });
    }

    res.json(menuPorRol[rol] || []);
});

// Ruta para subir archivos con rate limiting (requiere autenticación)
app.post('/upload', requireAuth, uploadLimiter, upload.array('documents'), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No se seleccionaron archivos' });
    }

    // Procesar archivos subidos de forma segura
    const uploadedFiles = [];
    
    for (const file of req.files) {
      // Validaciones adicionales de seguridad
      const filePath = file.path;
      const stats = await fs.stat(filePath);
      
      // Verificar que el archivo fue creado correctamente
      if (stats.size !== file.size) {
        await fs.unlink(filePath); // Eliminar archivo corrupto
        throw new Error('Archivo corrupto detectado');
      }
      
      uploadedFiles.push({
        originalName: file.originalname,
        filename: file.filename,
        size: file.size,
        mimetype: file.mimetype
      });
    }

    // Log de seguridad (sin exponer rutas completas)
    console.log(`[UPLOAD] ${uploadedFiles.length} archivos subidos desde IP: ${req.ip}`);
    
    res.json({ 
      message: 'Archivos subidos correctamente',
      files: uploadedFiles
    });
    
  } catch (error) {
    console.error('[UPLOAD ERROR]', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Manejo de errores de multer
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'Archivo demasiado grande (máximo 5MB)' });
    }
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Demasiados archivos (máximo 3)' });
    }
  }
  res.status(400).json({ error: error.message || 'Error al procesar archivo' });
});

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
      where: { username: usuario
       }
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

// Rutas
// Middleware de autenticación con debug mejorado
function authenticateToken(req, res, next) {
  console.log('\n=== MIDDLEWARE authenticateToken ===');

  const authHeader = req.headers['authorization'];
  
  if (!authHeader) {
    console.log('❌ No se encontró header Authorization');
    return res.status(401).json({ 
      error: 'Token de acceso requerido',
      detalle: 'No se encontró el header Authorization'
    });
  }

  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  console.log('Token extraído:', token ? 'Presente' : 'Ausente');
  
  if (!token) {
    console.log('❌ Token no encontrado en el header');
    return res.status(401).json({ 
      error: 'Token de acceso requerido',
      detalle: 'Token no encontrado en el header Authorization'
    });
  }

  try {
    console.log('🔍 Verificando token...');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('✅ Token válido, usuario decodificado:', decoded);
    
    req.user = decoded;
    next();
  } catch (error) {
    console.log('❌ Error al verificar token:', error.message);
    console.log('❌ Tipo de error:', error.name);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({ 
        error: 'Token expirado',
        detalle: 'El token ha expirado'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ 
        error: 'Token inválido',
        detalle: 'El token no es válido'
      });
    }
    
    return res.status(403).json({ 
      error: 'Token inválido',
      detalle: error.message
    });
  }
}

// Endpoint con debug inicial
app.post('/api/inhumaciones/generar', upload.array("archivos", 3), authenticateToken, async (req, res) => {
  console.log('\n=== POST /api/inhumaciones ===');
  console.log('✅ Middleware de autenticación pasado exitosamente');
  console.log(req.body)
  try {
    const { 
      numeroDocumento, 
      nombres, 
      primerApellido, 
      segundoApellido,
      tipoDocumento,
      nombreSolicitante,
      sexo,
      tipoMuerte,
      fechaDefuncion,
      certificadoDefuncion,
      edad,
      tipoEdad,
      ciudadOrigen,
      ciudadDestino,
      requiereTraslado,
      autorizado,
      usuarioId
    } = req.body;

    // Validación
    if (!numeroDocumento || !nombres || !fechaDefuncion || !primerApellido) {
      console.log('❌ Validación fallida - Datos faltantes:', {
        numeroDocumento: !!numeroDocumento,
        nombres: !!nombres,
        fechaDefuncion: !!fechaDefuncion,
        primerApellido: !!primerApellido
      });
      return res.status(400).json({ 
        error: 'Datos incompletos',
        faltantes: {
          numeroDocumento: !numeroDocumento,
          nombres: !nombres,
          fechaDefuncion: !fechaDefuncion,
          primerApellido: !primerApellido
        }
      });
    }

    const nuevaInhumacion = await prisma.inhumacion.create({
      data: {
        numeroDocumento: numeroDocumento,
        nombres: nombres,
        primerApellido: primerApellido,
        segundoApellido: segundoApellido,
        tipoDocumento: tipoDocumento,
        nombreSolicitante: nombreSolicitante,
        sexo: sexo,
        tipoMuerte: tipoMuerte,
        fechaDefuncion: new Date(fechaDefuncion),
        certificadoDefuncion: certificadoDefuncion,
        edad: parseInt(edad),
        tipoEdad: tipoEdad,
        ciudadOrigen: ciudadOrigen,
        ciudadDestino: ciudadDestino,
        requiereTraslado: requiereTraslado,
        autorizado: autorizado,
        usuarioId: req.user.id
      }
    });

    await prisma.logAuditoria.create({
        data: {
          accion: 'CREATE',
          tabla: 'inhumacion',
          InhumacionId: nuevaInhumacion.id,
          usuarioId: req.user.id,
          detalles: JSON.stringify({
            operacion: 'crear_inhumacion_rol_autorizador',
            datos_creados: {
              numeroDocumento,
              nombres_completos: `${nombres} ${primerApellido} ${segundoApellido || ''}`.trim(),
              nombreSolicitante,
              tipoMuerte,
              fechaDefuncion,
              requiereTraslado,
              autorizado
            },
            metadata: {
              ip: req.ip || req.connection?.remoteAddress || 'unknown',
              userAgent: req.get('User-Agent') || 'unknown',
              timestamp: new Date().toISOString()
            }
          })
        }
      });

      const archivosSubidos = [];
        
      for (const file of req.files) {
        // Generar ID único para el archivo
        const archivoId = crypto.randomUUID();
            
        // Información del archivo
        const infoArchivo = {
            id: archivoId,
            InhumacionId:InhumacionId,
            nombreOriginal: file.originalname,
            nombreServidor: file.filename,
            ruta: "uploads/" + file.filename,
            size: formatFileSize(file.size),
            mimetype: file.mimetype,
            fechaSubida: new Date().toISOString()
        };
            
        // Guardar información en "base de datos" (archivo JSON para este ejemplo)
        await guardarInfoArchivo(infoArchivo);
            
        archivosSubidos.push({
            id: archivoId,
            nombre: file.originalname,
            tamaño: formatFileSize(file.size),
            url: `/uploads/${archivoId}`
        });
      }

      console.log('✅ Inhumación creada exitosamente:', nuevaInhumacion);
      res.status(201).json(nuevaInhumacion);

  } catch (error) {
    console.error('❌ Error al crear inhumación:', error);
    console.error('❌ Stack trace:', error.stack);
    res.status(500).json({ 
      error: 'Error al crear inhumación',
      mensaje: error.message 
    });
  }
});

app.get('/api/inhumaciones/:id/archivos', authenticateToken, async (req, res) => {
  const inhumacionId = parseInt(req.params.id, 10);

  try {
    // Aquí buscas los archivos en tu DB o JSON en base al ID
    const archivos = await prisma.rutaArchivos.findMany({
            where: {
                InhumacionId: inhumacionId
            }
        });
    if (!archivos) {
      return res.json({ archivos: [] });
    }

    res.json(archivos);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al obtener archivos" });
  }
});

app.post('/api/inhumaciones/solicitar', upload.array("archivos", 3),  authenticateToken, async (req, res) => {
  console.log('\n=== POST /api/inhumaciones ===');
  console.log('✅ Middleware de autenticación pasado exitosamente');
  console.log(req.body)
  let IdInhumacion = "";
  try {
    const { 
      idInhuma,
      numeroDocumento, 
      nombres, 
      primerApellido, 
      segundoApellido,
      tipoDocumento,
      nombreSolicitante,
      sexo,
      tipoMuerte,
      fechaDefuncion,
      certificadoDefuncion,
      edad,
      tipoEdad,
      ciudadOrigen,
      ciudadDestino,
      requiereTraslado,
      autorizado,
      usuarioId
    } = req.body;

    // Validación
    if (!numeroDocumento || !nombres || !fechaDefuncion || !primerApellido) {
      console.log('❌ Validación fallida - Datos faltantes:', {
        numeroDocumento: !!numeroDocumento,
        nombres: !!nombres,
        fechaDefuncion: !!fechaDefuncion,
        primerApellido: !!primerApellido
      });
      return res.status(400).json({ 
        error: 'Datos incompletos',
        faltantes: {
          numeroDocumento: !numeroDocumento,
          nombres: !nombres,
          fechaDefuncion: !fechaDefuncion,
          primerApellido: !primerApellido
        }
      });
    }
    if (idInhuma === "")
    {
      const nuevaInhumacion = await prisma.inhumacion.create({
        data: {
          numeroDocumento: numeroDocumento,
          nombres: nombres,
          primerApellido: primerApellido,
          segundoApellido: segundoApellido,
          tipoDocumento: tipoDocumento,
          nombreSolicitante: nombreSolicitante,
          sexo: sexo,
          tipoMuerte: tipoMuerte,
          fechaDefuncion: new Date(fechaDefuncion),
          certificadoDefuncion: certificadoDefuncion,
          edad: parseInt(edad),
          tipoEdad: tipoEdad,
          ciudadOrigen: ciudadOrigen,
          ciudadDestino: ciudadDestino,
          requiereTraslado: requiereTraslado,
          autorizado: autorizado,
          usuarioId: req.user.id
        }
      });
      IdInhumacion = nuevaInhumacion.id;
      await prisma.logAuditoria.create({
          data: {
            accion: 'CREATE',
            tabla: 'inhumacion',
            InhumacionId: nuevaInhumacion.id,
            usuarioId: req.user.id,
            detalles: JSON.stringify({
              operacion: 'crear_inhumacion_rol_funeraria',
              datos_creados: {
                numeroDocumento,
                nombres_completos: `${nombres} ${primerApellido} ${segundoApellido || ''}`.trim(),
                nombreSolicitante,
                tipoMuerte,
                fechaDefuncion,
                requiereTraslado,
                autorizado
              },
              metadata: {
                ip: req.ip || req.connection?.remoteAddress || 'unknown',
                userAgent: req.get('User-Agent') || 'unknown',
                timestamp: new Date().toISOString()
              }
            })
          }
        });    
        console.log('✅ Inhumación creada exitosamente:', nuevaInhumacion);
        res.status(201).json(nuevaInhumacion);
    }
    else {
      IdInhumacion = idInhuma;
      const resultado = await prisma.$transaction(async (tx) => {
      // Obtener datos anteriores para comparación
      const inhumacionAnterior = await tx.inhumacion.findUnique({
        where: { id: parseInt(idInhuma) }
      });

      if (!inhumacionAnterior) {
        throw new Error('Inhumación no encontrada');
      }
      const datosActualizacion = {
          numeroDocumento: numeroDocumento,
          nombres: nombres,
          primerApellido: primerApellido,
          segundoApellido: segundoApellido,
          tipoDocumento: tipoDocumento,
          nombreSolicitante: nombreSolicitante,
          sexo: sexo,
          tipoMuerte: tipoMuerte,
          fechaDefuncion: new Date(fechaDefuncion),
          certificadoDefuncion: certificadoDefuncion,
          edad: parseInt(edad),
          tipoEdad: tipoEdad,
          ciudadOrigen: ciudadOrigen,
          ciudadDestino: ciudadDestino,
          requiereTraslado: requiereTraslado,
          autorizado: autorizado,
          usuarioId: req.user.id
        }

      // Actualizar la inhumación
      const inhumacionActualizada = await tx.inhumacion.update({
        where: { id: parseInt(idInhuma) },
        data: datosActualizacion
      });

      // Crear auditoría con datos anteriores y nuevos
      await tx.logAuditoria.create({
        data: {
          accion: 'UPDATE',
          tabla: 'inhumacion',
          InhumacionId: parseInt(idInhuma),
          usuarioId: req.user.id,
          detalles: JSON.stringify({
            operacion: 'actualizar informacion',
            cambios_realizados: obtenerCambios(inhumacionAnterior, datosActualizacion)
          })
        }
      });
      console.log('✅ Inhumación creada exitosamente:', datosActualizacion);
      res.status(201).json(datosActualizacion);
    });
  }
      
  const archivosSubidos = [];

        
  for (const file of req.files) {
        // Generar ID único para el archivo
        const archivoId = crypto.randomUUID();
            
        // Información del archivo
        const infoArchivo = {
            InhumacionId: parseInt(IdInhumacion),
            nombreOriginal: file.originalname,
            nombreServidor: file.filename,
            ruta: "uploads/" + file.filename,
            size: formatFileSize(file.size),
            mimetype: file.mimetype,
            fechaSubida: new Date().toISOString()
        };

        console.log(infoArchivo);
            
        // Guardar información en "base de datos" (archivo JSON para este ejemplo)
        await guardarInfoArchivo(infoArchivo);
            
        archivosSubidos.push({
            id: archivoId,
            nombre: file.originalname,
            tamaño: formatFileSize(file.size),
            url: `/uploads/${archivoId}`
        });
      }


  } catch (error) {
    console.error('❌ Error al crear inhumación:', error);
    console.error('❌ Stack trace:', error.stack);
    res.status(500).json({ 
      error: 'Error al crear inhumación',
      mensaje: error.message 
    });
  }
});

app.get('/api/inhumaciones', authenticateToken, async (req, res) => {
    console.log('\n=== GET /api/inhumaciones ===');
    console.log('Usuario:', req.user);
    
    // Verificar si el usuario está autenticado
    if (!req.user) {
        console.error('❌ Usuario no autenticado');
        return res.status(401).json({
            success: false,
            message: 'Usuario no autenticado'
        });
    }
    
    if (!req.user.id) {
        console.error('❌ Usuario sin ID');
        return res.status(400).json({
            success: false,
            message: 'Usuario sin ID válido'
        });
    }
    
    try {
        const usuarios = await prisma.usuariosAutorizacion.findMany({
            where: {
                idAutorizador: req.user.id
            },
            select: {
                idUsuarios: true
            }
        });
        const listaIds = usuarios.map(u => u.idUsuarios);

        const inhumaciones = await prisma.inhumacion.findMany({
            where: {
                usuarioId: {
                    in: listaIds
                },
                autorizado: "Pendiente"
            },
            orderBy: {
                fechaCreacion: 'desc'
            }
        });
        
        console.log('✅ Inhumaciones encontradas:', inhumaciones.length);
        res.json(inhumaciones);
        
    } catch (error) {
        console.error('❌ Error obteniendo inhumaciones:', error);
        res.status(500).json({
            success: false,
            message: 'Error obteniendo inhumaciones',
            error: error.message
        });
    }
});

app.get('/api/:id/inhumaciones', authenticateToken, async (req, res) => {
    console.log('\n=== GET /api/inhumaciones ===');
    console.log('Usuario:', req.user);
    const { id } = req.params;
    
    // Verificar si el usuario está autenticado
    if (!req.user) {
        console.error('❌ Usuario no autenticado');
        return res.status(401).json({
            success: false,
            message: 'Usuario no autenticado'
        });
    }
    
    if (!req.user.id) {
        console.error('❌ Usuario sin ID');
        return res.status(400).json({
            success: false,
            message: 'Usuario sin ID válido'
        });
    }
    
    try {
        const inhumaciones = await prisma.inhumacion.findUnique({
            where: {
                id: parseInt(id)
            }
        });
        
        console.log('✅ Inhumaciones encontradas:', inhumaciones.length);
        res.json(inhumaciones);
        
    } catch (error) {
        console.error('❌ Error obteniendo inhumaciones:', error);
        res.status(500).json({
            success: false,
            message: 'Error obteniendo inhumaciones',
            error: error.message
        });
    }
});

app.get('/api/:id/licencias', authenticateToken, async (req, res) => {
    console.log('\n=== GET /api/licencias ===');
    console.log('Usuario:', req.user);
    try {
        const { id } = req.params;
        let observaciones = '';
        const inhumaciones = await prisma.inhumacion.findFirst({
            where: {
                numeroDocumento: id
            }
        });

        const obs = await prisma.logAuditoria.findFirst({
            where: {
                InhumacionId: inhumaciones.id
            },
            orderBy:{
                fecha: 'desc'
            }
        });

        if (JSON.parse(obs.detalles).operacion == 'autorizar_licencia')
        {
            if('motivo' in JSON.parse(obs.detalles)){
                observaciones = JSON.parse(obs.detalles).motivo;
            }
        }
        
        const resultado = [{
            idLicencia: inhumaciones.id,
            numeroDocumento: inhumaciones.numeroDocumento,
            nombres: inhumaciones.nombres,
            primerApellido: inhumaciones.primerApellido,
            segundoApellido: inhumaciones.segundoApellido,
            autorizado: inhumaciones.autorizado,
            comentarios: observaciones
        }];
        res.json(resultado);
        
    } catch (error) {
        console.error('❌ Error obteniendo inhumaciones:', error);
        res.status(500).json({
            success: false,
            message: 'Error obteniendo inhumaciones',
            error: error.message
        });
    }
});

app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

app.put('/api/inhumaciones/autorizar/:id', authenticateToken, async (req, res) => {
    try {
    const { id } = req.params;

    const resultado = await prisma.$transaction(async (tx) => {
      // Obtener datos anteriores para comparación
      const inhumacionAnterior = await tx.inhumacion.findUnique({
        where: { id: parseInt(id) }
      });

      if (!inhumacionAnterior) {
        throw new Error('Inhumación no encontrada');
      }

      const datosActualizacion = {
                autorizado: "Aprobado",
                fechaActualizacion: new Date()
            };

      // Actualizar la inhumación
      const inhumacionActualizada = await tx.inhumacion.update({
        where: { id: parseInt(id) },
        data: datosActualizacion
      });

      // Crear auditoría con datos anteriores y nuevos
      await tx.logAuditoria.create({
        data: {
          accion: 'UPDATE',
          tabla: 'inhumacion',
          InhumacionId: parseInt(id),
          usuarioId: req.user.id,
          detalles: JSON.stringify({
            operacion: 'autorizar_licencia',
            cambios_realizados: obtenerCambios(inhumacionAnterior, datosActualizacion)
          })
        }
      });

      return inhumacionActualizada;
    });

    res.json({
      success: true,
      data: resultado,
      message: 'Inhumación actualizada exitosamente'
    });

  } catch (error) {
    console.error('Error al actualizar inhumación:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error interno del servidor'
    });
  }
});

app.put('/api/inhumaciones/rechazar/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { motivo } = req.body;

        const resultado = await prisma.$transaction(async (tx) => {
        // Obtener datos anteriores para comparación
        const inhumacionAnterior = await tx.inhumacion.findUnique({
            where: { id: parseInt(id) }
        });

        if (!inhumacionAnterior) {
            throw new Error('Inhumación no encontrada');
        }

        const datosActualizacion = {
                autorizado: "Rechazado",
                fechaActualizacion: new Date()
            };

      // Actualizar la inhumación
      const inhumacionActualizada = await tx.inhumacion.update({
        where: { id: parseInt(id) },
        data: datosActualizacion
      });

      // Crear auditoría con datos anteriores y nuevos
      await tx.logAuditoria.create({
        data: {
          accion: 'UPDATE',
          tabla: 'inhumacion',
          InhumacionId: parseInt(id),
          usuarioId: req.user.id,
          detalles: JSON.stringify({
            operacion: 'autorizar_licencia',
            motivo: motivo,
            cambios_realizados: obtenerCambios(inhumacionAnterior, datosActualizacion)
          })
        }
      });

      return inhumacionActualizada;
    });

    res.json({
      success: true,
      data: resultado,
      message: 'Inhumación actualizada exitosamente'
    });

  } catch (error) {
    console.error('Error al actualizar inhumación:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error interno del servidor'
    });
  }
});

app.post('/api/crear-usuario', authenticateToken, async (req, res) => {
    try {
        const { usuario, contraseña, rol } = req.body;
        
        if(req.user.rol != "administrador"){
          return res.status(400).json({ error: 'El usuario logueado no tiene permisos para crear usuarios' });
        }
  
        if (!usuario || !contraseña || !rol) {
            return res.status(400).json({ error: 'Todos los campos son obligatorios' });
        }
        
        if (!['funeraria', 'autorizador', 'administrador'].includes(rol)) {
            return res.status(400).json({ error: 'Rol no válido' });
        }
        
        // Verificar si el usuario ya existe
        const usuarioExistente = await prisma.usuario.findFirst({
            where: { username: usuario }
        });
        
        if (usuarioExistente) {
            return res.status(409).json({ error: 'El usuario ya existe' });
        }
        
        // Crear el usuario (asume que tienes bcrypt para hashear la contraseña)
        const bcrypt = require('bcrypt');
        const contraseñaHash = await bcrypt.hash(contraseña, 10);
        
        const nuevoUsuario = await prisma.usuario.create({
            data: {
                username: usuario,
                password: contraseñaHash,
                rol: rol
            }
        });
        
        // No devolver la contraseña en la respuesta
        const { contraseña: _, ...usuarioSinContraseña } = nuevoUsuario;
        
        res.status(201).json({
            message: 'Usuario creado exitosamente',
            usuario: usuarioSinContraseña
        });
        
    } catch (error) {
        console.error('Error al crear usuario:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

function formatFileSize(bytes) {
    // Verificar si el valor es válido
    if (bytes === 0) return '0 Bytes';
    if (!bytes || bytes < 0) return 'Tamaño desconocido';
    
    // Definir las unidades
    const unidades = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const k = 1024;
    
    // Calcular el índice de la unidad apropiada
    const indice = Math.floor(Math.log(bytes) / Math.log(k));
    
    // Limitar el índice al rango válido
    const indiceSeguro = Math.min(indice, unidades.length - 1);
    
    // Calcular el tamaño en la unidad apropiada
    const tamaño = bytes / Math.pow(k, indiceSeguro);
    
    // Formatear con decimales apropiados
    const tamaño_formateado = indiceSeguro === 0 ? 
        tamaño.toString() : 
        tamaño.toFixed(2);
    
    return `${tamaño_formateado} ${unidades[indiceSeguro]}`;
}

function generarHTMLLicencia(datos) {
  return `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Licencia de Inhumación</title>
    <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .documento {
            background: white;
            max-width: 800px;
            width: 100%;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            position: relative;
            overflow: hidden;
        }

        .documento::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        }

        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #e9ecef;
        }

        .logo-section {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .logo {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            font-size: 18px;
        }

        .titulo-principal {
            font-size: 24px;
            font-weight: 700;
            color: #2c3e50;
            letter-spacing: 0.5px;
        }

        .numero-licencia {
            font-size: 16px;
            font-weight: 500;
            color: #6c757d;
            margin-top: 4px;
        }

        .fecha-expedicion {
            text-align: right;
            color: #495057;
        }

        .fecha-label {
            font-size: 12px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #6c757d;
            margin-bottom: 4px;
        }

        .fecha-valor {
            font-size: 14px;
            font-weight: 600;
            color: #2c3e50;
        }

        .seccion {
            margin-bottom: 25px;
        }

        .seccion-titulo {
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #495057;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 1px solid #dee2e6;
        }

        .fila {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 20px;
        }

        .fila.completa {
            grid-template-columns: 1fr;
        }

        .campo {
            display: flex;
            flex-direction: column;
        }

        .campo-label {
            font-size: 12px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #6c757d;
            margin-bottom: 6px;
        }

        .campo-valor {
            font-size: 16px;
            font-weight: 400;
            color: #2c3e50;
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
            min-height: 32px;
        }

        .campo-valor.destacado {
            font-weight: 600;
            color: #495057;
        }

        .nombres-fallecido {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 20px;
        }

        .autorizacion {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            margin: 30px 0;
            border: 1px solid #dee2e6;
            display: none;
        }

        .autorizacion-texto {
            font-size: 14px;
            font-weight: 500;
            color: #495057;
            line-height: 1.6;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .funcionario {
            text-align: center;
            margin-top: 40px;
            padding-top: 30px;
            border-top: 1px solid #dee2e6;
        }

        .funcionario-titulo {
            font-size: 12px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #6c757d;
            margin-bottom: 20px;
        }

        .funcionario-nombre {
            font-size: 18px;
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 6px;
        }

        .funcionario-cc {
            font-size: 14px;
            color: #6c757d;
            margin-bottom: 30px;
        }

        .qr-code {
            width: 80px;
            height: 80px;
            background: #f8f9fa;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .qr-code:hover {
            border-color: #667eea;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.2);
        }

        .qr-code img {
            max-width: 100%;
            max-height: 100%;
            border-radius: 4px;
        }

        .watermark {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%) rotate(-45deg);
            font-size: 60px;
            font-weight: 100;
            color: rgba(0, 0, 0, 0.03);
            pointer-events: none;
            z-index: 0;
        }

        .contenido {
            position: relative;
            z-index: 1;
        }

        @media (max-width: 768px) {
            .documento {
                padding: 20px;
                margin: 10px;
            }
            
            .fila {
                grid-template-columns: 1fr;
                gap: 15px;
            }
            
            .nombres-fallecido {
                grid-template-columns: 1fr;
            }
            
            .header {
                flex-direction: column;
                text-align: center;
                gap: 15px;
            }
        }

        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .documento {
                box-shadow: none;
                max-width: none;
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="documento">
        <div class="watermark">OFICIAL</div>
        <div class="contenido">
            <div class="header">
                <div class="logo-section">
                    <div class="logo">LI</div>
                    <div>
                        <h1 class="titulo-principal">LICENCIA DE INHUMACIÓN</h1>
                        <div class="numero-licencia">No ${datos.numeroLicencia}</div>
                    </div>
                </div>
                <div class="fecha-expedicion">
                    <div class="fecha-label">Fecha de Expedición</div>
                    <div class="fecha-valor">${datos.fechaExpedicion}</div>
                </div>
            </div>

            <div class="seccion">
                <div class="seccion-titulo">Información del Lugar</div>
                <div class="fila">
		    <div class="campo">
                        <div class="campo-label">Departamento</div>
                        <div class="campo-valor">${datos.departamento}</div>
                    </div>
                    <div class="campo">
                        <div class="campo-label">Municipio</div>
                        <div class="campo-valor">${datos.municipio}</div>
                    </div>
                    <div class="campo">
                        <div class="campo-label">Inspección - Corregimiento o Caserio</div>
                        <div class="campo-valor">${datos.inspeccion}</div>
                    </div>
                </div>
            </div>

            <div class="seccion">
                <div class="seccion-titulo">Información del Fallecido</div>
                <div class="fila">
                    <div class="campo">
                        <div class="campo-label">Sexo</div>
                        <div class="campo-valor destacado">${datos.sexo}</div>
                    </div>
                    <div class="campo">
                        <div class="campo-label">Edad</div>
                        <div class="campo-valor">${datos.edad} ${datos.tipoEdad}</div>
                    </div>
                </div>
                <div class="nombres-fallecido">
                    <div class="campo">
                        <div class="campo-label">Primer Apellido</div>
                        <div class="campo-valor">${datos.primerApellido}</div>
                    </div>
                    <div class="campo">
                        <div class="campo-label">Segundo Apellido</div>
                        <div class="campo-valor">${datos.segundoApellido}</div>
                    </div>
                    <div class="campo">
                        <div class="campo-label">Nombres</div>
                        <div class="campo-valor">${datos.nombres}</div>
                    </div>
                </div>
            </div>
            <br/>
            <br/>
            <br/>
            <div class="seccion">
                <div class="seccion-titulo">Detalles del Fallecimiento</div>
                <div class="fila">
		                <div class="campo">
                        <div class="campo-label">Nombre del Solicitante</div>
                        <div class="campo-valor destacado">${datos.solcitante}</div>
                    </div>
                    <div class="campo">
                        <div class="campo-label">Fecha de Fallecimiento</div>
                        <div class="campo-valor destacado">${datos.fechaExpedicion}</div>
                    </div>
                    <div class="campo">
                        <div class="campo-label">Probable Manera de Muerte</div>
                        <div class="campo-valor">${datos.maneraMuerte}</div>
                    </div>
                </div>
                <div class="fila">
                    <div class="campo">
                        <div class="campo-label">Según Certificado de Defunción N°</div>
                        <div class="campo-valor">${datos.certificadoDefuncion}</div>
                    </div>
                    <div class="campo">
                        <div class="campo-label">Documento de Identificación</div>
                        <div class="campo-valor">${datos.tipoDocumento} ${datos.documento}</div>
                    </div>
                </div>
            </div>

            <div id="autorizacion" class="autorizacion">
                <div class="autorizacion-texto">
                    Se autoriza el traslado del cuerpo<br>
                    para su inhumación desde ${datos.ciudadOrigen}<br>
                    hasta ${datos.ciudadDestino}
                </div>
            </div>

            <div class="funcionario">
                <div class="funcionario-titulo">Funcionario o Autoridad que Expide la Licencia</div>
                <div class="funcionario-nombre">${datos.funcionarionombre}</div>
                <div class="funcionario-cc">${datos.funcionariocedula}</div>
                <div class="qr-code">
                <img src="${datos.qrDataURL}" alt="Código QR de verificación" title="Escanear para verificar: ${datos.urlVerificacion}">
            </div>
            </div>
        </div>
    </div>
    <script>
      const datosAutorizacion = {
            lugarOrigen: '${datos.ciudadOrigen}',      // Cambia por '' o null para ocultar la sección
            lugarDestino: '${datos.ciudadDestino}',    // Cambia por '' o null para ocultar la sección
        };
      function validarAutorizacion() {
        const seccionAutorizacion = document.getElementById('autorizacion');
        const hayDatos = datosAutorizacion.lugarOrigen && 
                           datosAutorizacion.lugarOrigen.trim() !== '' &&
                           datosAutorizacion.lugarDestino && 
                           datosAutorizacion.lugarDestino.trim() !== '';

        if (hayDatos) {
          seccionAutorizacion.style.display = 'block';
        }
        else {
          seccionAutorizacion.style.display = 'none'
        }
      }
        async function inicializarLicencia() {
            // Validar sección de autorización
            validarAutorizacion();
        }
      document.addEventListener('DOMContentLoaded', inicializarLicencia);
    </script>
</body>
</html>`;
}

async function generarPDFLicencia(datos) {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  try {
    const page = await browser.newPage();
    
    // Configurar el viewport y formato de página
    await page.setViewport({ width: 794, height: 1123 }); // A4 en pixels
    const html = generarHTMLLicencia(datos);
    await page.setContent(html, { waitUntil: 'networkidle0' });
  
    const pdf = await page.pdf({
        format: 'Letter',
        landscape: false,
        margin: { top: '15mm', bottom: '15mm', left: '15mm', right: '15mm' },
        printBackground: true
    });
    
    // CONVERTIR A BUFFER EXPLÍCITAMENTE
    const pdfBuffer = Buffer.from(pdf);
    
    return pdfBuffer;
  } catch (error) {
    console.error('Error generando PDF:', error);
    throw error;
  } finally {
    await browser.close();
  }
}

async function guardarInfoArchivo(info) {
    try{
      const nuevoArchivo = await prisma.rutaArchivos.create({data: info});
      console.log('✅ archivos cargardos exitosamente:', nuevoArchivo);
      return nuevoArchivo;
    }
    catch (error) {
      console.error("error al cargar la informacion a la BD: ", error );
      return error;
    }
}

// Función para usar con Express
async function crearRutaPDF(app) {
  app.get('/licencia-inhumacion/:id', async (req, res) => {
    try {
      const { id } = req.params;
      
      // Aquí harías la consulta a tu base de datos
      // const datos = await obtenerDatosLicencia(id);
      
      // Por ahora usamos datos de ejemplo
      const datos = { ...datosLicencia, numeroLicencia: id };
      
      const pdf = await generarPDFLicencia(datos);
      
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=licencia-${id}.pdf`);
      res.send(pdf);
      
    } catch (error) {
      console.error('Error generando PDF:', error);
      res.status(500).json({ error: 'Error generando la licencia' });
    }
  });
}

// Función standalone para generar PDF
async function generarLicenciaPDF(datosFromDB, outputPath = null) {
  try {
    const pdf = await generarPDFLicencia(datosFromDB);
    
    if (outputPath) {
      require('fs').writeFileSync(outputPath, pdf);
      console.log(`PDF generado en: ${outputPath}`);
    }
    
    return pdf;
  } catch (error) {
    console.error('Error:', error);
    throw error;
  }
}

async function obtenerDatosLicencia(licenciaId) {
    try {
        const inhumaciones = await prisma.inhumacion.findUnique({
                where: {
                    id: parseInt(licenciaId),
                    autorizado: "Aprobado"
                }
            });

        const urlVerificacion = `"http://localhost:3000/api/licencia/${licenciaId}/view"`;
        
        // Generar QR como Data URL
        const qrDataURL = await QRCode.toDataURL(urlVerificacion, {
            quality: 0.92,
            margin: 1,
            color: {
                dark: '#2c3e50',
                light: '#FFFFFF'
            },
            width: 200
        });
        
        const data = {
            numeroLicencia: licenciaId,
            fechaExpedicion: new Date(inhumaciones.fechaActualizacion),
            departamento: "Tolima",
            municipio: "Ibagué",
            inspeccion: "Ibagué",
            solicitante: inhumaciones.nombreSolicitante,
            primerApellido: inhumaciones.primerApellido,
            segundoApellido: inhumaciones.segundoApellido,
            nombres: inhumaciones.nombres,
            sexo: inhumaciones.sexo,
            fechaFallecimiento: inhumaciones.fechaDefuncion,
            maneraMuerte: inhumaciones.tipoMuerte,
            certificadoDefuncion: inhumaciones.certificadoDefuncion,
            documento: inhumaciones.numeroDocumento,
            tipoDocumento: inhumaciones.tipoDocumento,
            ciudadOrigen: inhumaciones.ciudadOrigen,
            ciudadDestino: inhumaciones.ciudadDestino,
            edad: inhumaciones.edad,
            tipoEdad: inhumaciones.tipoEdad,
            funcionarionombre: "Pepe Pedro Perez",
            funcionariocedula: "CC 343443344",
            urlVerificacion: urlVerificacion,
            qrDataURL: qrDataURL
        };
        return data;

    } catch (error) {
        console.error('❌ Error obteniendo inhumaciones:', error);
    }
}

function formatearFecha(fecha) {
  if (!fecha) return '';
  
  const date = new Date(fecha);
  const dia = date.getDate().toString().padStart(2, '0');
  const mes = (date.getMonth() + 1).toString().padStart(2, '0');
  const año = date.getFullYear();
  
  return `${dia}-${mes}-${año}`;
}

// Endpoint para generar PDF de licencia específica
app.get('/api/licencia/:id/pdf', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Obtener datos de la base de datos
    const datos = await obtenerDatosLicencia(id);
    
    // Generar PDF
    const pdf = await generarPDFLicencia(datos);
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="licencia.pdf"');
    res.setHeader('Content-Length', pdfBuffer.length);
    
    // Enviar el buffer
    res.send(pdfBuffer);
    
  } catch (error) {
    console.error('Error generando PDF:', error);
    res.status(500).json({ 
      error: 'Error generando la licencia',
      details: error.message 
    });
  }
});

// Endpoint para ver PDF en el navegador (sin descarga)
app.get('/api/licencia/:id/view', async (req, res) => {
  try {
    const { id } = req.params;
    const datos = await obtenerDatosLicencia(id);

    const pdf = await generarPDFLicencia(datos);
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline');
    res.send(pdf);
    
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'La licencia aun no ha sido aprobada' });
  }
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
    //console.log('Usuarios disponibles:');
    //console.log('- admin / admin123 (Administrador)');
    //console.log('- funeraria1 / pass123 (Funeraria)');
    //console.log('- operador / oper123 (Operador)');
});

// Manejo de errores
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('¡Algo salió mal!');
});

// Ruta 404
app.use((req, res) => {
    res.status(404).send(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Página no encontrada</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 50px;
                    background-color: #f5f5f5;
                }
                .error-container {
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    display: inline-block;
                }
                .back-btn {
                    background-color: #007bff;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="error-container">
                <h1>404 - Página no encontrada</h1>
                <p>La página que buscas no existe.</p>
                <a href="/dashboard" class="back-btn">Volver al Dashboard</a>
            </div>
        </body>
        </html>
    `);
});

app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));




// Función auxiliar para detectar cambios
function obtenerCambios(datosAnteriores, datosNuevos) {
  const cambios = {};
  
  for (const [key, valor] of Object.entries(datosNuevos)) {
    if (datosAnteriores[key] !== valor) {
      cambios[key] = {
        anterior: datosAnteriores[key],
        nuevo: valor
      };
    }
  }
  
  return cambios;
}

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
      console.log('Usuario funeraria creado: admin/admin123');
    }
  } catch (error) {
    console.error('Error al crear usuario admin:', error);
  }
}

module.exports = {
    generarPDFLicencia,
    generarLicenciaPDF,
    crearRutaPDF,
    app
};
// Ejecutar al iniciar la aplicación
crearUsuarioAdmin();