const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const path = require('path');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const CryptoJS = require('crypto-js');
const http = require('http');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();


// ======================
// Configuración Constante
// ======================
const ENCRYPTION_KEY = "1234567890abcdef1234567890abcdef";
const JWT_SECRET = "06177160876567451054943720268410";
const PORT = process.env.PORT || 4000; 
const DB_CONFIG = {
  host: "gateway01.us-east-1.prod.aws.tidbcloud.com",
  user: "4TWMF3o8nW2rqkp.root",
  password: "Pc29ZYqysxBygU2G",
  database: "pr_uni",
  connectionLimit: 10
};
const EMAIL_CONFIG = {
  service: "gmail",
  auth: {
    user: "dinocraft617@gmail.com",
    pass: "ihgd wnvq mpdo hinp"
  }
};

// Funciones de utilidad mejoradas
const encryptData = (data) => {
  if (!data) return null;
  try {
    const normalized = data.toString().toLowerCase().trim();
    const encrypted = CryptoJS.AES.encrypt(
      normalized,
      CryptoJS.enc.Utf8.parse(ENCRYPTION_KEY),
      { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }
    ).toString();
    console.log(`Encriptado: ${data} -> ${encrypted}`);
    return encrypted;
  } catch (error) {
    console.error('Error al encriptar:', error);
    throw error;
  }
};

const decryptData = (ciphertext) => {
  if (!ciphertext) return null;
  try {
    const bytes = CryptoJS.AES.decrypt(
      ciphertext,
      CryptoJS.enc.Utf8.parse(ENCRYPTION_KEY),
      { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }
    );
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);
    if (!decrypted) {
      throw new Error('Resultado de desencriptación vacío');
    }
    console.log(`Desencriptado: ${ciphertext} -> ${decrypted}`);
    return decrypted;
  } catch (error) {
    console.error('Error al desencriptar:', error);
    throw error;
  }
};

const generateVerificationCode = () => Math.floor(100000 + Math.random() * 900000).toString();

// Configuración inicial
const pool = mysql.createPool(DB_CONFIG);
const transporter = nodemailer.createTransport(EMAIL_CONFIG);

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cors({
  origin: "*",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Manejar preflight OPTIONS requests
app.options('*', cors());

// Configuración de Helmet - quitar restricciones HTTPS
app.use(helmet({
  contentSecurityPolicy: process.env.NODE_ENV === 'production' ? {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", 'https://your-production-domain.com']
    }
  } : false
}));

// Middleware de autenticación JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }

      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

app.get('/', (req, res) => {
  res.json({ 
    message: 'Backend PR_PW funcionando correctamente',
    version: '1.0.0',
    endpoints: {
      auth: ['/register', '/login', '/verify'],
      users: '/api/users',
      catalog: '/api/catalogo'
    }
  });
});

// ======================
// Rutas de Autenticación
// ======================

// Registro de Usuario 
app.post('/register', [
  body('username').trim().notEmpty().withMessage('Nombre de usuario requerido'),
  body('email').isEmail().normalizeEmail().withMessage('Email inválido'),
  body('password').isLength({ min: 8 }).withMessage('La contraseña debe tener al menos 8 caracteres'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Las contraseñas no coinciden');
    }
    return true;
  })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.error('Validation errors:', errors.array());
    return res.status(400).json({ 
      success: false, 
      error: 'Validation failed',
      details: errors.array() 
    });
  }

  const { username, email, password } = req.body;

  try {
    console.log('Starting registration for:', username, email);
    
    // Verify database connection first
    let conn;
    try {
      conn = await pool.getConnection();
      console.log('Database connection established');
    } catch (dbError) {
      console.error('Database connection error:', dbError);
      return res.status(500).json({ 
        success: false, 
        error: 'Database connection failed',
        details: process.env.NODE_ENV === 'development' ? dbError.message : null
      });
    }

    // Check if user exists
    const [userExists] = await conn.query('SELECT id_user FROM usuarios WHERE nombre = ?', [username]);
    if (userExists.length > 0) {
      conn.release();
      return res.status(409).json({ 
        success: false, 
        error: 'Usuario ya existe' 
      });
    }

    // Check if email exists
    const encryptedEmail = encryptData(email);
    console.log('Encrypted email:', encryptedEmail);
    
    const [emailExists] = await conn.query('SELECT id_user FROM usuarios WHERE correo = ?', [encryptedEmail]);
    if (emailExists.length > 0) {
      conn.release();
      return res.status(409).json({ 
        success: false, 
        error: 'Correo ya registrado' 
      });
    }

    // Generate verification code
    const verificationCode = generateVerificationCode();
    console.log(`Verification code for ${email}: ${verificationCode}`);

    // Send email (wrap in try-catch)
    try {
      await transporter.sendMail({
        from: `"Sistema de Registro" <${EMAIL_CONFIG.auth.user}>`,
        to: email,
        subject: "Código de Verificación",
        html: `Tu código de verificación es: <strong>${verificationCode}</strong>`
      });
      console.log('Verification email sent');
    } catch (emailError) {
      console.error('Email sending error:', emailError);
      conn.release();
      return res.status(500).json({ 
        success: false, 
        error: 'Error al enviar el correo de verificación',
        details: process.env.NODE_ENV === 'development' ? emailError.message : null
      });
    }

    // Create temp token
    const hashedPassword = await bcrypt.hash(password, 10);
    const tempToken = jwt.sign({
      username,
      email: encryptedEmail,
      password: hashedPassword,
      verificationCode
    }, JWT_SECRET, { expiresIn: '15m' });

    conn.release();
    console.log('Registration successful, temp token generated');
    
    return res.json({ 
      success: true, 
      tempToken,
      debugCode: process.env.NODE_ENV === 'development' ? verificationCode : null
    });

  } catch (error) {
    console.error('Registration error:', {
      message: error.message,
      stack: error.stack,
      inputData: { username, email }
    });
    return res.status(500).json({ 
      success: false, 
      error: 'Error en el servidor',
      details: process.env.NODE_ENV === 'development' ? error.message : null
    });
  }
});

// Verificación de Registro (único endpoint)
app.post('/verify-registration', [
  body('code').isLength({ min: 6, max: 6 }).isNumeric(),
  body('tempToken').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { code, tempToken } = req.body;

  try {
    const decoded = jwt.verify(tempToken, JWT_SECRET);
    
    // Verificar el código
    if (code !== decoded.verificationCode) {
      return res.status(401).json({ 
        success: false, 
        error: 'Código de verificación incorrecto' 
      });
    }

    // Insertar usuario en la base de datos
   const [result] = await pool.query(
    'INSERT INTO usuarios (nombre, correo, contraseña, rol, estado) VALUES (?, ?, ?, ?, ?)',
    [decoded.username, decoded.email, decoded.password, 'user', 'activo']
  );

    // Crear token de acceso
    const accessToken = jwt.sign(
      { 
        userId: result.insertId, 
        email: decryptData(decoded.email),
        role: 'user' 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ 
      success: true,
      message: 'Registro completado exitosamente',
      token: accessToken,
      user: {
        id: result.insertId,
        name: decoded.username,
        email: decryptData(decoded.email),
        role: 'user'
      }
    });

  } catch (error) {
    console.error('Error en verificación:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false,
        error: 'Token inválido o expirado' 
      });
    }
    
    res.status(500).json({ 
      success: false,
      error: 'Error en el servidor',
      details: process.env.NODE_ENV === 'development' ? error.message : null
    });
  }
});

// Inicio de Sesión 
app.post('/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  const cleanEmail = email.toLowerCase().trim();

  try {
    // 1. Encriptar email para búsqueda
    const encryptedEmail = encryptData(cleanEmail);
    console.log(`Buscando: ${cleanEmail} → ${encryptedEmail}`);

    // 2. Buscar usuario incluyendo el estado
    const [users] = await pool.query(
      'SELECT id_user, nombre, correo, contraseña, rol, estado FROM usuarios WHERE correo = ?', 
      [encryptedEmail]
    );

    if (users.length === 0) {
      return res.status(401).json({ success: false, error: 'Credenciales inválidas' });
    }

    const user = users[0];
    
    // 3. Verificar si el usuario está activo
    if (user.estado !== 'activo') {
      return res.status(403).json({ 
        success: false, 
        error: 'Cuenta inactiva. Contacte al administrador.' 
      });
    }

    console.log(`Usuario encontrado: ${user.nombre}`);
    console.log(`Hash almacenado: ${user.contraseña}`);

    // 4. Comparación robusta de contraseñas
    let validPassword = false;
    try {
      validPassword = await bcrypt.compare(password, user.contraseña);
      console.log(`Resultado bcrypt.compare: ${validPassword}`);
      
      // Si falla, verificar si la contraseña fue almacenada en texto plano (solo para migración)
      if (!validPassword && !user.contraseña.startsWith('$2a$')) {
        console.log('Posible contraseña en texto plano');
        validPassword = (password === user.contraseña);
        
        // Si coincide, actualizar a hash bcrypt
        if (validPassword) {
          const newHash = await bcrypt.hash(password, 10);
          await pool.query(
            'UPDATE usuarios SET contraseña = ? WHERE id_user = ?',
            [newHash, user.id_user]
          );
          console.log('Contraseña migrada a bcrypt');
        }
      }
    } catch (hashError) {
      console.error('Error al comparar contraseñas:', hashError);
      return res.status(500).json({ success: false, error: 'Error interno' });
    }

    if (!validPassword) {
      return res.status(401).json({ 
        success: false, 
        error: 'Contraseña incorrecta',
        debug: process.env.NODE_ENV === 'development' ? {
          input: password,
          stored: user.contraseña,
          isBcrypt: user.contraseña.startsWith('$2a$')
        } : null
      });
    }

    // 5. Generar token JWT
    const decryptedEmail = decryptData(user.correo);
    const accessToken = jwt.sign(
      { userId: user.id_user, email: decryptedEmail, role: user.rol },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token: accessToken,
      user: {
        id: user.id_user,
        name: user.nombre,
        email: decryptedEmail,
        role: user.rol
      }
    });

  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ 
      success: false,
      error: 'Error interno del servidor',
      details: process.env.NODE_ENV === 'development' ? error.message : null
    });
  }
});

// Ruta protegida
app.get('/protected', authenticateJWT, (req, res) => {
  res.json({
    message: 'Esta es una ruta protegida',
    user: req.user
  });
});

// Obtener usuarios con paginación
app.get('/api/users', authenticateJWT, checkRole('Adm'), async (req, res) => {
    let conn;
    try {
        const { page = 1, limit = 10, search = '', status = '' } = req.query;
        const offset = (page - 1) * limit;
        
        conn = await pool.getConnection();
        
        let query = 'SELECT id_user, nombre, correo, contraseña, rol, estado FROM usuarios';
        let countQuery = 'SELECT COUNT(*) as total FROM usuarios';
        const params = [];
        const whereClauses = [];
        
        if (search) {
            whereClauses.push('(nombre LIKE ? OR correo LIKE ?)');
            params.push(`%${search}%`, `%${search}%`);
        }
        
        if (status) {
            whereClauses.push('estado = ?');
            params.push(status);
        }
        
        if (whereClauses.length > 0) {
            const whereStatement = ' WHERE ' + whereClauses.join(' AND ');
            query += whereStatement;
            countQuery += whereStatement;
        }
        
        query += ' LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));
        
        const [users] = await conn.query(query, params);
        const [[{ total }]] = await conn.query(countQuery, params.slice(0, -2));
        
        // Procesar usuarios para desencriptar
        const processedUsers = users.map(user => {
            try {
                return {
                    ...user,
                    correo: decryptData(user.correo) || user.correo, // Mostrar desencriptado o original si falla
                    contraseña: user.contraseña // Mostrar contraseña directamente (sin encriptar)
                };
            } catch (error) {
                console.error('Error desencriptando datos:', error);
                return user; // Devolver datos originales si hay error
            }
        });
        
        res.json({ 
            users: processedUsers, 
            total,
            page: parseInt(page),
            limit: parseInt(limit),
            totalPages: Math.ceil(total / limit)
        });
        
    } catch (error) {
        console.error('Error en /api/users:', error);
        res.status(500).json({ 
            error: 'Error al obtener usuarios',
            details: process.env.NODE_ENV === 'development' ? error.message : null
        });
    } finally {
        if (conn) conn.release();
    }
});

// Actualizar usuario (versión corregida)
app.put('/api/users/:id', authenticateJWT, checkRole('Adm'), [
    body('nombre').trim().notEmpty().withMessage('Nombre es requerido'),
    body('correo').isEmail().withMessage('Correo electrónico inválido'),
    body('rol').isIn(['user', 'Adm']).withMessage('Rol inválido'),
    body('estado').isIn(['activo', 'inactivo']).withMessage('Estado inválido')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false,
            errors: errors.array(),
            message: 'Validación fallida'
        });
    }
    
    try {
        const { id } = req.params;
        const { nombre, correo, rol, estado } = req.body;
        
        // Encriptar el correo antes de guardar
        const encryptedEmail = encryptData(correo);
        
        const [result] = await pool.query(
            'UPDATE usuarios SET nombre = ?, correo = ?, rol = ?, estado = ? WHERE id_user = ?',
            [nombre, encryptedEmail, rol, estado, id]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ 
                success: false,
                error: 'Usuario no encontrado' 
            });
        }
        
        res.json({ 
            success: true,
            message: 'Usuario actualizado correctamente'
        });
    } catch (error) {
        console.error('Error al actualizar usuario:', error);
        res.status(500).json({ 
            success: false,
            error: 'Error al actualizar usuario',
            details: process.env.NODE_ENV === 'development' ? error.message : null
        });
    }
});

// Desactivar usuario
app.put('/api/users/:id/deactivate', authenticateJWT, checkRole('Adm'), async (req, res) => {
    try {
        const { id } = req.params;
        
        await pool.query(
            'UPDATE usuarios SET estado = "inactivo" WHERE id_user = ?',
            [id]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error al desactivar usuario:', error);
        res.status(500).json({ error: 'Error al desactivar usuario' });
    }
});

// Activar usuario
app.put('/api/users/:id/activate', authenticateJWT, checkRole('Adm'), async (req, res) => {
    try {
        const { id } = req.params;
        
        await pool.query(
            'UPDATE usuarios SET estado = "activo" WHERE id_user = ?',
            [id]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error al activar usuario:', error);
        res.status(500).json({ error: 'Error al activar usuario' });
    }
});

app.get('/api/users/:id', authenticateJWT, checkRole('Adm'), async (req, res) => {
    try {
        const { id } = req.params;
        
        const [users] = await pool.query(
            'SELECT id_user, nombre, correo, rol, estado FROM usuarios WHERE id_user = ?', 
            [id]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        
        const user = users[0];
        
        // Desencriptar el correo
        try {
            user.correo = decryptData(user.correo);
        } catch (error) {
            console.error('Error desencriptando correo:', error);
            // Mantener el correo encriptado si falla la desencriptación
        }
        
        res.json(user);
        
    } catch (error) {
        console.error('Error al obtener usuario:', error);
        res.status(500).json({ 
            error: 'Error al obtener usuario',
            details: process.env.NODE_ENV === 'development' ? error.message : null
        });
    }
});

//API
// Carreras
app.get('/api/carreras', async (req, res) => {
  try {
    const [carreras] = await pool.query('SELECT id_carrera AS id, nombre FROM carreras ORDER BY nombre');
    res.json(carreras);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener carreras' });
  }
});

// Agrega esto junto con tus otras rutas de carreras
app.post('/api/carreras', [
  body('nombre').trim().notEmpty().withMessage('El nombre es requerido')
    .isLength({ max: 100 }).withMessage('Máximo 100 caracteres')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { nombre } = req.body;

  try {
    // Verificar si la carrera ya existe
    const [existente] = await pool.query(
      'SELECT id_carrera FROM carreras WHERE nombre = ?', 
      [nombre]
    );
    
    if (existente.length > 0) {
      return res.status(409).json({ error: 'Esta carrera ya existe' });
    }

    const [result] = await pool.query(
      'INSERT INTO carreras (nombre) VALUES (?)',
      [nombre]
    );
    
    res.status(201).json({ 
      success: true,
      id: result.insertId,
      nombre
    });
    
  } catch (error) {
    console.error('Error en POST /api/carreras:', error);
    res.status(500).json({ 
      error: 'Error al crear carrera',
      details: process.env.NODE_ENV === 'development' ? error.message : null
    });
  }
});

app.get('/api/carreras/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [carreras] = await pool.query('SELECT * FROM carreras WHERE id_carrera = ?', [id]);
    if (carreras.length === 0) {
      return res.status(404).json({ error: 'Carrera no encontrada' });
    }
    res.json(carreras[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener carrera' });
  }
});

app.put('/api/carreras/:id', [
  body('nombre').trim().notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { id } = req.params;
  const { nombre } = req.body;

  try {
    await pool.query(
      'UPDATE carreras SET nombre = ? WHERE id_carrera = ?',
      [nombre, id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar carrera' });
  }
});

// Eliminar carrera
app.delete('/api/carreras/:id', async (req, res) => {
  const { id } = req.params;
  let conn;
  
  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();

    // 1. Eliminar temas relacionados
    await conn.query(`
      DELETE t FROM temas t
      JOIN cuatrimestres c ON t.id_cuatri = c.id_cuatri
      WHERE c.id_carrera = ?
    `, [id]);

    // 2. Eliminar cuatrimestres
    await conn.query('DELETE FROM cuatrimestres WHERE id_carrera = ?', [id]);

    // 3. Eliminar la carrera
    const [result] = await conn.query('DELETE FROM carreras WHERE id_carrera = ?', [id]);

    if (result.affectedRows === 0) {
      await conn.rollback();
      return res.status(404).json({ error: 'Carrera no encontrada' });
    }

    await conn.commit();
    res.json({ 
      success: true, 
      message: 'Carrera y datos relacionados eliminados correctamente' 
    });

  } catch (error) {
    if (conn) await conn.rollback();
    console.error('Error al eliminar carrera:', error);
    res.status(500).json({ 
      error: 'Error al eliminar carrera',
      details: process.env.NODE_ENV === 'development' ? error.message : null
    });
  } finally {
    if (conn) conn.release();
  }
});


// Cuatrimestres
app.get('/api/cuatrimestres', async (req, res) => {
  let { carrera } = req.query;

  carrera = parseInt(carrera?.toString().replace(/:.*/, ''));
  if (isNaN(carrera)) {
    return res.status(400).json({ 
      error: 'ID de carrera debe ser un número válido',
      received: req.query.carrera
    });
  }

  try {
    console.log("Consultando cuatrimestres para carrera:", carrera);

    const [cuatrimestres] = await pool.query(
      'SELECT id_cuatri AS id, numero FROM cuatrimestres WHERE id_carrera = ? ORDER BY numero',
      [carrera]
    );

    res.json(cuatrimestres);
  } catch (error) {
    console.error('Error en GET /api/cuatrimestres:', error);
    res.status(500).json({ 
      error: 'Error al obtener cuatrimestres',
      details: error.message // para depuración en desarrollo
    });
  }
});

app.get('/api/cuatrimestres/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [cuatrimestres] = await pool.query(`
      SELECT c.*, ca.nombre as carrera_nombre 
      FROM cuatrimestres c
      JOIN carreras ca ON c.id_carrera = ca.id_carrera
      WHERE c.id_cuatri = ?
    `, [id]);
    
    if (cuatrimestres.length === 0) {
      return res.status(404).json({ error: 'Cuatrimestre no encontrado' });
    }
    res.json(cuatrimestres[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener cuatrimestre' });
  }
});

app.put('/api/cuatrimestres/:id', [
  body('numero').isInt({ min: 1, max: 11 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { id } = req.params;
  const { numero } = req.body;

  try {
    await pool.query(
      'UPDATE cuatrimestres SET numero = ? WHERE id_cuatri = ?',
      [numero, id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar cuatrimestre' });
  }
});

// Eliminar cuatrimestre
app.delete('/api/cuatrimestres/:id', async (req, res) => {
  const { id } = req.params;
  let conn;
  
  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();

    // 1. Eliminar temas relacionados
    await conn.query('DELETE FROM temas WHERE id_cuatri = ?', [id]);

    // 2. Eliminar el cuatrimestre
    const [result] = await conn.query('DELETE FROM cuatrimestres WHERE id_cuatri = ?', [id]);

    if (result.affectedRows === 0) {
      await conn.rollback();
      return res.status(404).json({ error: 'Cuatrimestre no encontrado' });
    }

    await conn.commit();
    res.json({ 
      success: true, 
      message: 'Cuatrimestre y temas eliminados correctamente' 
    });

  } catch (error) {
    if (conn) await conn.rollback();
    console.error('Error al eliminar cuatrimestre:', error);
    res.status(500).json({ 
      error: 'Error al eliminar cuatrimestre',
      details: process.env.NODE_ENV === 'development' ? error.message : null
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/cuatrimestres', [
  body('numero').isInt({ min: 1, max: 11 }).withMessage('Número de cuatrimestre inválido (1-11)'),
  body('id_carrera').isInt().withMessage('ID de carrera inválido')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { numero, id_carrera } = req.body;

  try {
    // Verificar que exista la carrera
    const [carrera] = await pool.query('SELECT id_carrera FROM carreras WHERE id_carrera = ?', [id_carrera]);
    if (carrera.length === 0) return res.status(404).json({ error: 'Carrera no encontrada' });

    const [result] = await pool.query(
      'INSERT INTO cuatrimestres (numero, id_carrera) VALUES (?, ?)',
      [numero, id_carrera]
    );
    
    res.status(201).json({
      success: true,
      id: result.insertId,
      numero,
      id_carrera
    });
  } catch (error) {
    console.error('Error al crear cuatrimestre:', error);
    res.status(500).json({ error: 'Error al crear cuatrimestre' });
  }
});

//Parcial
app.get('/api/parciales', async (req, res) => {
  try {
    // Devolvemos siempre los 3 parciales básicos
    const parciales = [
      { id: 1, numero: 1 },
      { id: 2, numero: 2 },
      { id: 3, numero: 3 }
    ];
    res.json(parciales);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener parciales' });
  }
});

// Temas
app.get('/api/temas', async (req, res) => {
  const { carrera } = req.query;
  
  console.log('Recibida petición a /api/temas'); // Debug
  
  try {
    let query = `
      SELECT 
        t.id_tema as id,
        t.nombre,
        t.descripcion,
        t.materia,
        t.url,
        t.id_par,
        t.id_cuatri,
        p.numero as parcial_numero,
        c.numero as cuatrimestre_numero,
        ca.nombre as carrera_nombre,
        ca.id_carrera
      FROM temas t
      JOIN parciales p ON t.id_par = p.id_par
      JOIN cuatrimestres c ON t.id_cuatri = c.id_cuatri
      JOIN carreras ca ON c.id_carrera = ca.id_carrera
    `;
    
    const params = [];
    
    if (carrera) {
      query += ' WHERE ca.id_carrera = ?';
      params.push(carrera);
    }
    
    query += ' ORDER BY ca.nombre, c.numero, p.numero, t.nombre';
    
    console.log('Ejecutando consulta:', query); // Debug
    console.log('Con parámetros:', params); // Debug
    
    const [temas] = await pool.query(query, params);
    console.log('Consulta exitosa. Temas encontrados:', temas.length); // Debug
    
    res.json(temas);
  } catch (error) {
    console.error('ERROR DETALLADO:', {
      message: error.message,
      sqlMessage: error.sqlMessage,
      sql: error.sql,
      stack: error.stack,
      code: error.code,
      errno: error.errno
    });
    
    res.status(500).json({ 
      error: 'Error al obtener temas',
      details: process.env.NODE_ENV === 'development' ? {
        message: error.message,
        sqlMessage: error.sqlMessage,
        sql: error.sql
      } : null
    });
  }
});

app.put('/api/temas/:id', [
  body('nombre').trim().notEmpty(),
  body('descripcion').trim().notEmpty(),
  body('materia').trim().notEmpty(),
  body('url').isURL(),
  body('id_par').isInt(),
  body('id_cuatri').isInt()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false,
      errors: errors.array() 
    });
  }

  const { id } = req.params;
  const { nombre, descripcion, materia, url, id_par, id_cuatri } = req.body;

  try {
    // Verificar que existan las relaciones
    const [parcial] = await pool.query('SELECT id_par FROM parciales WHERE id_par = ?', [id_par]);
    if (parcial.length === 0) {
      return res.status(404).json({ error: 'Parcial no encontrado' });
    }

    const [cuatrimestre] = await pool.query('SELECT id_cuatri FROM cuatrimestres WHERE id_cuatri = ?', [id_cuatri]);
    if (cuatrimestre.length === 0) {
      return res.status(404).json({ error: 'Cuatrimestre no encontrado' });
    }

    const [result] = await pool.query(
      `UPDATE temas SET 
        nombre = ?, 
        descripcion = ?, 
        materia = ?, 
        url = ?,
        id_par = ?,
        id_cuatri = ?
      WHERE id_tema = ?`,
      [nombre, descripcion, materia, url, id_par, id_cuatri, id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Tema no encontrado' });
    }
    
    res.json({ 
      success: true,
      message: 'Tema actualizado correctamente'
    });
  } catch (error) {
    console.error('Error al actualizar tema:', {
      message: error.message,
      sqlMessage: error.sqlMessage,
      sql: error.sql,
      stack: error.stack
    });
    res.status(500).json({ 
      error: 'Error al actualizar tema',
      details: process.env.NODE_ENV === 'development' ? {
        message: error.message,
        sqlMessage: error.sqlMessage,
        sql: error.sql
      } : null
    });
  }
});

app.delete('/api/temas/:id', async (req, res) => {
  const { id } = req.params;
  
  if (isNaN(id)) {
    return res.status(400).json({ 
      error: 'ID de tema inválido',
      details: 'El ID debe ser un número'
    });
  }

  try {
    const [result] = await pool.query('DELETE FROM temas WHERE id_tema = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        error: 'Tema no encontrado',
        details: `No se encontró un tema con ID ${id}`
      });
    }
    
    res.json({ 
      success: true,
      message: 'Tema eliminado correctamente'
    });
  } catch (error) {
    console.error('Error al eliminar tema:', error);
    res.status(500).json({ 
      error: 'Error al eliminar tema',
      details: process.env.NODE_ENV === 'development' ? error.message : null
    });
  }
});

app.post('/api/temas', [
  body('nombre').trim().notEmpty().withMessage('El nombre es requerido'),
  body('descripcion').trim().notEmpty().withMessage('La descripción es requerida'),
  body('materia').trim().notEmpty().withMessage('La materia es requerida'),
  body('url').isURL().withMessage('URL inválida'),
  body('id_par').isInt().withMessage('ID de parcial inválido'),
  body('id_cuatri').isInt().withMessage('ID de cuatrimestre inválido') // Añade esta validación
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false,
      error: 'Validación fallida',
      errors: errors.array() 
    });
  }

  const { nombre, descripcion, materia, url, id_par, id_cuatri } = req.body;

  try {
    // Verificar que exista el parcial
    const [parcial] = await pool.query('SELECT id_par FROM parciales WHERE id_par = ?', [id_par]);
    if (parcial.length === 0) {
      return res.status(404).json({ 
        success: false,
        error: 'Parcial no encontrado' 
      });
    }

    // Verificar que exista el cuatrimestre
    const [cuatrimestre] = await pool.query('SELECT id_cuatri FROM cuatrimestres WHERE id_cuatri = ?', [id_cuatri]);
    if (cuatrimestre.length === 0) {
      return res.status(404).json({ 
        success: false,
        error: 'Cuatrimestre no encontrado' 
      });
    }

    const [result] = await pool.query(
      'INSERT INTO temas (nombre, descripcion, materia, url, id_par, id_cuatri) VALUES (?, ?, ?, ?, ?, ?)',
      [nombre, descripcion, materia, url, id_par, id_cuatri] // Añade id_cuatri aquí
    );
    
    res.status(201).json({
      success: true,
      id: result.insertId,
      nombre,
      descripcion,
      materia,
      url,
      id_par,
      id_cuatri // Devuelve también el id_cuatri para confirmación
    });
  } catch (error) {
    console.error('Error al crear tema:', error);
    res.status(500).json({ 
      success: false,
      error: 'Error al crear tema',
      details: process.env.NODE_ENV === 'development' ? error.message : null
    });
  }
});

// API para obtener estructura completa del catálogo
app.get('/api/catalogo/completo', async (req, res) => {
  try {
    // Obtener todas las carreras
    const [carreras] = await pool.query('SELECT id_carrera AS id, nombre FROM carreras ORDER BY nombre');
    
    // Para cada carrera, obtener sus cuatrimestres
    for (const carrera of carreras) {
      const [cuatrimestres] = await pool.query(
        'SELECT id_cuatri AS id, numero FROM cuatrimestres WHERE id_carrera = ? ORDER BY numero',
        [carrera.id]
      );
      
      carrera.cuatrimestres = cuatrimestres;
      
      // Para cada cuatrimestre, obtener sus temas agrupados por parcial
      for (const cuatrimestre of carrera.cuatrimestres) {
        const [temas] = await pool.query(`
          SELECT 
            t.id_tema AS id,
            t.nombre,
            t.materia,
            t.descripcion,
            t.url,
            p.numero AS parcial
          FROM temas t
          JOIN parciales p ON t.id_par = p.id_par
          WHERE t.id_cuatri = ?
          ORDER BY p.numero, t.nombre
        `, [cuatrimestre.id]);
        
        // Agrupar por parcial
        cuatrimestre.parciales = {
          1: temas.filter(t => t.parcial === 1),
          2: temas.filter(t => t.parcial === 2),
          3: temas.filter(t => t.parcial === 3)
        };
      }
    }
    
    res.json(carreras);
  } catch (error) {
    console.error('Error al obtener catálogo completo:', error);
    res.status(500).json({ error: 'Error al obtener catálogo completo' });
  }
});

// API para búsqueda avanzada
app.get('/api/catalogo/buscar', async (req, res) => {
  try {
    const { q, carrera, cuatrimestre, parcial, materia } = req.query;
    
    let query = `
      SELECT 
        t.id_tema AS id,
        t.nombre,
        t.descripcion,
        t.materia,
        t.url,
        p.numero AS parcial_numero,
        c.numero AS cuatrimestre_numero,
        ca.nombre AS carrera_nombre,
        ca.id_carrera AS carrera_id,
        c.id_cuatri AS cuatrimestre_id
      FROM temas t
      JOIN parciales p ON t.id_par = p.id_par
      JOIN cuatrimestres c ON t.id_cuatri = c.id_cuatri
      JOIN carreras ca ON c.id_carrera = ca.id_carrera
      WHERE 1=1
    `;
    
    const params = [];
    
    if (q) {
      query += ' AND (t.nombre LIKE ? OR t.descripcion LIKE ? OR t.materia LIKE ?)';
      params.push(`%${q}%`, `%${q}%`, `%${q}%`);
    }
    
    if (carrera) {
      query += ' AND ca.id_carrera = ?';
      params.push(carrera);
    }
    
    if (cuatrimestre) {
      query += ' AND c.id_cuatri = ?';
      params.push(cuatrimestre);
    }
    
    if (parcial) {
      query += ' AND p.id_par = ?';
      params.push(parcial);
    }
    
    if (materia) {
      query += ' AND t.materia LIKE ?';
      params.push(`%${materia}%`);
    }
    
    query += ' ORDER BY ca.nombre, c.numero, p.numero, t.nombre';
    
    const [temas] = await pool.query(query, params);
    
    res.json({
      results: temas
    });
  } catch (error) {
    console.error('Error en búsqueda de catálogo:', error);
    res.status(500).json({ error: 'Error en búsqueda de catálogo' });
  }
});

// API para obtener temas por criterios
app.get('/api/temas/filtrados', async (req, res) => {
  try {
    const { carrera, cuatrimestre, parcial } = req.query;
    
    if (!carrera || !cuatrimestre || !parcial) {
      return res.status(400).json({ error: 'Se requieren carrera, cuatrimestre y parcial' });
    }
    
    const query = `
      SELECT 
        t.id_tema,
        t.nombre,
        t.descripcion,
        t.materia,
        t.url,
        p.numero AS parcial,
        c.numero AS cuatrimestre,
        ca.nombre AS carrera
      FROM temas t
      JOIN parciales p ON t.id_par = p.id_par
      JOIN cuatrimestres c ON t.id_cuatri = c.id_cuatri
      JOIN carreras ca ON c.id_carrera = ca.id_carrera
      WHERE ca.id_carrera = ? AND c.id_cuatri = ? AND p.id_par = ?
      ORDER BY t.nombre
    `;
    
    const [temas] = await pool.query(query, [carrera, cuatrimestre, parcial]);
    
    res.json(temas);
  } catch (error) {
    console.error('Error al obtener temas filtrados:', error);
    res.status(500).json({ error: 'Error al obtener temas' });
  }
});

// Ruta para solicitar recuperación de contraseña
app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        // Validación básica
        if (!email || !email.includes('@')) {
            return res.status(400).json({ 
                success: false,
                error: 'Por favor ingrese un correo electrónico válido'
            });
        }
        
        // Buscar usuario por email (encriptado)
        const encryptedEmail = encryptData(email.toLowerCase().trim());
        const [users] = await pool.query(
            'SELECT id_user, nombre FROM usuarios WHERE correo = ?', 
            [encryptedEmail]
        );
        
        // Siempre mostrar mismo mensaje por seguridad
        const responseMessage = 'Si el correo existe, recibirás un código de verificación';
        
        if (users.length === 0) {
            return res.status(200).json({ 
                success: true,
                message: responseMessage
            });
        }
        
        const user = users[0];
        const verificationCode = generateVerificationCode();
        
        // Crear token temporal (15 minutos de validez)
        const tempToken = jwt.sign(
            {
                userId: user.id_user,
                email: encryptedEmail,
                code: verificationCode,
                action: 'password_reset'
            },
            JWT_SECRET, // Usando el mismo secreto que para JWT
            { expiresIn: '15m' }
        );
        
        // Enviar correo con el código
        const mailOptions = {
            from: '"Soporte del Sistema" <dinocraft617@gmail.com>',
            to: email,
            subject: 'Código para restablecer contraseña',
            html: `
                <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                    <h2 style="color: #3498db;">Restablecer contraseña</h2>
                    <p>Hola ${user.nombre},</p>
                    <p>Usa este código para restablecer tu contraseña:</p>
                    <h3 style="margin: 20px 0; font-size: 24px;">${verificationCode}</h3>
                    <p>El código expira en 15 minutos.</p>
                </div>
            `
        };
        
        await transporter.sendMail(mailOptions);
        
        res.json({ 
            success: true,
            message: responseMessage,
            tempToken
        });
        
    } catch (error) {
        console.error('Error en forgot-password:', error);
        res.status(500).json({ 
            success: false,
            error: 'Error al procesar la solicitud'
        });
    }
});

// Ruta para verificar el código y cambiar contraseña
app.post('/reset-password-with-code', [
    body('code').isLength({ min: 6, max: 6 }).isNumeric(),
    body('tempToken').notEmpty(),
    body('newPassword').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false,
            errors: errors.array() 
        });
    }

    const { code, tempToken, newPassword } = req.body;

    try {
        // Verificar token JWT
        const decoded = jwt.verify(tempToken, JWT_SECRET);
        
        // Validar que sea para recuperación y el código coincida
        if (decoded.action !== 'password_reset' || decoded.code !== code) {
            return res.status(400).json({ 
                success: false,
                error: 'Código inválido o expirado'
            });
        }
        
        // Hashear nueva contraseña
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Actualizar contraseña en la base de datos
        await pool.query(
            'UPDATE usuarios SET contraseña = ? WHERE id_user = ?',
            [hashedPassword, decoded.userId]
        );
        
        res.json({ 
            success: true,
            message: 'Contraseña actualizada correctamente'
        });
        
    } catch (error) {
        console.error('Error en reset-password-with-code:', error);
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(400).json({ 
                success: false,
                error: 'Token inválido o expirado'
            });
        }
        
        res.status(500).json({ 
            success: false,
            error: 'Error al cambiar la contraseña'
        });
    }
});

// Middleware para verificar rol de administrador
function checkRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ error: 'Acceso denegado' });
        }
        next();
    };
}


// Manejo de errores
app.use((err, req, res, next) => {
  console.error('Error no manejado:', err);
  res.status(500).json({
    success: false,
    error: 'Error interno del servidor',
    details: err.message
  });
});

// Iniciar el servidor HTTP y verificar la conexión a la BD
const server = http.createServer(app);

server.listen(PORT, () => {
  console.log(`🚀 Servidor HTTP corriendo en http://localhost:${PORT}`);
  
  // 1. Intentar obtener una conexión del pool
  pool.getConnection()
    .then(conn => {
      // 2. Si tiene éxito, liberar la conexión y confirmar
      conn.release();
      console.log('✅ Conexión con la base de datos establecida correctamente.');
    })
    .catch(err => {
      // 3. Si falla, mostrar el error
      console.error('❌ Error fatal: Fallo al conectar con la base de datos:', err.message);
      console.log('El servidor Express está corriendo, pero no podrá manejar peticiones a la BD.');
      // Opcional: process.exit(1); para detener la aplicación si la BD es crítica.
    });

});

