// Importamos las librerías necesarias
require('dotenv').config(); // Carga las variables del archivo .env
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Creamos la aplicación Express
const app = express();

// RUTA PING (Para evitar que Render se duerma)
// Sin seguridad, sin rate-limit, sin cors estricto. Solo responder rápido.
app.get('/ping', (req, res) => {
    console.log('Ping recibido!'); // Opcional: para verlo en los logs
    res.send('pong');
});

// --- SEGURIDAD 1: HELMET ---
app.use(helmet());

// --- IMPORTANTE PARA LA NUBE (Render/Vercel) ---
// Esto permite que el rate-limit funcione bien detrás del proxy de la nube
app.set('trust proxy', 1);

// --- SEGURIDAD 2: LIMITADOR GENERAL ---
const generalLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minutos
    max: 100, // Máximo 100 peticiones por IP
    message: 'Demasiadas peticiones, intenta más tarde.',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(generalLimiter);

// --- SEGURIDAD 3: LIMITADOR SOLO PARA LOGIN ---
const loginLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minuto
    max: 5, // Solo 5 intentos fallidos
    message: { message: 'Demasiados intentos de login. Espera 1 minuto.' }
});

// 👇 APLICAR EL LIMITADOR AL LOGIN
app.use('/api/login', loginLimiter);

// Middlewares: funciones que se ejecutan en cada petición

// index.js

// Lista blanca de orígenes permitidos
const whitelist = [
  'http://localhost:5173', // Para cuando desarrollas en casa
  'http://localhost:3000', // Por si acaso
  'http://192.168.1.14:3000', // Para probar desde tu celular en local
  'https://kiga-front.vercel.app' // 👈 ¡TU NUEVA URL DE VERCEL! (Sin barra al final)
];

const corsOptions = {
  origin: function (origin, callback) {
    // Permitir peticiones sin origen (como Postman/Mobile apps) o si está en la lista
    if (!origin || whitelist.indexOf(origin) !== -1) {
      callback(null, true)
    } else {
      callback(new Error('Bloqueado por CORS: Tu origen no está autorizado'))
    }
  },
  credentials: true 
};

app.use(cors(corsOptions));
app.use(cors()); // Permite peticiones de otros orígenes (nuestro frontend)
app.use(express.json({ limit: '50mb' })); // Permite al servidor entender JSON y aumenta el límite para los archivos

// Configuración de la conexión a la base de datos
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: 4000, // Asegúrate que sea el 4000
    
    //ESTO ES LO QUE TE FALTA
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    },
    // SIN ESTO, TiDB TE BLOQUEA 

    // Configuración extra para evitar que se corte la conexión:
    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0,
    enableKeepAlive: true
}).promise(); // Usamos .promise() para poder usar async/await con la DB

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    console.log("Login recibido:", req.body); // << esto siempre al inicio

    if (!username || !password) {
        return res.status(400).json({ error: 'Username y password son requeridos' });
    }

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Usuario no encontrado' });
        }

        const user = rows[0];

        // Verificar contraseña
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Contraseña incorrecta' });
        }

        // Generar JWT
        const token = jwt.sign(
            {
                id: user.id,
                username: user.username,
                nombre: user.nombre,
                apellido: user.apellido,
                role: user.role,
                permissions: user.permissions
            },
            process.env.JWT_SECRET,
            { expiresIn: '10h' }
        );

        console.log("Usuario encontrado:", user.username);
        console.log("Token generado:", token);

        res.json({
            mensaje: 'Login exitoso',
            user: {
                id: user.id,
                username: user.username,
                nombre: user.nombre,
                apellido: user.apellido,
                role: user.role,
                permissions: user.permissions
            },
            accessToken: token // <- si tu frontend espera accessToken
        });

    } catch (err) {
        console.error("Error en login:", err);
        res.status(500).json({ error: 'Error en el servidor', detalle: err.message });
    }
});




const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // formato: "Bearer TOKEN"

    if (!token) return res.status(401).json({ error: 'Token no proporcionado' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // guardamos la info del usuario en req.user
        next(); // pasamos a la siguiente función
    } catch (err) {
        res.status(403).json({ error: 'Token inválido o expirado' });
    }
};


// A partir de aquí, todas las rutas usarán el middleware de autenticación
app.use(authenticateToken);

// ----- PACIENTES -----
app.get('/api/patients', async (req, res) => {
  try {
    const [rows] = await db.execute(`
      SELECT 
        id_paciente,
        nombre,
        apellido,
        referencia,
        DATE_FORMAT(fecha_nacimiento, '%Y-%m-%d') AS fecha_nacimiento,
        dni,
        telefono,
        antecedentes
      FROM patients
    `);
    res.json(rows);
  } catch (error) {
    console.error('Error al obtener pacientes:', error);
    res.status(500).json({ error: 'Error al obtener pacientes' });
  }
});

app.post('/api/patients', async (req, res) => {
    try {
        const { Nombre, Apellido, Referencia, FechaNacimiento, DNI, Telefono, Antecedentes } = req.body;
        
        const [result] = await db.query(
            'INSERT INTO patients (nombre, apellido, referencia, fecha_nacimiento, dni, telefono, antecedentes) VALUES (?, ?, ?, ?, ?, ?, ?)', 
            [Nombre, Apellido, Referencia, FechaNacimiento || null, DNI || null, Telefono, Antecedentes]
        );

        const [[newUser]] = await db.query('SELECT * FROM patients WHERE id_paciente = ?', [result.insertId]);
        res.status(201).json(newUser);

    } catch (error) {
        // 1. IMPRIMIMOS EL ERROR PARA VER QUÉ CÓDIGO TRAE
        console.log("🔴 Error al guardar paciente. Código:", error.code, "| Número:", error.errno);

        // 2. VERIFICACIÓN DOBLE (Texto o Número 1062)
        // 1062 es el número universal de "Duplicate Entry" en MySQL
        if (error.code === 'ER_DUP_ENTRY' || error.errno === 1062) {
            return res.status(409).json({ 
                message: 'No se puede guardar: Ya existe un paciente con ese DNI.' 
            });
        }

        // Si no es duplicado, es otro error
        console.error("Error desconocido:", error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});
app.put('/api/patients/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { Nombre, Apellido, Referencia, FechaNacimiento, DNI, Telefono, Antecedentes } = req.body;

        // --- CORRECCIÓN ---
        // Si FechaNacimiento es un string vacío "" o undefined, enviamos NULL a la base de datos.
        // Si tiene dato, lo enviamos tal cual (MySQL acepta 'YYYY-MM-DD').
        const fechaNacimientoMySQL = (FechaNacimiento && FechaNacimiento !== '') ? FechaNacimiento : null;

        await db.query(
            'UPDATE patients SET nombre = ?, apellido = ?, referencia = ?, fecha_nacimiento = ?, dni = ?, telefono = ?, antecedentes = ? WHERE id_paciente = ?',
            [Nombre, Apellido, Referencia, fechaNacimientoMySQL, DNI, Telefono, Antecedentes, id]
        );

        const [[updatedUser]] = await db.query('SELECT * FROM patients WHERE id_paciente = ?', [id]);
        res.json(updatedUser);

    } catch (error) {
        console.error("Error al actualizar paciente:", error);
        res.status(500).json({ message: 'Error al actualizar paciente', error: error.message });
    }
});
app.delete('/api/patients/:id', async (req, res) => {
    await db.query('DELETE FROM patients WHERE id_paciente = ?', [req.params.id]);
    res.sendStatus(204);
});

// ----- ESPECIALIDADES -----

// GET: obtener todas las especialidades
app.get('/api/specialties', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM specialties');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener especialidades', error: error.message });
    }
});

// POST: crear una nueva especialidad
app.post('/api/specialties', async (req, res) => {
    try {
        const { id_especialidad, nombre, duracion, costo, color, activa, is_monthly } = req.body;
        await db.query(
            'INSERT INTO specialties (id_especialidad, nombre, duracion, costo, color, activa, is_monthly) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [id_especialidad, nombre, duracion, costo, color, activa || 1, is_monthly || 0]
        );
        const [[newSpecialty]] = await db.query('SELECT * FROM specialties WHERE id_especialidad = ?', [id_especialidad]);
        res.status(201).json(newSpecialty);
    } catch (error) {
        res.status(500).json({ message: 'Error al crear especialidad', error: error.message });
    }
});

// PUT: actualizar una especialidad existente
app.put('/api/specialties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, duracion, costo, color, activa, is_monthly } = req.body;
        await db.query(
            'UPDATE specialties SET nombre = ?, duracion = ?, costo = ?, color = ?, activa = ?, is_monthly = ? WHERE id_especialidad = ?',
            [nombre, duracion, costo, color, activa, is_monthly, id]
        );
        const [[updatedSpecialty]] = await db.query('SELECT * FROM specialties WHERE id_especialidad = ?', [id]);
        res.json(updatedSpecialty);
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar especialidad', error: error.message });
    }
});

// DELETE: eliminar una especialidad
app.delete('/api/specialties/:id', async (req, res) => {
    try {
        await db.query('DELETE FROM specialties WHERE id_especialidad = ?', [req.params.id]);
        res.sendStatus(204);
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar especialidad', error: error.message });
    }
});



// ----- TURNOS (APPOINTMENTS) -----
app.get('/api/appointments', async (req, res) => {
    const [rows] = await db.query('SELECT * FROM appointments');
    res.json(rows);
});

app.post('/api/appointments', async (req, res) => {
  try {
    // Función para formatear ISO string a formato MySQL local
    const formatearFechaLocal = (isoString) => {
      const fecha = new Date(isoString);

      const yyyy = fecha.getFullYear();
      const mm = String(fecha.getMonth() + 1).padStart(2, '0'); // Mes empieza en 0
      const dd = String(fecha.getDate()).padStart(2, '0');
      const hh = String(fecha.getHours()).padStart(2, '0');
      const min = String(fecha.getMinutes()).padStart(2, '0');
      const ss = String(fecha.getSeconds()).padStart(2, '0');

      return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
    };

    // Para turnos recurrentes
    if (Array.isArray(req.body)) {
      const newAppointments = req.body;
      const recurringId = Date.now().toString(); // Generar un ID para la serie

      for (const app of newAppointments) {
        const { id_paciente, id_especialidad, HoraInicio, HoraFin, Pago } = app;

        const horaInicioFormateada = formatearFechaLocal(HoraInicio);
        const horaFinFormateada = formatearFechaLocal(HoraFin);

        await db.query(
          'INSERT INTO appointments (id_paciente, id_especialidad, hora_inicio, hora_fin, pago, recurring_id) VALUES (?, ?, ?, ?, ?, ?)',
          [id_paciente, id_especialidad, horaInicioFormateada, horaFinFormateada, Pago, recurringId]
        );
      }

      res.status(201).json({ message: `${newAppointments.length} turnos creados` });

    } else {
      // Turno individual
      const { id_paciente, id_especialidad, HoraInicio, HoraFin, Pago, FechaPago, id_metodo_pago, CostoTurno } = req.body;

      const horaInicioFormateada = formatearFechaLocal(HoraInicio);
      const horaFinFormateada = formatearFechaLocal(HoraFin);
      const fechaPagoFormateada = FechaPago ? formatearFechaLocal(FechaPago) : null;

      const [result] = await db.query(
        'INSERT INTO appointments (id_paciente, id_especialidad, hora_inicio, hora_fin, pago, fecha_pago, id_metodo_pago, costo_turno) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [id_paciente, id_especialidad, horaInicioFormateada, horaFinFormateada, Pago, fechaPagoFormateada, id_metodo_pago, CostoTurno]
      );

      const [[newAppointment]] = await db.query(
        'SELECT * FROM appointments WHERE id_turno = ?',
        [result.insertId]
      );

      res.status(201).json(newAppointment);
    }

  } catch (error) {
    console.error('Error al crear turno:', error);
    res.status(500).json({ message: 'Error al crear turno', error: error.message });
  }
});

app.put('/api/appointments/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const {
      id_paciente,
      id_especialidad,
      HoraInicio,
      HoraFin,
      Pago,
      FechaPago,
      id_metodo_pago,
      CostoTurno
    } = req.body;

    // 🔧 Función para convertir ISO → formato MySQL local
    const formatearFechaLocal = (isoString) => {
      if (!isoString) return null;
      const fecha = new Date(isoString);

      // Convertir a horario local (de Argentina)
      const offset = fecha.getTimezoneOffset() * 60000;
      const local = new Date(fecha.getTime());

      const yyyy = local.getFullYear();
      const mm = String(local.getMonth() + 1).padStart(2, '0');
      const dd = String(local.getDate()).padStart(2, '0');
      const hh = String(local.getHours()).padStart(2, '0');
      const min = String(local.getMinutes()).padStart(2, '0');
      const ss = String(local.getSeconds()).padStart(2, '0');

      return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
    };

    // 🕒 Convertir los campos de fecha/hora
    const horaInicioMySQL = formatearFechaLocal(HoraInicio);
    const horaFinMySQL = formatearFechaLocal(HoraFin);
    const fechaPagoMySQL = FechaPago ? formatearFechaLocal(FechaPago) : null;

    // 💾 Actualizar el turno
    await db.query(
      `UPDATE appointments
       SET id_paciente=?, id_especialidad=?, hora_inicio=?, hora_fin=?, pago=?, fecha_pago=?, id_metodo_pago=?, costo_turno=?
       WHERE id_turno = ?`,
      [
        id_paciente,
        id_especialidad,
        horaInicioMySQL,
        horaFinMySQL,
        Pago,
        fechaPagoMySQL,
        id_metodo_pago,
        CostoTurno,
        id
      ]
    );

    // 📤 Devolver el turno actualizado
    const [[updatedAppointment]] = await db.query(
      'SELECT * FROM appointments WHERE id_turno = ?',
      [id]
    );

    res.json(updatedAppointment);
  } catch (error) {
    console.error('Error al actualizar turno:', error);
    res
      .status(500)
      .json({ message: 'Error al actualizar turno', error: error.message });
  }
});

app.delete('/api/appointments/:id', async (req, res) => {
    await db.query('DELETE FROM appointments WHERE id_turno = ?', [req.params.id]);
    res.sendStatus(204);
});
// Endpoints para eliminar turnos recurrentes
app.delete('/api/appointments/recurring/all/:recurringId', async (req, res) => {
    await db.query('DELETE FROM appointments WHERE recurring_id = ?', [req.params.recurringId]);
    res.sendStatus(204);
});
app.delete('/api/appointments/recurring/future', async (req, res) => {
    const { recurringId, cutoffDate } = req.query;
    
    // VALIDACIÓN (por si acaso)
    if (!recurringId || !cutoffDate) {
        return res.status(400).send('Faltan parámetros');
    }

    // --- LA SOLUCIÓN ---
    // Convertimos el string UTC que nos llega (...'T'...Z) a un objeto Date
    const fechaParaMySQL = new Date(cutoffDate); 
    // -------------------

    await db.query('DELETE FROM appointments WHERE recurring_id = ? AND hora_inicio >= ?', [recurringId, fechaParaMySQL]); // Le pasas el OBJETO DATE
    res.sendStatus(204);
});


// ----- HISTORIAL CLÍNICO -----

// GET: obtener todos los registros de historial
app.get('/api/history_entries', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM history_entries');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener historial clínico', error: error.message });
    }
});

// POST: crear un nuevo registro de historial
app.post('/api/history_entries', async (req, res) => {
  try {
    const { id_paciente, Fecha, Seguimiento } = req.body;

    // Convertir ISO → formato MySQL (solo fecha)
        const fechaFormateada = new Date(Fecha).toISOString().slice(0, 10);

    // Insertamos el nuevo historial
    const [result] = await db.query(
      'INSERT INTO history_entries (id_paciente, fecha, seguimiento) VALUES (?, ?, ?)',
      [id_paciente, fechaFormateada, Seguimiento]
    );

    // Obtenemos el registro recién creado usando el id autogenerado
    const [[newEntry]] = await db.query(
      'SELECT * FROM history_entries WHERE id_historial = ?',
      [result.insertId]
    );

    res.status(201).json(newEntry);
  } catch (error) {
    console.error('Error al crear historial clínico:', error);
    res.status(500).json({ message: 'Error al crear historial clínico', error: error.message });
  }
});


// PUT: actualizar un registro de historial existente
app.put('/api/history_entries/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { id_paciente, Fecha, Seguimiento } = req.body;

    // Convertir ISO → formato MySQL (solo fecha)
    const fechaFormateada = new Date(Fecha).toISOString().slice(0, 10);

    await db.query(
      'UPDATE history_entries SET id_paciente = ?, fecha = ?, seguimiento = ? WHERE id_historial = ?',
      [id_paciente, fechaFormateada, Seguimiento, id]
    );

    // Devolver el registro actualizado
    const [[updatedEntry]] = await db.query(
      'SELECT * FROM history_entries WHERE id_historial = ?',
      [id]
    );

    res.json(updatedEntry);
  } catch (error) {
    console.error('Error al actualizar historial clínico:', error);
    res.status(500).json({
      message: 'Error al actualizar historial clínico',
      error: error.message,
    });
  }
});


// DELETE: eliminar un registro de historial
app.delete('/api/history_entries/:id', async (req, res) => {
    try {
        await db.query('DELETE FROM history_entries WHERE id_historial = ?', [req.params.id]);
        res.sendStatus(204);
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar historial clínico', error: error.message });
    }
});



// ----- ESTUDIOS -----

// GET: obtener todos los estudios
app.get('/api/studies', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT id_estudio, id_paciente, fecha, file_name, comentarios FROM studies');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener estudios', error: error.message });
    }
});

// POST: crear un nuevo estudio
app.post('/api/studies', async (req, res) => {
  try {
    const { id_estudio, id_paciente, Fecha, TipoArchivo, ArchivoAdjunto, ArchivoNombre, Comentarios } = req.body;

    // ✅ Formatear fecha
    const fechaFormateada = new Date(Fecha).toISOString().slice(0, 10);

    // 🧹 LIMPIEZA PROFUNDA DEL BASE64
    let base64Limpio = ArchivoAdjunto;

    // Caso 1: Viene con prefijo estándar de Data URI (data:application/pdf;base64,...)
    if (ArchivoAdjunto.includes('base64,')) {
        base64Limpio = ArchivoAdjunto.split('base64,')[1];
    }
    // Caso 2: Viene con tu prefijo "sucio" (ej: 104212025-11-10application/pdfJVBERi...)
    // Usamos el TipoArchivo (ej: application/pdf) como marcador para saber dónde cortar.
    else if (TipoArchivo && ArchivoAdjunto.includes(TipoArchivo)) {
        // Cortamos justo después de donde termine el TipoArchivo
        const indiceCorte = ArchivoAdjunto.indexOf(TipoArchivo) + TipoArchivo.length;
        base64Limpio = ArchivoAdjunto.substring(indiceCorte);
    }

    // Limpieza extra por seguridad (elimina espacios en blanco si quedaron)
    base64Limpio = base64Limpio.replace(/\s/g, '');

    // 💾 Insertar
    await db.query(
      `INSERT INTO studies (id_estudio, id_paciente, fecha, file_type, file_data, file_name, comentarios)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [id_estudio, id_paciente, fechaFormateada, TipoArchivo, base64Limpio, ArchivoNombre, Comentarios]
    );

    const [[newStudy]] = await db.query('SELECT * FROM studies WHERE id_estudio = ?', [id_estudio]);
    res.status(201).json(newStudy);

  } catch (error) {
    console.error('Error al crear estudio:', error);
    res.status(500).json({ message: 'Error al crear estudio', error: error.message });
  }
});

// GET: Descargar estudio
app.get('/api/studies/file/:id', async (req, res) => {
  try {
    const studyId = req.params.id;

    // Buscamos el archivo en la base de datos
    const [rows] = await db.query(
      'SELECT file_data, file_name, file_type FROM studies WHERE id_estudio = ?',
      [studyId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Archivo no encontrado' });
    }

    const { file_data, file_name, file_type } = rows[0];

    if (!file_data) {
      return res.status(404).json({ message: 'Archivo vacío' });
    }

    // Convertimos base64 a buffer
    const base64 = file_data.replace(/\s/g, '');
    const fileBuffer = Buffer.from(base64, 'base64');

    // Headers correctos para descargar
    res.setHeader('Content-Disposition', `attachment; filename="${file_name}"`);
    res.setHeader('Content-Type', file_type || 'application/octet-stream');
    res.setHeader('Content-Length', fileBuffer.length);
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    // Enviamos el archivo
    return res.send(fileBuffer);

  } catch (error) {
    console.error('Error descargando archivo:', error);
    res.status(500).json({ message: 'Error al descargar archivo', error: error.message });
  }
});


// PUT: actualizar un estudio existente
app.put('/api/studies/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // 1. RECIBIMOS los nombres que envía el frontend (del formulario)
    const { id_paciente, Fecha, Comentarios, ArchivoNombre, TipoArchivo, ArchivoAdjunto } = req.body;

    // 2. Formatear fecha
    const fechaFormateada = new Date(Fecha).toISOString().slice(0, 10);

    // 3. CONSTRUCCIÓN DINÁMICA DE LA CONSULTA
    const fieldsToUpdate = [];
    const values = [];

    // Campos que siempre se actualizan
    fieldsToUpdate.push('id_paciente = ?');
    values.push(id_paciente);
    
    fieldsToUpdate.push('fecha = ?');
    values.push(fechaFormateada);
    
    // Usamos 'comentarios' (minúscula) porque así se llama tu columna en la BBD
    fieldsToUpdate.push('comentarios = ?'); 
    values.push(Comentarios);

    // 4. ✅ LÓGICA CLAVE: Actualizar el archivo SÓLO SI SE PROPORCIONÓ UNO
    // Si 'ArchivoAdjunto' es null, '', o undefined, este 'if' será falso
    // y las columnas del archivo NO se tocarán.
    if (ArchivoAdjunto) { 
      fieldsToUpdate.push('file_type = ?');
      values.push(TipoArchivo);
      
      fieldsToUpdate.push('file_data = ?');
      values.push(ArchivoAdjunto);
      
      fieldsToUpdate.push('file_name = ?');
      values.push(ArchivoNombre);
    }
    
    // 5. Unir todo y ejecutar
    const query = `UPDATE studies SET ${fieldsToUpdate.join(', ')} WHERE id_estudio = ?`;
    values.push(id); // Añadir el ID al final para el WHERE

    await db.query(query, values);

    // Devolver el estudio actualizado
    const [[updatedStudy]] = await db.query('SELECT * FROM studies WHERE id_estudio = ?', [id]);
    res.json(updatedStudy);

  } catch (error) {
    console.error('Error al actualizar estudio:', error);
    res.status(500).json({ message: 'Error al actualizar estudio', error: error.message });
  }
});


// DELETE: eliminar un estudio
app.delete('/api/studies/:id', async (req, res) => {
    try {
        await db.query('DELETE FROM studies WHERE id_estudio = ?', [req.params.id]);
        res.sendStatus(204);
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar estudio', error: error.message });
    }
});



// ----- MÉTODOS DE PAGO -----

// GET: obtener todos los métodos de pago
app.get('/api/payment_methods', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM payment_methods');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener métodos de pago', error: error.message });
    }
});

// POST: crear un nuevo método de pago
app.post('/api/payment_methods', async (req, res) => {
    try {
        const { Nombre, Activo = 1 } = req.body; // por defecto activo
        const [result] = await db.query(
            'INSERT INTO payment_methods (nombre, activo) VALUES (?, ?)',
            [Nombre, Activo]
        );
        const [[newMethod]] = await db.query(
            'SELECT * FROM payment_methods WHERE id_metodo_pago = ?',
            [result.insertId]
        );
        res.status(201).json(newMethod);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error al crear método de pago', error: error.message });
    }
});



// PUT: actualizar un método de pago
app.put('/api/payment_methods/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { Nombre, Activo } = req.body;
        await db.query(
            'UPDATE payment_methods SET nombre = ?, activo = ? WHERE id_metodo_pago = ?',
            [Nombre, Activo, id]
        );
        const [[updatedMethod]] = await db.query(
            'SELECT * FROM payment_methods WHERE id_metodo_pago = ?',
            [id]
        );
        res.json(updatedMethod);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error al actualizar método de pago', error: error.message });
    }
});


// DELETE: eliminar un método de pago
app.delete('/api/payment_methods/:id', async (req, res) => {
    try {
        await db.query('DELETE FROM payment_methods WHERE id_metodo_pago = ?', [req.params.id]);
        res.sendStatus(204);
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar método de pago', error: error.message });
    }
});


// ----- USUARIOS -----

// GET: obtener todos los usuarios (sin password)
app.get('/api/users', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT id, username, nombre, apellido, role, permissions FROM users');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener usuarios', error: error.message });
    }
});

// POST: crear un usuario
app.post('/api/users', async (req, res) => {
    try {
        // 1. NO pedimos 'id'.
        const { username, nombre, apellido, password, role, permissions } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 2. NO incluimos 'id' en el INSERT
        const [result] = await db.query(
            'INSERT INTO users (username, nombre, apellido, password, role, permissions) VALUES (?, ?, ?, ?, ?, ?)', 
            [username, nombre, apellido, hashedPassword, role, JSON.stringify(permissions)]
        );

        // 3. Obtenemos el ID que MySQL acaba de crear
        const newId = result.insertId;

        const [[newUser]] = await db.query('SELECT id, username, nombre, apellido, role, permissions FROM users WHERE id = ?', [newId]); // <-- 4. Usamos el newId
        res.status(201).json(newUser);
    } catch (error) {
        console.error("Error al crear usuario:", error); // <-- Añadí un log de error
        res.status(500).json({ message: 'Error al crear usuario', error: error.message });
    }
});

// PUT: actualizar un usuario
app.put('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { username, nombre, apellido, password, role, permissions } = req.body;
        const hashedPassword = password ? await bcrypt.hash(password, 10) : undefined;
        if (hashedPassword) {
            await db.query('UPDATE users SET username = ?, nombre = ?, apellido = ?, password = ?, role = ?, permissions = ? WHERE id = ?', [username, nombre, apellido, hashedPassword, role, JSON.stringify(permissions), id]);
        } else {
            await db.query('UPDATE users SET username = ?, nombre = ?, apellido = ?, role = ?, permissions = ? WHERE id = ?', [username, nombre, apellido, role, JSON.stringify(permissions), id]);
        }
        const [[updatedUser]] = await db.query('SELECT id, username, nombre, apellido, role, permissions FROM users WHERE id = ?', [id]);
        res.json(updatedUser);
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar usuario', error: error.message });
    }
});

// DELETE: eliminar un usuario
app.delete('/api/users/:id', async (req, res) => {
    try {
        await db.query('DELETE FROM users WHERE id = ?', [req.params.id]);
        res.sendStatus(204);
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar usuario', error: error.message });
    }
});


// ----- CUOTAS MENSUALES -----

// GET: obtener todas las cuotas
app.get('/api/monthly_fees', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM monthly_fees');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener cuotas', error: error.message });
    }
});

// POST: crear una cuota
// POST: crear una cuota (CORREGIDO)
app.post('/api/monthly_fees', async (req, res) => {
    try {
        // 1. NO pedimos 'id_cuota'. La base de datos lo genera.
        const { id_paciente, mes, ano, monto, fecha_pago, id_metodo_pago } = req.body;

        // 2. Convertimos la fecha ISO (que viene del frontend) a un objeto Date
        // El driver 'mysql2' sabrá cómo formatear este objeto para MySQL.
        const fechaPagoParaMySQL = new Date(fecha_pago);

        // 3. Modificamos la consulta para NO incluir 'id_cuota'
        const [result] = await db.query(
            'INSERT INTO monthly_fees (id_paciente, mes, ano, monto, fecha_pago, id_metodo_pago) VALUES (?, ?, ?, ?, ?, ?)',
            [id_paciente, mes, ano, monto, fechaPagoParaMySQL, id_metodo_pago] // <-- Usamos la fecha convertida
        );

        // 4. Obtenemos el ID de la fila que acabamos de insertar
        const newId = result.insertId;

        const [[newFee]] = await db.query('SELECT * FROM monthly_fees WHERE id_cuota = ?', [newId]); // <-- Usamos el newId


        res.status(201).json(newFee);
    } catch (error) {
        // Esto es muy útil para ver el error exacto en la consola del servidor
        console.error("Error al crear cuota:", error); 
        res.status(500).json({ message: 'Error al crear cuota', error: error.message });
    }
});
// PUT: actualizar una cuota
app.put('/api/monthly_fees/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { id_paciente, mes, ano, monto, fecha_pago, id_metodo_pago } = req.body;
        const fechaPagoParaMySQL = new Date(fecha_pago);
        await db.query(
            'UPDATE monthly_fees SET id_paciente = ?, mes = ?, ano = ?, monto = ?, fecha_pago = ?, id_metodo_pago = ? WHERE id_cuota = ?',
            [id_paciente, mes, ano, monto, fechaPagoParaMySQL, id_metodo_pago, id]
        );
        const [[updatedFee]] = await db.query('SELECT * FROM monthly_fees WHERE id_cuota = ?', [id]);
        res.json(updatedFee);
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar cuota', error: error.message });
    }
});

// DELETE: eliminar una cuota
app.delete('/api/monthly_fees/:id', async (req, res) => {
    try {
        await db.query('DELETE FROM monthly_fees WHERE id_cuota = ?', [req.params.id]);
        res.sendStatus(204);
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar cuota', error: error.message });
    }
});



// Ponemos a escuchar el servidor en un puerto
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});