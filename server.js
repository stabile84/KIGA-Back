require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

const whitelist = [
  'http://localhost:5173',
  'http://localhost:3000',
  'http://192.168.1.14:3000',
  'https://kiga-kinesio.vercel.app'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || whitelist.indexOf(origin) !== -1) {
      callback(null, true)
    } else {
      callback(new Error('Bloqueado por CORS: Tu origen no está autorizado'))
    }
  },
  credentials: true
};

app.use(cors(corsOptions));

// RUTA PING (Con Reintento Automático)
app.get('/ping', async (req, res) => {
  try {
    // INTENTO 1
    await db.query('SELECT 1');
    console.log('✅ Ping OK - APP y DB activas. (Intento 1)');
    res.status(200).send('pong');

  } catch (error) {
    console.warn('⚠️ El primer intento de Ping falló. Reintentando...', error.code);

    try {
      // INTENTO 2 (Forzamos reconexión)
      // Esperamos 1 segundo por seguridad
      await new Promise(resolve => setTimeout(resolve, 5000));

      await db.query('SELECT 1');
      console.log('✅ Ping RECUPERADO - APP y DB activas. (Intento 2)');
      res.status(200).send('pong recuperado');

    } catch (error2) {
      // Si falla dos veces, es que la base de datos se cayó de verdad
      console.error('❌ ALERTA: La DB está caída definitivamente:', error2);
      res.status(500).send('DB Error Fatal');
    }
  }
});

// --- SEGURIDAD ---
app.use(helmet());
app.set('trust proxy', 1);
app.use(cookieParser());

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { message: 'Demasiadas peticiones, intenta más tarde.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(generalLimiter);

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { message: 'Demasiados intentos de login. Espera 1 minuto.' }
});

app.use('/api/login', loginLimiter);

app.use(express.json({ limit: '50mb' }));

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: 4000,
  ssl: {
    minVersion: 'TLSv1.2',
    rejectUnauthorized: true
  },
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0,
  enableKeepAlive: true,
  dateStrings: true
}).promise();

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  console.log("Login recibido:", req.body);

  if (!username || !password) {
    return res.status(400).json({ error: 'Username y password son requeridos' });
  }

  try {
    const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    const user = rows[0];

    if (!user.is_active) {
      return res.status(403).json({ error: 'Usuario desactivado. Contacte al administrador.' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }

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
      { expiresIn: '8h' }
    );

    res.cookie('token', token, {
      httpOnly: true, // 🛡️ JavaScript no la ve (Anti-XSS)
      secure: true,   // 🛡️ Obligatorio para HTTPS (Render/Vercel) y SameSite: None
      sameSite: 'none', // 🛡️ Permite que viaje de Vercel a Render
      maxAge: 8 * 60 * 60 * 1000 // 8 horas
    });

    console.log("Usuario encontrado:", user.username);

    res.json({
      mensaje: 'Login exitoso',
      user: {
        id: user.id,
        username: user.username,
        nombre: user.nombre,
        apellido: user.apellido,
        role: user.role,
        permissions: user.permissions
      }
    });

  } catch (err) {
    console.error("Error en login:", err);
    res.status(500).json({ error: 'Error en el servidor', detalle: err.message });
  }
});

app.post('/api/logout', (req, res) => {
  // Para borrar la cookie, necesitamos pasar las MISMAS opciones 
  // que usamos al crearla (excepto maxAge/expires)
  res.clearCookie('token', {
    httpOnly: true,
    secure: true,   // true para Render/Vercel (HTTPS)
    sameSite: 'none'
  });

  return res.status(200).json({ message: 'Sesión cerrada exitosamente' });
});

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.clearCookie('token');
    res.status(403).json({ error: 'Token inválido o expirado' });
  }
};

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
    console.log("🔴 Error al guardar paciente. Código:", error.code, "| Número:", error.errno);

    if (error.code === 'ER_DUP_ENTRY' || error.errno === 1062) {
      return res.status(409).json({
        message: 'No se puede guardar: Ya existe un paciente con ese DNI.'
      });
    }

    console.error("Error desconocido:", error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});
app.put('/api/patients/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { Nombre, Apellido, Referencia, FechaNacimiento, DNI, Telefono, Antecedentes } = req.body;

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

app.get('/api/specialties', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM specialties');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener especialidades', error: error.message });
  }
});

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
    const formatearFechaLocal = (isoString) => {
      const fecha = new Date(isoString);
      const yyyy = fecha.getFullYear();
      const mm = String(fecha.getMonth() + 1).padStart(2, '0');
      const dd = String(fecha.getDate()).padStart(2, '0');
      const hh = String(fecha.getHours()).padStart(2, '0');
      const min = String(fecha.getMinutes()).padStart(2, '0');
      const ss = String(fecha.getSeconds()).padStart(2, '0');
      return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
    };

    if (Array.isArray(req.body)) {
      const newAppointments = req.body;
      const recurringId = Date.now().toString();

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

    const formatearFechaLocal = (isoString) => {
      if (!isoString) return null;
      const fecha = new Date(isoString);
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

    const horaInicioMySQL = formatearFechaLocal(HoraInicio);
    const horaFinMySQL = formatearFechaLocal(HoraFin);
    const fechaPagoMySQL = FechaPago ? formatearFechaLocal(FechaPago) : null;

    await db.query(
      `UPDATE appointments
       SET id_paciente=?, id_especialidad=?, hora_inicio=?, hora_fin=?, pago=?, fecha_pago=?, id_metodo_pago=?, costo_turno=?
       WHERE id_turno = ?`,
      [id_paciente, id_especialidad, horaInicioMySQL, horaFinMySQL, Pago, fechaPagoMySQL, id_metodo_pago, CostoTurno, id]
    );

    const [[updatedAppointment]] = await db.query(
      'SELECT * FROM appointments WHERE id_turno = ?',
      [id]
    );
    res.json(updatedAppointment);
  } catch (error) {
    console.error('Error al actualizar turno:', error);
    res.status(500).json({ message: 'Error al actualizar turno', error: error.message });
  }
});

app.delete('/api/appointments/:id', async (req, res) => {
  await db.query('DELETE FROM appointments WHERE id_turno = ?', [req.params.id]);
  res.sendStatus(204);
});

app.delete('/api/appointments/recurring/all/:recurringId', async (req, res) => {
  await db.query('DELETE FROM appointments WHERE recurring_id = ?', [req.params.recurringId]);
  res.sendStatus(204);
});

app.delete('/api/appointments/recurring/future', async (req, res) => {
  const { recurringId, cutoffDate } = req.query;
  if (!recurringId || !cutoffDate) {
    return res.status(400).send('Faltan parámetros');
  }
  const fechaParaMySQL = new Date(cutoffDate);
  await db.query('DELETE FROM appointments WHERE recurring_id = ? AND hora_inicio >= ?', [recurringId, fechaParaMySQL]);
  res.sendStatus(204);
});

// ----- HISTORIAL CLÍNICO -----
app.get('/api/history_entries', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM history_entries');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener historial clínico', error: error.message });
  }
});

app.post('/api/history_entries', async (req, res) => {
  try {
    const { id_paciente, Fecha, Seguimiento } = req.body;
    const fechaFormateada = new Date(Fecha).toISOString().slice(0, 10);

    const [result] = await db.query(
      'INSERT INTO history_entries (id_paciente, fecha, seguimiento) VALUES (?, ?, ?)',
      [id_paciente, fechaFormateada, Seguimiento]
    );

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

app.put('/api/history_entries/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { id_paciente, Fecha, Seguimiento } = req.body;
    const fechaFormateada = new Date(Fecha).toISOString().slice(0, 10);

    await db.query(
      'UPDATE history_entries SET id_paciente = ?, fecha = ?, seguimiento = ? WHERE id_historial = ?',
      [id_paciente, fechaFormateada, Seguimiento, id]
    );

    const [[updatedEntry]] = await db.query(
      'SELECT * FROM history_entries WHERE id_historial = ?',
      [id]
    );
    res.json(updatedEntry);
  } catch (error) {
    console.error('Error al actualizar historial clínico:', error);
    res.status(500).json({ message: 'Error al actualizar historial clínico', error: error.message });
  }
});

app.delete('/api/history_entries/:id', async (req, res) => {
  try {
    await db.query('DELETE FROM history_entries WHERE id_historial = ?', [req.params.id]);
    res.sendStatus(204);
  } catch (error) {
    res.status(500).json({ message: 'Error al eliminar historial clínico', error: error.message });
  }
});

// ----- ESTUDIOS -----
app.get('/api/studies', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id_estudio, id_paciente, fecha, file_name, comentarios FROM studies');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener estudios', error: error.message });
  }
});

app.post('/api/studies', async (req, res) => {
  try {
    const { id_estudio, id_paciente, Fecha, TipoArchivo, ArchivoAdjunto, ArchivoNombre, Comentarios } = req.body;
    const fechaFormateada = new Date(Fecha).toISOString().slice(0, 10);
    let base64Limpio = ArchivoAdjunto;

    if (ArchivoAdjunto.includes('base64,')) {
      base64Limpio = ArchivoAdjunto.split('base64,')[1];
    } else if (TipoArchivo && ArchivoAdjunto.includes(TipoArchivo)) {
      const indiceCorte = ArchivoAdjunto.indexOf(TipoArchivo) + TipoArchivo.length;
      base64Limpio = ArchivoAdjunto.substring(indiceCorte);
    }
    base64Limpio = base64Limpio.replace(/\s/g, '');

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

app.get('/api/studies/file/:id', async (req, res) => {
  try {
    const studyId = req.params.id;
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

    const base64 = file_data.replace(/\s/g, '');
    const fileBuffer = Buffer.from(base64, 'base64');

    res.setHeader('Content-Disposition', `attachment; filename="${file_name}"`);
    res.setHeader('Content-Type', file_type || 'application/octet-stream');
    res.setHeader('Content-Length', fileBuffer.length);
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    return res.send(fileBuffer);

  } catch (error) {
    console.error('Error descargando archivo:', error);
    res.status(500).json({ message: 'Error al descargar archivo', error: error.message });
  }
});

app.put('/api/studies/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { id_paciente, Fecha, Comentarios, ArchivoNombre, TipoArchivo, ArchivoAdjunto } = req.body;
    const fechaFormateada = new Date(Fecha).toISOString().slice(0, 10);

    const fieldsToUpdate = [];
    const values = [];

    fieldsToUpdate.push('id_paciente = ?');
    values.push(id_paciente);

    fieldsToUpdate.push('fecha = ?');
    values.push(fechaFormateada);

    fieldsToUpdate.push('comentarios = ?');
    values.push(Comentarios);

    if (ArchivoAdjunto) {
      fieldsToUpdate.push('file_type = ?');
      values.push(TipoArchivo);

      fieldsToUpdate.push('file_data = ?');
      values.push(ArchivoAdjunto);

      fieldsToUpdate.push('file_name = ?');
      values.push(ArchivoNombre);
    }

    const query = `UPDATE studies SET ${fieldsToUpdate.join(', ')} WHERE id_estudio = ?`;
    values.push(id);

    await db.query(query, values);

    const [[updatedStudy]] = await db.query('SELECT * FROM studies WHERE id_estudio = ?', [id]);
    res.json(updatedStudy);

  } catch (error) {
    console.error('Error al actualizar estudio:', error);
    res.status(500).json({ message: 'Error al actualizar estudio', error: error.message });
  }
});

app.delete('/api/studies/:id', async (req, res) => {
  try {
    await db.query('DELETE FROM studies WHERE id_estudio = ?', [req.params.id]);
    res.sendStatus(204);
  } catch (error) {
    res.status(500).json({ message: 'Error al eliminar estudio', error: error.message });
  }
});

// ----- MÉTODOS DE PAGO -----
app.get('/api/payment_methods', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM payment_methods');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener métodos de pago', error: error.message });
  }
});

app.post('/api/payment_methods', async (req, res) => {
  try {
    const { Nombre, Activo = 1 } = req.body;
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

app.delete('/api/payment_methods/:id', async (req, res) => {
  try {
    await db.query('DELETE FROM payment_methods WHERE id_metodo_pago = ?', [req.params.id]);
    res.sendStatus(204);
  } catch (error) {
    res.status(500).json({ message: 'Error al eliminar método de pago', error: error.message });
  }
});

// ----- USUARIOS -----
app.get('/api/users', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id, username, nombre, apellido, role, permissions, is_active FROM users');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener usuarios', error: error.message });
  }
});

app.post('/api/users', async (req, res) => {
  try {
    const { username, nombre, apellido, password, role, permissions, is_active } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      'INSERT INTO users (username, nombre, apellido, password, role, permissions, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [username, nombre, apellido, hashedPassword, role, JSON.stringify(permissions), is_active !== undefined ? is_active : true]
    );

    const newId = result.insertId;
    const [[newUser]] = await db.query('SELECT id, username, nombre, apellido, role, permissions, is_active FROM users WHERE id = ?', [newId]);
    res.status(201).json(newUser);
  } catch (error) {
    console.error("Error al crear usuario:", error);
    res.status(500).json({ message: 'Error al crear usuario', error: error.message });
  }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { username, nombre, apellido, password, role, permissions, is_active } = req.body;
    const hashedPassword = password ? await bcrypt.hash(password, 10) : undefined;
    if (hashedPassword) {
      await db.query('UPDATE users SET username = ?, nombre = ?, apellido = ?, password = ?, role = ?, permissions = ?, is_active = ? WHERE id = ?', [username, nombre, apellido, hashedPassword, role, JSON.stringify(permissions), is_active, id]);
    } else {
      await db.query('UPDATE users SET username = ?, nombre = ?, apellido = ?, role = ?, permissions = ?, is_active = ? WHERE id = ?', [username, nombre, apellido, role, JSON.stringify(permissions), is_active, id]);
    }
    const [[updatedUser]] = await db.query('SELECT id, username, nombre, apellido, role, permissions, is_active FROM users WHERE id = ?', [id]);
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar usuario', error: error.message });
  }
});

app.delete('/api/users/:id', async (req, res) => {
  try {
    await db.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.sendStatus(204);
  } catch (error) {
    res.status(500).json({ message: 'Error al eliminar usuario', error: error.message });
  }
});

// ----- CUOTAS MENSUALES -----
app.get('/api/monthly_fees', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM monthly_fees');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener cuotas', error: error.message });
  }
});

app.post('/api/monthly_fees', async (req, res) => {
  try {
    const { id_paciente, mes, ano, monto, fecha_pago, id_metodo_pago } = req.body;
    const fechaPagoParaMySQL = new Date(fecha_pago);

    const [result] = await db.query(
      'INSERT INTO monthly_fees (id_paciente, mes, ano, monto, fecha_pago, id_metodo_pago) VALUES (?, ?, ?, ?, ?, ?)',
      [id_paciente, mes, ano, monto, fechaPagoParaMySQL, id_metodo_pago]
    );

    const newId = result.insertId;
    const [[newFee]] = await db.query('SELECT * FROM monthly_fees WHERE id_cuota = ?', [newId]);
    res.status(201).json(newFee);
  } catch (error) {
    console.error("Error al crear cuota:", error);
    res.status(500).json({ message: 'Error al crear cuota', error: error.message });
  }
});

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

app.delete('/api/monthly_fees/:id', async (req, res) => {
  try {
    await db.query('DELETE FROM monthly_fees WHERE id_cuota = ?', [req.params.id]);
    res.sendStatus(204);
  } catch (error) {
    res.status(500).json({ message: 'Error al eliminar cuota', error: error.message });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});