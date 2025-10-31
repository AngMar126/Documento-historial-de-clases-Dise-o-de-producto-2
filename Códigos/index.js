const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Conexión a MongoDB Atlas
const MONGO_URI = "mongodb+srv://tequilaypachita_db_user:6qOZgzuBgXx42pFV@cluster0.bithaeo.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
mongoose.connect(MONGO_URI, { dbName: "cafeteria" })
  .then(() => console.log("Conectado a MongoDB Atlas"))
  .catch(err => console.error("Error de conexión:", err.message));

/* ============================================================
   SCHEMAS Y MODELOS
   ============================================================ */

// ROL
const rolSchema = new mongoose.Schema({
  nombre: { type: String, required: true, unique: true }
});
const Rol = mongoose.model("Rol", rolSchema);

// LUGAR
const lugarSchema = new mongoose.Schema({
  nombre: { type: String, required: true },
  descripcion: String
});
const Lugar = mongoose.model("Lugar", lugarSchema);

// USUARIO
const usuarioSchema = new mongoose.Schema({
  cedula: { type: String, required: true, unique: true },
  nombre: { type: String, required: true },
  apellido: { type: String, required: true },
  contrasena: { type: String, required: true },
  rol: { type: mongoose.Schema.Types.ObjectId, ref: 'Rol', required: true },
  lugar: { type: mongoose.Schema.Types.ObjectId, ref: 'Lugar' }
}, { timestamps: true });
const Usuario = mongoose.model("Usuario", usuarioSchema);

// CANECA
const canecaSchema = new mongoose.Schema({
  serial: { type: String, required: true, unique: true },
  id_lugar: { type: mongoose.Schema.Types.ObjectId, ref: "Lugar" },
  tipo: String,
  nivel_almacenamiento: String
});
const Caneca = mongoose.model("Caneca", canecaSchema);

// DETALLE CANECA
const detalleCanecaSchema = new mongoose.Schema({
  id_caneca: { type: mongoose.Schema.Types.ObjectId, ref: "Caneca" },
  categoria: String,
  cantidad: Number
});
const DetalleCaneca = mongoose.model("DetalleCaneca", detalleCanecaSchema);

// HISTÓRICO
const historicoNivelSchema = new mongoose.Schema({
  id_caneca: { type: mongoose.Schema.Types.ObjectId, ref: "Caneca" },
  fecha: { type: Date, default: Date.now },
  nivel_almacenamiento: String
});
const HistoricoNivel = mongoose.model("HistoricoNivel", historicoNivelSchema);

// MONITOREO
const monitoreoSchema = new mongoose.Schema({
  id_caneca: { type: mongoose.Schema.Types.ObjectId, ref: "Caneca" },
  fecha: { type: Date, default: Date.now },
  nivel_almacenamiento: String,
  nivel_bateria: Number,
  estado_bateria: String,
  observaciones: String
});
const Monitoreo = mongoose.model("Monitoreo", monitoreoSchema);

/* ============================================================
   AUTENTICACIÓN
   ============================================================ */

const SECRET_KEY = "reciclaje";

// Verificar token
function verificarToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ mensaje: "Token no proporcionado" });

  try {
    const decoded = jwt.verify(token.replace("Bearer ", ""), SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ mensaje: "Token inválido o expirado" });
  }
}

// Verificar rol de administrador
async function soloAdmin(req, res, next) {
  const usuario = await Usuario.findById(req.user.id).populate("rol");
  if (!usuario || usuario.rol.nombre !== "Administrador") {
    return res.status(403).json({ mensaje: "Acceso denegado: se requiere rol Administrador" });
  }
  next();
}

/* ============================================================
   RUTAS DE AUTENTICACIÓN
   ============================================================ */

// Crear usuario
app.post("/usuarios", async (req, res) => {
  try {
    const { cedula, nombre, apellido, contrasena, rol } = req.body;
    const hash = await bcrypt.hash(contrasena, 10);
    const nuevo = new Usuario({ cedula, nombre, apellido, contrasena: hash, rol });
    await nuevo.save();
    res.status(201).json({ mensaje: "Usuario creado", usuario: nuevo });
  } catch (error) {
    res.status(500).json({ mensaje: "Error al crear usuario", error: error.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { cedula, contrasena } = req.body;
  const usuario = await Usuario.findOne({ cedula }).populate("rol");
  if (!usuario) return res.status(404).json({ mensaje: "Usuario no encontrado" });

  const match = await bcrypt.compare(contrasena, usuario.contrasena);
  if (!match) return res.status(401).json({ mensaje: "Contraseña incorrecta" });

  const token = jwt.sign({ id: usuario._id, rol: usuario.rol.nombre }, SECRET_KEY, { expiresIn: "2h" });
  res.json({ mensaje: "Login exitoso", token, rol: usuario.rol.nombre });
});

/* ============================================================
   CRUD PRINCIPALES
   ============================================================ */

// Roles
// Roles (sin token)
app.post("/roles", async (req, res) => {
  try {
    const rol = new Rol(req.body);
    await rol.save();
    res.json(rol);
  } catch (error) {
    res.status(500).json({ mensaje: "Error al crear rol", error: error.message });
  }
});

app.get("/roles", async (req, res) => {
  try {
    const roles = await Rol.find();
    res.json(roles);
  } catch (error) {
    res.status(500).json({ mensaje: "Error al listar roles", error: error.message });
  }
});

app.delete("/roles/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await Rol.findByIdAndDelete(id);
    res.json({ mensaje: "Rol eliminado correctamente" });
  } catch (error) {
    res.status(500).json({ mensaje: "Error al eliminar rol", error: error.message });
  }
});


// Lugares
app.post("/lugares", verificarToken, soloAdmin, async (req, res) => {
  const lugar = new Lugar(req.body);
  await lugar.save();
  res.json(lugar);
});
app.get("/lugares", async (req, res) => {
  const lugares = await Lugar.find();
  res.json(lugares);
});
app.delete("/lugares/:id", verificarToken, soloAdmin, async (req, res) => {
  const { id } = req.params;
  const canecasAsociadas = await Caneca.find({ id_lugar: id });
  if (canecasAsociadas.length > 0) {
    return res.status(400).json({ mensaje: "No se puede eliminar el lugar porque tiene canecas asociadas" });
  }
  await Lugar.findByIdAndDelete(id);
  res.json({ mensaje: "Lugar eliminado correctamente" });
});

// Canecas
app.post("/canecas", verificarToken, soloAdmin, async (req, res) => {
  const caneca = new Caneca(req.body);
  await caneca.save();
  res.json(caneca);
});
app.get("/canecas", async (req, res) => {
  const canecas = await Caneca.find().populate("id_lugar");
  res.json(canecas);
});
app.delete("/canecas/:id", verificarToken, soloAdmin, async (req, res) => {
  const { id } = req.params;
  await Caneca.findByIdAndDelete(id);
  res.json({ mensaje: "Caneca eliminada correctamente" });
});

// Detalle de Caneca
app.post("/detallecaneca", verificarToken, soloAdmin, async (req, res) => {
  const detalle = new DetalleCaneca(req.body);
  await detalle.save();
  res.json(detalle);
});
app.get("/detallecaneca", async (req, res) => {
  const detalles = await DetalleCaneca.find().populate("id_caneca");
  res.json(detalles);
});
app.delete("/detallecaneca/:id", verificarToken, soloAdmin, async (req, res) => {
  const { id } = req.params;
  await DetalleCaneca.findByIdAndDelete(id);
  res.json({ mensaje: "Detalle de Caneca eliminado correctamente" });
});

// Monitoreo
app.post("/monitoreo", verificarToken, async (req, res) => {
  const monitoreo = new Monitoreo(req.body);
  await monitoreo.save();
  res.json(monitoreo);
});
app.get("/monitoreo", async (req, res) => {
  const monitoreos = await Monitoreo.find().populate("id_caneca");
  res.json(monitoreos);
});

// Histórico
app.post("/historico", verificarToken, async (req, res) => {
  const historico = new HistoricoNivel(req.body);
  await historico.save();
  res.json(historico);
});
app.get("/historico", async (req, res) => {
  const historicos = await HistoricoNivel.find().populate("id_caneca");
  res.json(historicos);
});

/* ============================================================
   INICIO DEL SERVIDOR
   ============================================================ */
app.listen(PORT, () => {
  console.log(`Servidor iniciado en http://localhost:${PORT}`);
});

