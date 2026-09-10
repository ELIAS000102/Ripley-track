require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Validación estricta de variables de entorno requeridas
const requiredEnvVars = [
    'API_SECRET',
    'TOKEN_SECRET_KEY',
    'MATRIX_PE_URL',
    'MATRIX_CL_URL'
];

const missingEnvVars = requiredEnvVars.filter((varName) => !process.env[varName]);

if (missingEnvVars.length > 0) {
    console.error(`❌ ERROR CRÍTICO: Faltan las siguientes variables de entorno: ${missingEnvVars.join(', ')}`);
    process.exit(1);
}

const app = express();

const API_SECRET = process.env.API_SECRET;
const ENCRYPTION_SECRET = process.env.TOKEN_SECRET_KEY;
const PORT = process.env.PORT || 3000; // Asignado dinámicamente por la plataforma de Hosting

const MATRIX_PE = process.env.MATRIX_PE_URL;
const MATRIX_CL = process.env.MATRIX_CL_URL;

const allowedOrigins = [MATRIX_PE, MATRIX_CL];

// Configuración estricta de CORS
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Bloqueado por política CORS'));
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Origin', 'Accept', 'X-Requested-With'],
    credentials: true
}));

app.options('*', cors());

app.use(express.json());

const ENCRYPTION_KEY = crypto.scryptSync(ENCRYPTION_SECRET, 'salt', 32);
const TOKENS_FILE = path.join(__dirname, 'tokens.bin');

// Funciones de Cifrado AES-256-GCM
function encrypt(text) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return JSON.stringify({ iv: iv.toString('hex'), encrypted, authTag });
}

function decrypt(data) {
    try {
        const { iv, encrypted, authTag } = JSON.parse(data);
        const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        return null;
    }
}

// Cargar almacenamiento persistente
let tokens = { PE: null, CL: null };
if (fs.existsSync(TOKENS_FILE)) {
    const decryptedData = decrypt(fs.readFileSync(TOKENS_FILE, 'utf-8'));
    if (decryptedData) tokens = JSON.parse(decryptedData);
}

// Middleware de autenticación Bearer Token
function verificarAutenticacion(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader === `Bearer ${API_SECRET}`) {
        return next();
    }
    return res.status(401).json({ error: "No autorizado" });
}

// Endpoints
app.post('/save-token', verificarAutenticacion, (req, res) => {
    const { country, token } = req.body;
    if (token && (country === 'PE' || country === 'CL')) {
        tokens[country] = token.trim().replace(/^"|"$/g, '');
        tokens[`${country}_updated_at`] = new Date().toISOString();

        fs.writeFileSync(TOKENS_FILE, encrypt(JSON.stringify(tokens)), 'utf-8');
        console.log(`✅ Token de ${country} actualizado y cifrado correctamente.`);
        return res.json({ status: "success", country });
    }
    return res.status(400).json({ error: "Datos de token o país inválidos" });
});

app.get('/get-token', verificarAutenticacion, (req, res) => {
    return res.json({ status: "success", tokens });
});

app.get('/get-token/pe', verificarAutenticacion, (req, res) => {
    if (!tokens.PE) return res.status(404).json({ error: "Token PE no disponible" });
    return res.json({ status: "success", country: "PE", id_token: tokens.PE });
});

app.get('/get-token/cl', verificarAutenticacion, (req, res) => {
    if (!tokens.CL) return res.status(404).json({ error: "Token CL no disponible" });
    return res.json({ status: "success", country: "CL", id_token: tokens.CL });
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor activo en puerto ${PORT}`);
    console.log(`🇵🇪 Origen PE: ${MATRIX_PE}`);
    console.log(`🇨🇱 Origen CL: ${MATRIX_CL}`);
});