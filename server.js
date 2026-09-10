require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// 1. Validación estricta de variables de entorno requeridas (Sin fallbacks)
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
const PORT = process.env.PORT || 3000; 

const MATRIX_PE = process.env.MATRIX_PE_URL;
const MATRIX_CL = process.env.MATRIX_CL_URL;

const allowedOrigins = [MATRIX_PE, MATRIX_CL];

// 2. Configuración estricta de CORS compatible con Express v5
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Bloqueado por política CORS'));
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Origin', 'Accept', 'X-Requested-With'],
    credentials: true,
    optionsSuccessStatus: 200
}));

app.use(express.json());

// 3. Configuración de Cifrado AES-256-GCM
const ENCRYPTION_KEY = crypto.scryptSync(ENCRYPTION_SECRET, 'salt', 32);
const TOKENS_FILE = path.join(__dirname, 'tokens.bin');

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

// Cargar almacenamiento persistente cifrado si existe en disco
let tokens = { PE: null, CL: null };
if (fs.existsSync(TOKENS_FILE)) {
    const decryptedData = decrypt(fs.readFileSync(TOKENS_FILE, 'utf-8'));
    if (decryptedData) tokens = JSON.parse(decryptedData);
}

// 4. Middleware de Autenticación por Bearer Token
function verificarAutenticacion(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader === `Bearer ${API_SECRET}`) {
        return next();
    }
    return res.status(401).json({ error: "No autorizado" });
}

// 5. ENDPOINT: Guardar o limpiar Token (Perú o Chile)
app.post('/save-token', verificarAutenticacion, (req, res) => {
    const { country, token } = req.body;
    
    if (country === 'PE' || country === 'CL') {
        // Si el token viene vacío, nulo o indefinido, lo borramos
        if (!token) {
            tokens[country] = null;
            tokens[`${country}_updated_at`] = new Date().toISOString();
            console.log(`🗑️ Token de Matrix ${country} eliminado (Cierre de sesión detectado).`);
        } else {
            tokens[country] = token.trim().replace(/^"|"$/g, '');
            tokens[`${country}_updated_at`] = new Date().toISOString();
            console.log(`✅ Token de Matrix ${country} recibido y cifrado correctamente.`);
        }

        fs.writeFileSync(TOKENS_FILE, encrypt(JSON.stringify(tokens)), 'utf-8');
        return res.json({ status: "success", country, active: !!tokens[country] });
    }
    
    return res.status(400).json({ error: "País inválido" });
});

// ENDPOINT: Obtener todos los tokens
app.get('/get-token', verificarAutenticacion, (req, res) => {
    if (!tokens.PE && !tokens.CL) {
        return res.status(404).json({ 
            status: "error", 
            message: "Token no encontrado. Las sesiones de Perú y Chile están cerradas." 
        });
    }

    return res.json({ 
        status: "success", 
        tokens: {
            PE: tokens.PE || "Token no encontrado",
            PE_updated_at: tokens.PE_updated_at || null,
            CL: tokens.CL || "Token no encontrado",
            CL_updated_at: tokens.CL_updated_at || null
        } 
    });
});

// ENDPOINT: Obtener token de Perú
app.get('/get-token/pe', verificarAutenticacion, (req, res) => {
    if (!tokens.PE) {
        return res.status(404).json({ 
            status: "error", 
            message: "Token no encontrado para Perú" 
        });
    }
    return res.json({ 
        status: "success", 
        country: "PE", 
        id_token: tokens.PE, 
        updated_at: tokens.PE_updated_at 
    });
});

// ENDPOINT: Obtener token de Chile
app.get('/get-token/cl', verificarAutenticacion, (req, res) => {
    if (!tokens.CL) {
        return res.status(404).json({ 
            status: "error", 
            message: "Token no encontrado para Chile" 
        });
    }
    return res.json({ 
        status: "success", 
        country: "CL", 
        id_token: tokens.CL, 
        updated_at: tokens.CL_updated_at 
    });
});

// 6. Inicio del Servidor enlazado a 0.0.0.0
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor Multi-País activo en el puerto ${PORT}`);
    console.log(`🇵🇪 Origen PE: ${MATRIX_PE}`);
    console.log(`🇨🇱 Origen CL: ${MATRIX_CL}`);
});