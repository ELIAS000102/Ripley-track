require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// CONFIGURACIÓN DE SEGURIDAD
const API_SECRET = process.env.API_SECRET;
const ENCRYPTION_SECRET = process.env.TOKEN_SECRET_KEY;
const ENCRYPTION_KEY = crypto.scryptSync(ENCRYPTION_SECRET, 'salt', 32);
const TOKENS_FILE = path.join(__dirname, 'tokens.bin');

// Funciones de cifrado AES-256-GCM
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

// Cargar estado guardado desde el archivo cifrado al arrancar
let tokens = { PE: null, CL: null };
if (fs.existsSync(TOKENS_FILE)) {
    const rawData = fs.readFileSync(TOKENS_FILE, 'utf-8');
    const decryptedData = decrypt(rawData);
    if (decryptedData) {
        tokens = JSON.parse(decryptedData);
        console.log("🔒 [INICIO] Tokens cifrados cargados correctamente desde el disco.");
    }
}

// Restricción de Origen (CORS controlado)
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (!origin || origin.includes('localhost') || origin.includes('ripleyprd.com')) {
        res.header("Access-Control-Allow-Origin", origin || "*");
        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
        res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        if (req.method === 'OPTIONS') return res.sendStatus(200);
        return next();
    }
    return res.status(403).json({ error: "Acceso bloqueado por política CORS" });
});

// Middleware de Autorización por Bearer Token
function verificarAutenticacion(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader === `Bearer ${API_SECRET}`) {
        return next();
    }
    return res.status(401).json({ error: "No autorizado. Debes enviar Authorization: Bearer <API_SECRET>" });
}

// ENDPOINT: Recibir y cifrar tokens desde la extensión
app.post('/save-token', (req, res) => {
    const { country, token } = req.body;
    if (token && (country === 'PE' || country === 'CL')) {
        const cleanToken = token.trim().replace(/^"|"$/g, '');
        tokens[country] = cleanToken;
        tokens[`${country}_updated_at`] = new Date().toISOString();

        // Escribir archivo cifrado binario
        const encryptedContent = encrypt(JSON.stringify(tokens));
        fs.writeFileSync(TOKENS_FILE, encryptedContent, 'utf-8');

        console.log(`✅ [${new Date().toLocaleTimeString()}] Token de Matrix ${country} CIFRADO y actualizado en disco.`);
        return res.json({ status: "success", country: country });
    }
    return res.status(400).json({ error: "Datos de token o país inválidos" });
});

// ENDPOINTS PROTEGIDOS: Consultar tokens
app.get('/get-token', verificarAutenticacion, (req, res) => {
    return res.json({
        status: "success",
        tokens: {
            pe: tokens.PE,
            cl: tokens.CL,
            updated_pe: tokens.PE_updated_at,
            updated_cl: tokens.CL_updated_at
        }
    });
});

app.get('/get-token/pe', verificarAutenticacion, (req, res) => {
    if (!tokens.PE) {
        return res.status(404).json({ error: "Token de Perú no disponible. Abre Matrix Perú en el navegador." });
    }
    return res.json({ status: "success", country: "PE", id_token: tokens.PE, updated_at: tokens.PE_updated_at });
});

app.get('/get-token/cl', verificarAutenticacion, (req, res) => {
    if (!tokens.CL) {
        return res.status(404).json({ error: "Token de Chile no disponible. Abre Matrix Chile en el navegador." });
    }
    return res.json({ status: "success", country: "CL", id_token: tokens.CL, updated_at: tokens.CL_updated_at });
});

// Vinculación exclusiva a loopback local (127.0.0.1)
app.listen(3000, '127.0.0.1', () => {
    console.log("🔒 Servidor Seguro Multi-País activo exclusivamente en http://127.0.0.1:3000");
});