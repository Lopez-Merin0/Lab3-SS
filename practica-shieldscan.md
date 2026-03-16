# 🛡 Práctica: Sistema Web de Escaneo de Malware con ClamAV
### Seguridad Informática · Uso de IA en Desarrollo

---

## 1. Descripción del Proyecto

**ShieldScan** es una aplicación web full-stack que permite a los usuarios subir archivos para analizarlos en busca de malware mediante **ClamAV** (antivirus de código abierto). La interfaz presenta resultados dinámicos con animaciones y retroalimentación visual clara.

**Stack tecnológico:**
- **Frontend:** HTML5, CSS3, JavaScript (Vanilla)
- **Backend:** Node.js + Express.js
- **Antivirus:** ClamAV (`clamd` daemon + `clamscan`)
- **Almacenamiento:** Multer (uploads), sistema de archivos local
- **IA utilizada:** Claude (Anthropic) para generación de código

---

## 2. Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENTE (Browser)                        │
│   ┌──────────────┐    Drag & Drop / Click    ┌──────────────┐   │
│   │  index.html  │ ──── archivo ──────────▶  │  fetch API   │   │
│   │  (UI/UX)     │ ◀─── JSON resultado ───── │  POST /scan  │   │
│   └──────────────┘                           └──────────────┘   │
└──────────────────────────────────┬──────────────────────────────┘
                                   │  HTTP (multipart/form-data)
┌──────────────────────────────────▼──────────────────────────────┐
│                    SERVIDOR Node.js (Express)                     │
│                                                                   │
│  ┌─────────────┐   ┌──────────────┐   ┌───────────────────────┐ │
│  │   Multer    │──▶│  SHA-256     │──▶│  ClamAV Integration   │ │
│  │  (upload)   │   │  Hash Check  │   │  (clamscan npm pkg)   │ │
│  └─────────────┘   └──────────────┘   └──────────┬────────────┘ │
│                                                   │              │
│  ┌────────────────────────────────────────────────▼───────────┐ │
│  │              clamd (ClamAV Daemon — Socket Unix)           │ │
│  │     Base de firmas: /var/lib/clamav/*.cvd  (260k+ firmas)  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌──────────────┐   ┌──────────────────────────────────────────┐ │
│  │  /uploads/   │   │          /quarantine/                    │ │
│  │ (temporal)   │   │  (archivos infectados aislados)          │ │
│  └──────────────┘   └──────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Instalación y Configuración

### 3.1 Requisitos del Sistema

| Componente | Versión mínima |
|---|---|
| Node.js | 18.x |
| npm | 9.x |
| ClamAV | 1.0+ |
| SO | Ubuntu 20.04 / Debian 11 / macOS |

### 3.2 Instalar ClamAV (Linux/Ubuntu)

```bash
# 1. Instalar paquetes
sudo apt update
sudo apt install clamav clamav-daemon -y

# 2. Detener servicio para actualizar definiciones
sudo systemctl stop clamav-freshclam

# 3. Actualizar base de firmas de virus (~300 MB)
sudo freshclam

# 4. Iniciar el daemon clamd
sudo systemctl start clamav-daemon
sudo systemctl enable clamav-daemon

# 5. Verificar estado
sudo systemctl status clamav-daemon
# Debe mostrar: Active: active (running)

# 6. Probar con archivo EICAR (test estándar de antivirus)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
clamscan /tmp/eicar.com
# Debe mostrar: /tmp/eicar.com: Eicar-Signature FOUND
```

### 3.3 Instalar Dependencias Node.js

```bash
# Crear proyecto
mkdir shieldscan && cd shieldscan
npm init -y

# Instalar dependencias
npm install express multer clamscan cors dotenv

# Estructura de directorios
shieldscan/
├── server.js          ← Backend API
├── public/
│   └── index.html     ← Frontend
├── uploads/           ← Archivos temporales (auto-creado)
├── quarantine/        ← Archivos infectados (auto-creado)
├── .env               ← Variables de entorno
└── package.json
```

### 3.4 Variables de Entorno (.env)

```env
PORT=3000
MAX_FILE_SIZE=52428800
CLAMD_SOCKET=/var/run/clamav/clamd.ctl
NODE_ENV=development
```

### 3.5 Ejecutar el Servidor

```bash
# Desarrollo (con auto-reload)
npx nodemon server.js

# Producción
node server.js

# Verificar que funciona
curl http://localhost:3000/api/health
```

---

## 4. API REST — Endpoints

### `POST /api/scan`
Sube y escanea un archivo.

**Request:**
```http
POST /api/scan HTTP/1.1
Content-Type: multipart/form-data
Body: file=<binary>
```

**Response (limpio):**
```json
{
  "id": "scan_1727800320000",
  "status": "clean",
  "filename": "documento.pdf",
  "size": 204800,
  "sizeFormatted": "200.0 KB",
  "sha256": "a3f5c8b2e1d4...",
  "threats": [],
  "action": "none",
  "scanDuration": "0.83",
  "scannedAt": "2025-10-01T14:32:00.000Z"
}
```

**Response (infectado):**
```json
{
  "id": "scan_1727800400000",
  "status": "infected",
  "filename": "malware_sample.exe",
  "size": 81920,
  "sha256": "f8c2a1...",
  "threats": ["Win.Trojan.Agent-1234", "Heuristics.Suspicious"],
  "action": "quarantined",
  "scanDuration": "1.12",
  "scannedAt": "2025-10-01T14:33:20.000Z"
}
```

### `GET /api/health`
Estado del servicio ClamAV.

```json
{
  "status": "ok",
  "clamd": "running",
  "version": "ClamAV 1.3.0",
  "timestamp": "2025-10-01T14:30:00.000Z"
}
```

### `GET /api/scan/:id`
Recupera el resultado de un escaneo por ID.

### `GET /api/scans`
Lista los últimos 50 escaneos realizados.

### `DELETE /api/file/:id`
Elimina permanentemente un archivo en cuarentena.

---

## 5. Frontend — Funcionalidades

| Característica | Descripción |
|---|---|
| Drag & Drop | Arrastrar archivos directamente a la zona de carga |
| Clic para seleccionar | Input `<file>` nativo del navegador |
| Validación visual | Muestra nombre, tamaño e ícono según extensión |
| Progreso animado | 5 pasos con barra de progreso y estados visuales |
| Resultado dinámico | Tarjeta verde (limpio) o roja (infectado) |
| Lista de amenazas | Muestra el nombre exacto del virus detectado |
| Diseño responsivo | Funciona en móvil, tablet y escritorio |
| Documentación inline | Sección colapsable de la API REST |

---

## 6. Seguridad Implementada

### 6.1 Validaciones del Servidor
```javascript
// Límite de tamaño: 50MB
limits: { fileSize: 50 * 1024 * 1024 }

// Bloqueo de extensiones peligrosas en el servidor
const blocked = ['.php', '.phtml'];

// Hash SHA-256 para integridad
const sha256 = await sha256File(filePath);
```

### 6.2 Gestión Post-Escaneo
- **Archivo limpio** → Se elimina del servidor inmediatamente
- **Archivo infectado** → Se mueve a `/quarantine/` (aislado)
- **Error** → Se elimina automáticamente del directorio de uploads

### 6.3 Medidas Adicionales Recomendadas (Producción)
```javascript
// Rate limiting
const rateLimit = require('express-rate-limit');
app.use('/api/scan', rateLimit({ windowMs: 60000, max: 10 }));

// Autenticación JWT
app.use('/api', verifyToken);

// HTTPS obligatorio
// Usar nginx como reverse proxy con certificado SSL/TLS
```

---

## 7. Uso de IA en el Desarrollo

Este proyecto fue desarrollado con asistencia de **Claude (Anthropic)** mediante los siguientes prompts:

### Prompt 1 — Generación del Frontend
> *"Crea una interfaz web moderna para un escáner de malware llamado ShieldScan. Debe incluir zona de drag & drop, barra de progreso animada con pasos, y tarjetas de resultado dinámicas (verde = limpio, roja = infectado). Usa un diseño oscuro industrial con colores verde neón y rojo."*

**Resultado:** Interfaz completa en ~350 líneas de HTML/CSS/JS

### Prompt 2 — Generación del Backend
> *"Crea un servidor Express.js que reciba archivos con Multer, calcule SHA-256, los escanee con ClamAV usando el paquete clamscan, mueva los infectados a cuarentena y devuelva JSON con el resultado. Incluye endpoints: POST /api/scan, GET /api/health, DELETE /api/file/:id"*

**Resultado:** API REST funcional con manejo de errores y cuarentena

### Prompt 3 — Documentación
> *"Genera documentación técnica en Markdown para el proyecto ShieldScan con: arquitectura ASCII, instrucciones de instalación de ClamAV, ejemplos de API con JSON, secciones de seguridad y preguntas de evaluación."*

### Beneficios del uso de IA
| Tarea | Sin IA | Con IA | Ahorro |
|---|---|---|---|
| Frontend completo | ~4 horas | ~20 minutos | 80% |
| Backend API | ~3 horas | ~15 minutos | 92% |
| Documentación | ~2 horas | ~10 minutos | 92% |
| **Total** | **~9 horas** | **~45 minutos** | **~91%** |

---

## 8. Pruebas

### 8.1 Prueba con Archivo EICAR (Virus de Prueba Estándar)
```bash
# El archivo EICAR es reconocido por todos los antivirus como test
# NO es un virus real, es seguro usarlo en pruebas
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > test_eicar.com

# Subirlo via curl
curl -X POST http://localhost:3000/api/scan \
  -F "file=@test_eicar.com"

# Resultado esperado:
# { "status": "infected", "threats": ["Eicar-Signature"] }
```

### 8.2 Prueba con Archivo Limpio
```bash
echo "Este es un archivo de texto normal" > limpio.txt
curl -X POST http://localhost:3000/api/scan \
  -F "file=@limpio.txt"

# Resultado esperado:
# { "status": "clean", "threats": [] }
```

### 8.3 Prueba del Health Check
```bash
curl http://localhost:3000/api/health
# { "status": "ok", "clamd": "running", "version": "ClamAV 1.3.0" }
```

---

## 9. Preguntas de Evaluación

1. ¿Qué diferencia hay entre `clamscan` y `clamd`? ¿Por qué usamos el daemon?
2. ¿Por qué se calcula el SHA-256 antes del escaneo? ¿Qué ventaja ofrece?
3. ¿Qué pasaría si no elimináramos los archivos limpios del servidor?
4. ¿Cómo funciona el archivo EICAR? ¿Por qué es útil para pruebas?
5. ¿Qué vulnerabilidades de seguridad podría tener este sistema en producción?
6. ¿Cómo mejorarías el sistema para soportar 1000 usuarios concurrentes?
7. ¿Qué ventajas y desventajas tiene usar IA para generar código en proyectos de seguridad?

---

## 10. Referencias

- Documentación oficial ClamAV: https://docs.clamav.net
- npm `clamscan`: https://github.com/kylefarris/clamscan
- EICAR Test File: https://www.eicar.org/download-anti-malware-testfile/
- Express.js: https://expressjs.com
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

---

*Desarrollado con asistencia de Claude (Anthropic) · Práctica de Seguridad Informática 2025*
