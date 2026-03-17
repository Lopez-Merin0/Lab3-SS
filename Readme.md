# ShieldScan

Aplicacion web para escaneo de archivos con ClamAV, construida con Node.js + Express en backend y frontend vanilla (HTML/CSS/JS).

## Caracteristicas principales

- Carga de archivos con drag & drop.
- Validacion de tipo y tamano en cliente y servidor.
- Escaneo antivirus asincrono con ClamAV.
- Polling de estado de escaneo (`pending`, `scanning`, `completed`, `error`).
- Manejo de timeout por request y timeout global de escaneo.
- Retry logic para fallos temporales con backoff exponencial.
- Resultados diferenciados:
  - `200`: archivo limpio
  - `422`: archivo infectado
  - `500`: error tecnico
- Acciones UX:
  - Descargar reporte JSON
  - Copiar reporte al portapapeles
  - Descargar archivo limpio
  - Limpieza de archivo infectado (`DELETE /api/cleanup/:fileId`)

## Estructura del proyecto

```text
P3/
├── backend/
│   ├── server.js
│   ├── routes/
│   │   ├── upload.js
│   │   ├── scan.js
│   │   └── status.js
│   ├── middleware/
│   │   ├── validation.js
│   │   └── auth.js
│   ├── services/
│   │   └── clamav.js
│   └── utils/
│       └── helpers.js
├── public/
│   └── frontend/
│       ├── index.html
│       ├── styles.css
│       └── script.js
├── uploads/
├── quarantine/
├── package.json
└── README.md
```

## Requisitos

- Node.js 18+
- ClamAV (daemon `clamd`) activo

## Instalacion

1. Instalar dependencias:

```bash
npm install
```

2. (Opcional) Configurar variables de entorno en un archivo `.env`:

```env
PORT=3000
CORS_ORIGIN=*
CLAMD_HOST=127.0.0.1
CLAMD_PORT=3310
API_KEY=
```

## Ejecucion

```bash
npm start
```

Servidor por defecto: `http://localhost:3000`

## Flujo de escaneo

1. `POST /api/upload` para subir archivo.
2. `POST /api/scan/:fileId` para crear job de escaneo.
3. Polling con `GET /api/status/:scanId` hasta `completed` o `error`.
4. Obtener resultado con `GET /api/result/:scanId`.
5. (Opcional) Limpiar temporales con `DELETE /api/cleanup/:fileId`.

## API (resumen)

### POST /api/upload
Recibe archivo multipart y retorna `fileId`.

### POST /api/scan/:fileId
Inicia escaneo asincrono y retorna `scanId`.

### GET /api/status/:scanId
Retorna estado del job: `pending`, `scanning`, `completed`, `error`.

### GET /api/result/:scanId
- `200` archivo limpio
- `422` archivo infectado
- `500` error tecnico

### DELETE /api/cleanup/:fileId
Elimina temporales asociados al archivo y sus scans.

## Seguridad y validaciones

- Filtro de extensiones y tamano maximo.
- Rate limiter en memoria por IP.
- CORS configurable.
- API key opcional (`X-API-Key` o `Authorization: Bearer`).

## Notas

- Los datos de archivos y jobs se guardan en memoria (`Map`), por lo que se reinician al apagar el servidor.
- Para produccion, se recomienda persistencia en base de datos y cola de jobs.
