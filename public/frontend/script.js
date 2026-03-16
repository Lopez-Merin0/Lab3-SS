/* ========================
   Referencias y estado
======================== */
const uploadZone = document.getElementById('uploadZone');
const fileInput = document.getElementById('fileInput');
let selectedFile = null;

const MAX_SIZE = 10 * 1024 * 1024; // 10MB
const ALLOWED_EXTENSIONS = [
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.txt', '.jpg', '.jpeg', '.png', '.gif',
    '.zip', '.rar', '.7z', '.exe'
];

// ========================
// Comunicacion asincrona con backend
// ========================
const API_BASE = '/api';
const REQUEST_TIMEOUT_MS = 10000;      // Timeout por request individual
const SCAN_TIMEOUT_MS = 120000;        // Timeout total del proceso de escaneo
const POLL_INTERVAL_MS = 1500;         // Frecuencia de polling de estado
const MAX_RETRIES = 3;                 // Reintentos para fallos temporales
const RETRY_BASE_DELAY_MS = 500;       // Backoff exponencial base

// Interfaz drag & drop
uploadZone.addEventListener('dragover', (e) => { e.preventDefault(); uploadZone.classList.add('drag-over'); });

uploadZone.addEventListener('dragleave', () => { uploadZone.classList.remove('drag-over'); });

uploadZone.addEventListener('drop', (e) => {
    e.preventDefault(); uploadZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) handleFileSelect(file);
});

uploadZone.addEventListener('click', () => { fileInput.click(); });

fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) handleFileSelect(fileInput.files[0]);
});

//Validacion de archivos client-side
function handleFileSelect(file) {
    const ext = '.' + file.name.split('.').pop().toLowerCase();

    // Valida tipo permitido antes de enviar al servidor.
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
        alert(`❌ Extensión no permitida: ${ext}\n\nExtensiones aceptadas:\n${ALLOWED_EXTENSIONS.join('  ')}`);
        fileInput.value = '';
        return;
    }

    // Valida tamano maximo (10MB).
    if (file.size > MAX_SIZE) {
        alert(`❌ Archivo demasiado grande: ${formatSize(file.size)}\n\nMáximo permitido: 10MB`);
        fileInput.value = '';
        return;
    }

    // Muestra metadatos del archivo al usuario.
    selectedFile = file;
    document.getElementById('fileName').textContent = file.name;
    document.getElementById('fileSize').textContent = `${formatSize(file.size)} · ${file.type || 'tipo desconocido'}`;
    document.getElementById('fileEmoji').textContent = getFileEmoji(file.name);
    document.getElementById('selectedFile').classList.add('show');
    document.getElementById('scanBtn').disabled = false;
    document.getElementById('resultSection').classList.remove('show');
    document.getElementById('progressSection').classList.remove('show');
}

function clearFile() {
    selectedFile = null;
    fileInput.value = '';
    document.getElementById('selectedFile').classList.remove('show');
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('resultSection').classList.remove('show');
    document.getElementById('progressSection').classList.remove('show');
}

//Barra de progreso
function setProgress(pct, text) {
    document.getElementById('progressFill').style.width = `${pct}%`;
    document.getElementById('progressPct').textContent = `${pct}%`;
    document.getElementById('progressText').textContent = text;
}

function resetSteps() {
    ['step1', 'step2', 'step3', 'step4', 'step5'].forEach((id) => {
        const el = document.getElementById(id);
        el.classList.remove('active', 'done');
    });
    setProgress(0, 'Iniciando...');
}

function setStepActive(id) {
    document.getElementById(id).classList.add('active');
}

function setStepDone(id) {
    const el = document.getElementById(id);
    el.classList.remove('active');
    el.classList.add('done');
}

//Estados visuales (loading/success/error)
async function startScan() {
    if (!selectedFile) return;

    // Loading: deshabilita boton y muestra progreso.
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('progressSection').classList.add('show');
    document.getElementById('resultSection').classList.remove('show');
    resetSteps();

    try {
        // 1) SUBIDA DEL ARCHIVO (POST /api/upload)
        setStepActive('step1');
        setProgress(20, 'Subiendo archivo...');
        const uploadData = await uploadFile(selectedFile);
        setStepDone('step1');

        // 2) CREACION DEL JOB DE ESCANEO (POST /api/scan/:fileId)
        setStepActive('step2');
        setProgress(40, 'Creando job de escaneo...');
        const scanData = await createScanJob(uploadData.fileId);
        setStepDone('step2');

        // 3) POLLING ASINCRONO + TIMEOUT GLOBAL + RETRY EN FALLOS TEMPORALES
        const result = await pollScanResult(scanData.scanId);
        showResult(result); // clean o infected
    } catch (e) {
        showResult({ status: 'error', message: e.message });
    }

    document.getElementById('scanBtn').disabled = false;
}

//Feedback visual del resultado del escaneo
function showResult(data) {
    document.getElementById('progressSection').classList.remove('show');
    const sec = document.getElementById('resultSection');

    let html = '';

    if (data.status === 'clean') {
        html = `
      <div class="result-card clean">
        <div class="result-header">
          <span class="result-status-icon">✅</span>
          <div>
            <div class="result-title">Archivo Limpio</div>
            <div class="result-subtitle">No se detectaron amenazas. El archivo es seguro.</div>
          </div>
        </div>
        <div class="result-details">
          <div class="detail-item"><div class="detail-label">Archivo</div><div class="detail-value">${data.filename}</div></div>
          <div class="detail-item"><div class="detail-label">Tamaño</div><div class="detail-value">${formatSize(data.size)}</div></div>
          <div class="detail-item"><div class="detail-label">SHA-256</div><div class="detail-value" style="font-size:0.75rem">${data.sha256}...</div></div>
          <div class="detail-item"><div class="detail-label">Duración</div><div class="detail-value">${data.scanDuration}s</div></div>
        </div>
        <div class="action-buttons">
          <button class="scan-btn" style="width:auto;padding:12px 24px" onclick="clearFile()">📁 Escanear otro</button>
          <button class="btn-secondary">📋 Copiar reporte</button>
        </div>
      </div>`;
    } else if (data.status === 'infected') {
        const threatItems = data.threats.map((t) => `<div class="threat-item">${t}</div>`).join('');
        html = `
      <div class="result-card infected">
        <div class="result-header">
          <span class="result-status-icon">🚨</span>
          <div>
            <div class="result-title">¡Amenaza Detectada!</div>
            <div class="result-subtitle">${data.threats.length} amenaza(s) encontrada(s). Archivo puesto en cuarentena.</div>
          </div>
        </div>
        <div class="result-details">
          <div class="detail-item"><div class="detail-label">Archivo</div><div class="detail-value">${data.filename}</div></div>
          <div class="detail-item"><div class="detail-label">Estado</div><div class="detail-value" style="color:#ff3366">En cuarentena</div></div>
          <div class="detail-item"><div class="detail-label">SHA-256</div><div class="detail-value" style="font-size:0.75rem">${data.sha256}...</div></div>
          <div class="detail-item"><div class="detail-label">Escaneo</div><div class="detail-value">${new Date(data.scannedAt).toLocaleTimeString()}</div></div>
        </div>
        <div class="threat-list">
          <h4>⚠ Amenazas encontradas</h4>
          ${threatItems}
        </div>
        <div class="action-buttons">
          <button class="btn-danger">🗑 Eliminar archivo</button>
          <button class="btn-secondary">📋 Copiar reporte</button>
          <button class="btn-secondary" onclick="clearFile()">↩ Volver</button>
        </div>
      </div>`;
    } else {
        html = `
      <div class="result-card error">
        <div class="result-header">
          <span class="result-status-icon">⚠️</span>
          <div>
            <div class="result-title">Error de Escaneo</div>
            <div class="result-subtitle">${data.message || 'No se pudo completar el escaneo.'}</div>
          </div>
        </div>
        <div class="action-buttons">
          <button class="btn-secondary" onclick="startScan()">↺ Reintentar</button>
        </div>
      </div>`;
    }

    sec.innerHTML = html;
    sec.classList.add('show');
}

/* ========================
   Utilidades auxiliares
======================== */
function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
}

function isTemporaryFailureStatus(status) {
    return [408, 425, 429, 500, 502, 503, 504].includes(status);
}

function getRetryDelay(attempt) {
    const exponential = RETRY_BASE_DELAY_MS * (2 ** attempt);
    const jitter = Math.floor(Math.random() * 200);
    return exponential + jitter;
}

// Request con timeout por AbortController.
// Retorna status HTTP y body JSON (o texto fallback) para poder manejar 200/422/500.
async function requestJson(url, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });

        let data = null;
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
            data = await response.json();
        } else {
            const text = await response.text();
            data = { message: text || 'Respuesta sin contenido' };
        }

        return { ok: response.ok, status: response.status, data };
    } catch (err) {
        if (err.name === 'AbortError') {
            throw new Error('Timeout de red: el servidor tardo demasiado en responder');
        }
        throw new Error(`Error de red: ${err.message}`);
    } finally {
        clearTimeout(timer);
    }
}

// Retry logic para fallos temporales (timeouts, errores de red y status transitorios).
// Se usa en endpoints idempotentes de polling para no duplicar operaciones.
async function requestWithRetry(url, options = {}, cfg = {}) {
    const {
        retries = MAX_RETRIES,
        timeoutMs = REQUEST_TIMEOUT_MS
    } = cfg;

    let lastError = null;

    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            const res = await requestJson(url, options, timeoutMs);

            if (!res.ok && isTemporaryFailureStatus(res.status) && attempt < retries) {
                await sleep(getRetryDelay(attempt));
                continue;
            }

            return res;
        } catch (err) {
            lastError = err;
            if (attempt < retries) {
                await sleep(getRetryDelay(attempt));
                continue;
            }
            throw lastError;
        }
    }

    throw lastError || new Error('Fallo temporal no recuperable');
}

// POST /api/upload
async function uploadFile(file) {
    const form = new FormData();
    form.append('file', file);

    const res = await requestJson(`${API_BASE}/upload`, {
        method: 'POST',
        body: form
    });

    if (!res.ok) {
        throw new Error(res.data?.error || res.data?.message || 'No se pudo subir el archivo');
    }

    return res.data;
}

// POST /api/scan/:fileId
async function createScanJob(fileId) {
    const res = await requestJson(`${API_BASE}/scan/${encodeURIComponent(fileId)}`, {
        method: 'POST'
    });

    if (!res.ok) {
        throw new Error(res.data?.error || res.data?.message || 'No se pudo iniciar el escaneo');
    }

    return res.data;
}

// Polling asincrono del estado y resultado final.
// Cubre:
// - Comunicacion asincrona (polling)
// - Timeout total del escaneo
// - Retry para errores temporales
async function pollScanResult(scanId) {
    const timeoutAt = Date.now() + SCAN_TIMEOUT_MS;
    let step3Done = false;
    let step4Active = false;

    setStepActive('step3');
    setProgress(60, 'Esperando inicio del escaneo...');

    while (Date.now() < timeoutAt) {
        const statusRes = await requestWithRetry(`${API_BASE}/status/${encodeURIComponent(scanId)}`, {
            method: 'GET'
        });

        if (!statusRes.ok) {
            throw new Error(statusRes.data?.error || statusRes.data?.message || 'No se pudo consultar el estado');
        }

        const status = statusRes.data.status;

        if (status === 'pending') {
            setProgress(60, 'Escaneo en cola...');
            await sleep(POLL_INTERVAL_MS);
            continue;
        }

        if (status === 'scanning') {
            if (!step3Done) {
                setStepDone('step3');
                step3Done = true;
            }

            if (!step4Active) {
                setStepActive('step4');
                step4Active = true;
            }

            setProgress(80, 'ClamAV analizando firmas...');
            await sleep(POLL_INTERVAL_MS);
            continue;
        }

        if (status === 'error') {
            const resultRes = await requestWithRetry(`${API_BASE}/result/${encodeURIComponent(scanId)}`, {
                method: 'GET'
            });
            throw new Error(resultRes.data?.error || resultRes.data?.message || 'El escaneo fallo');
        }

        if (status === 'completed') {
            if (!step3Done) setStepDone('step3');
            if (step4Active) setStepDone('step4');

            setStepActive('step5');
            setProgress(100, 'Generando reporte final...');

            const resultRes = await requestWithRetry(`${API_BASE}/result/${encodeURIComponent(scanId)}`, {
                method: 'GET'
            });

            // 200 => archivo limpio
            if (resultRes.status === 200) {
                setStepDone('step5');
                return resultRes.data;
            }

            // 422 => archivo infectado (resultado valido con amenazas)
            if (resultRes.status === 422) {
                setStepDone('step5');
                return resultRes.data;
            }

            // 500 u otro estado inesperado
            throw new Error(resultRes.data?.error || resultRes.data?.message || 'No se pudo obtener el resultado final');
        }

        await sleep(POLL_INTERVAL_MS);
    }

    throw new Error(`Timeout: el escaneo excedio ${Math.floor(SCAN_TIMEOUT_MS / 1000)} segundos`);
}

function getFileEmoji(name) {
    const ext = name.split('.').pop().toLowerCase();
    const map = {
        pdf: '📄',
        zip: '🗜',
        exe: '⚙',
        doc: '📝',
        docx: '📝',
        js: '📜',
        py: '🐍',
        sh: '💻',
        jpg: '🖼',
        png: '🖼',
        mp4: '🎬',
        mp3: '🎵'
    };
    return map[ext] || '📁';
}

function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(2)} MB`;
}

// Toggle visual de la seccion de documentacion API.
function toggleApi() {
    const body = document.getElementById('apiBody');
    const txt = document.getElementById('apiToggleText');
    body.classList.toggle('open');
    txt.textContent = body.classList.contains('open') ? 'Colapsar ↑' : 'Expandir ↓';
}
