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

    const steps = [
        { id: 'step1', text: 'Subiendo archivo...', pct: 20 },
        { id: 'step2', text: 'Verificando SHA-256...', pct: 40 },
        { id: 'step3', text: 'Iniciando ClamAV...', pct: 60 },
        { id: 'step4', text: 'Analizando firmas...', pct: 80 },
        { id: 'step5', text: 'Generando reporte...', pct: 100 }
    ];

    for (let i = 0; i < steps.length; i++) {
        setStepActive(steps[i].id);
        setProgress(steps[i].pct, steps[i].text);
        await sleep(700 + Math.random() * 400);
        setStepDone(steps[i].id);
    }

    await sleep(400);

    try {
        const result = await mockScanAPI(selectedFile);
        showResult(result); // success o infected
    } catch (e) {
        showResult({ status: 'error', message: e.message }); // error
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

// MOCK - reemplazar por fetch('/api/scan', { method: 'POST', body: formData })
async function mockScanAPI(file) {
    await sleep(300);

    const isInfected = file.name.toLowerCase().includes('test') || file.name.toLowerCase().includes('virus');
    const sha256 = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');

    if (isInfected) {
        return {
            status: 'infected',
            filename: file.name,
            size: file.size,
            sha256,
            scannedAt: new Date().toISOString(),
            threats: ['Win.Trojan.Agent-' + Math.floor(Math.random() * 9999), 'Heuristics.Suspicious']
        };
    }

    return {
        status: 'clean',
        filename: file.name,
        size: file.size,
        sha256,
        scannedAt: new Date().toISOString(),
        threats: [],
        scanDuration: (Math.random() * 2 + 0.5).toFixed(2)
    };
}

// Toggle visual de la seccion de documentacion API.
function toggleApi() {
    const body = document.getElementById('apiBody');
    const txt = document.getElementById('apiToggleText');
    body.classList.toggle('open');
    txt.textContent = body.classList.contains('open') ? 'Colapsar ↑' : 'Expandir ↓';
}
