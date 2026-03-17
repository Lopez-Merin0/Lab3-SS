const http = require('http');
const { spawn } = require('child_process');

const APP_URL = 'http://localhost:3000';
const HEALTH_URL = `${APP_URL}/api/health`;

const backend = spawn('npm run start:backend', [], {
  stdio: 'inherit',
  shell: true
});

let opened = false;

function openBrowser(url) {
  if (process.platform === 'win32') {
    spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore' }).unref();
    return;
  }

  if (process.platform === 'darwin') {
    spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
    return;
  }

  spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).unref();
}

function checkBackendReady() {
  const req = http.get(HEALTH_URL, (res) => {
    // 200 (clamd listo) o 503 (backend arriba sin clamd) significa que el backend responde.
    if (!opened && (res.statusCode === 200 || res.statusCode === 503)) {
      opened = true;
      clearInterval(timer);
      openBrowser(APP_URL);
      console.log(`Abriendo app en ${APP_URL}`);
    }

    res.resume();
  });

  req.on('error', () => {
    // Backend aun no disponible. Reintentar en el siguiente ciclo.
  });

  req.setTimeout(1500, () => {
    req.destroy();
  });
}

const timer = setInterval(checkBackendReady, 1000);
checkBackendReady();

backend.on('exit', (code) => {
  clearInterval(timer);
  process.exit(code || 0);
});

backend.on('error', (err) => {
  clearInterval(timer);
  console.error(`No se pudo iniciar el backend: ${err.message}`);
  process.exit(1);
});
