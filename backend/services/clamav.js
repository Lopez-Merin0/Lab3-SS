const NodeClam = require('clamscan');

let clamscan = null;

async function initClamAV() {
  clamscan = await new NodeClam().init({
    removeInfected: false,
    quarantineInfected: false,
    scanRecursively: false,
    clamdscan: {
      socket: false,
      host: process.env.CLAMD_HOST || '127.0.0.1',
      port: Number(process.env.CLAMD_PORT || 3310),
      active: true
    },
    preference: 'clamdscan'
  });

  return clamscan;
}

function isReady() {
  return Boolean(clamscan);
}

async function scanFile(filePath) {
  if (!clamscan) {
    throw new Error('ClamAV no inicializado');
  }

  return clamscan.isInfected(filePath);
}

async function getVersion() {
  if (!clamscan) {
    throw new Error('ClamAV no inicializado');
  }

  const version = await clamscan.getVersion();
  return version.trim();
}

module.exports = {
  initClamAV,
  isReady,
  scanFile,
  getVersion
};
