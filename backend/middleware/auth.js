function auth(req, res, next) {
  const requiredApiKey = process.env.API_KEY;

  // Si no hay API_KEY configurada, el middleware se vuelve no bloqueante.
  if (!requiredApiKey) {
    return next();
  }

  const apiKeyHeader = req.headers['x-api-key'];
  const authHeader = req.headers.authorization || '';
  const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  const provided = apiKeyHeader || bearerToken;
  if (!provided || provided !== requiredApiKey) {
    return res.status(401).json({ error: 'No autorizado' });
  }

  next();
}

module.exports = {
  auth
};
