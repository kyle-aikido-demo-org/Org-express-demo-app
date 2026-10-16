// Basic-auth protected API + OpenAPI spec for Aikido REST API scans.
// INTENTIONALLY VULNERABLE. Demo only.
const path = require('path');
const fs = require('fs');

module.exports = function registerPrivateApi(app, db, rows) {
  const USER = process.env.DEMO_USER || 'demo';
  const PASS = process.env.DEMO_PASS || 'demo-password';

  db.run(`CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT);
          INSERT INTO notes VALUES (1,'alice','Alice private note'),(2,'bob','Bob private note'),(3,'demo','Demo note');`);

  function basicAuth(req, res, next) {
    const h = req.headers.authorization || '';
    const [scheme, token] = h.split(' ');
    if (scheme === 'Basic' && token) {
      const [u, p] = Buffer.from(token, 'base64').toString().split(':');
      if (u === USER && p === PASS) return next();
    }
    res.set('WWW-Authenticate', 'Basic realm="dast-demo"');
    res.status(401).json({ error: 'authentication required' });
  }

  // OpenAPI spec (Aikido can fetch this URL). Uses the request host so it works anywhere.
  app.get('/openapi.json', (req, res) => {
    const server = `${req.protocol}://${req.get('host')}`;
    const q = (name, extra = {}) => ({ name, in: 'query', required: true, schema: { type: 'string', ...extra } });
    res.json({
      openapi: '3.0.3',
      info: { title: 'DAST Demo API', version: '1.0.0' },
      servers: [{ url: server }],
      components: { securitySchemes: { basicAuth: { type: 'http', scheme: 'basic' } } },
      paths: {
        '/api/health': { get: { responses: { 200: { description: 'ok' } } } },
        '/api/products': { get: { parameters: [q('name')], responses: { 200: { description: 'products' } } } },
        '/api/users/{id}': {
          get: { parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'user' } } },
        },
        '/api/private/notes': {
          get: { security: [{ basicAuth: [] }], parameters: [q('search')], responses: { 200: { description: 'notes' } } },
          post: {
            security: [{ basicAuth: [] }],
            requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { body: { type: 'string' } }, required: ['body'] } } } },
            responses: { 201: { description: 'created' } },
          },
        },
        '/api/private/notes/{id}': {
          get: { security: [{ basicAuth: [] }], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'note' } } },
        },
        '/api/private/files': {
          get: { security: [{ basicAuth: [] }], parameters: [q('name')], responses: { 200: { description: 'file contents' } } },
        },
      },
    });
  });

  // VULN: SQL injection (needs auth)
  app.get('/api/private/notes', basicAuth, (req, res) => {
    const s = req.query.search || '';
    try {
      res.json(rows(`SELECT * FROM notes WHERE body LIKE '%${s}%'`));
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // VULN: IDOR, any authenticated user can read any note, plus SQLi in the id
  app.get('/api/private/notes/:id', basicAuth, (req, res) => {
    try {
      const n = rows(`SELECT * FROM notes WHERE id=${req.params.id}`)[0];
      n ? res.json(n) : res.status(404).json({ error: 'not found' });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // VULN: SQLi on insert (and mass assignment of owner)
  app.post('/api/private/notes', basicAuth, (req, res) => {
    const { body = '', owner = USER } = req.body || {};
    try {
      db.run(`INSERT INTO notes (owner, body) VALUES ('${owner}', '${body}')`);
      res.status(201).json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // VULN: path traversal (needs auth)
  app.get('/api/private/files', basicAuth, (req, res) => {
    const p = path.join(__dirname, 'files', req.query.name || 'readme.txt');
    fs.readFile(p, 'utf8', (err, data) => {
      if (err) return res.status(404).json({ error: `cannot read ${p}` });
      res.type('text/plain').send(data);
    });
  });
};
