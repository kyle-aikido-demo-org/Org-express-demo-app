// Basic-auth protected API + OpenAPI spec for Aikido REST API scans.
// INTENTIONALLY VULNERABLE. Demo only.
const path = require('path');
const fs = require('fs');

module.exports = function registerPrivateApi(app, db, rows) {
  const USER = process.env.DEMO_USER || 'demo';
  const PASS = process.env.DEMO_PASS || 'demo-password';

  db.run(`CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT);
          INSERT INTO notes VALUES (1,'alice','Alice private note'),(2,'bob','Bob private note'),(3,'demo','Demo note');`);

  // Makes the existing time-based blind SQLi payloads (SLEEP()/pg_sleep()) in
  // /api/products, /api/users/:id and /api/private/notes* actually observable.
  // Capped at 10s so a scan can't chain requests into a long hang.
  const MAX_SLEEP_SECONDS = 10;
  const blockingSleep = (seconds) => {
    const ms = Math.min(Number(seconds) || 0, MAX_SLEEP_SECONDS) * 1000;
    const until = Date.now() + ms;
    while (Date.now() < until) {
      /* intentionally blocking, mirrors a slow query for demo purposes */
    }
    return null;
  };
  if (typeof db.create_function === 'function') {
    db.create_function('SLEEP', blockingSleep);
    db.create_function('sleep', blockingSleep);
    db.create_function('pg_sleep', blockingSleep);
  }

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
    const q = (name) => ({ name, in: 'query', required: true, schema: { type: 'string' } });
    const idParam = { name: 'id', in: 'path', required: true, schema: { type: 'string' } };
    const auth = [{ basicAuth: [] }];
    const loginSchema = {
      type: 'object',
      properties: { username: { type: 'string' }, password: { type: 'string' } },
      required: ['username', 'password'],
    };
    const anyJson = { content: { 'application/json': { schema: { type: 'object', additionalProperties: true } } } };

    res.json({
      openapi: '3.0.3',
      info: { title: 'DAST Demo API', version: '1.0.0' },
      servers: [{ url: server }],
      components: { securitySchemes: { basicAuth: { type: 'http', scheme: 'basic' } } },
      paths: {
        '/api/health': { get: { responses: { 200: { description: 'ok' } } } },
        '/search': { get: { parameters: [q('q')], responses: { 200: { description: 'HTML results page' } } } },
        '/api/products': { get: { parameters: [q('name')], responses: { 200: { description: 'products' } } } },
        '/api/users/{id}': { get: { parameters: [idParam], responses: { 200: { description: 'user' } } } },
        '/download': {
          get: { parameters: [q('file')], responses: { 200: { description: 'file contents' }, 404: { description: 'not found' } } },
        },
        '/redirect': { get: { parameters: [q('url')], responses: { 302: { description: 'redirect' } } } },
        '/error': { get: { responses: { 500: { description: 'error page' } } } },
        '/login': {
          get: { responses: { 200: { description: 'login form' } } },
          post: {
            requestBody: {
              required: true,
              content: {
                'application/x-www-form-urlencoded': { schema: loginSchema },
                'application/json': { schema: loginSchema },
              },
            },
            responses: { 200: { description: 'welcome' }, 401: { description: 'invalid credentials' } },
          },
        },
        '/webhook': {
          get: { responses: { 200: { description: 'echoes request body' } } },
          post: { requestBody: anyJson, responses: { 200: { description: 'echoes request body' } } },
          put: { requestBody: anyJson, responses: { 200: { description: 'echoes request body' } } },
          patch: { requestBody: anyJson, responses: { 200: { description: 'echoes request body' } } },
          delete: { responses: { 200: { description: 'echoes request body' } } },
        },
        '/api/private/notes': {
          get: { security: auth, parameters: [q('search')], responses: { 200: { description: 'notes' }, 401: { description: 'unauthorized' } } },
          post: {
            security: auth,
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: { body: { type: 'string' }, owner: { type: 'string' } },
                    required: ['body'],
                  },
                },
              },
            },
            responses: { 201: { description: 'created' }, 401: { description: 'unauthorized' } },
          },
        },
        '/api/private/notes/{id}': {
          get: { security: auth, parameters: [idParam], responses: { 200: { description: 'note' }, 401: { description: 'unauthorized' } } },
        },
        '/api/private/files': {
          get: { security: auth, parameters: [q('name')], responses: { 200: { description: 'file contents' }, 401: { description: 'unauthorized' } } },
        },
        '/files/{name}': {
          get: { parameters: [{ name: 'name', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'file contents' }, 404: { description: 'not found' } } },
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

  // VULN: path traversal via URL *path* parameter (no auth) - the same class of
  // bug as /download and /api/private/files, reachable the way the REST
  // scanner's "path traversal via URL path" check specifically probes for.
  app.get('/files/:name', (req, res) => {
    const p = path.join(__dirname, 'files', req.params.name);
    fs.readFile(p, 'utf8', (err, data) => {
      if (err) return res.status(404).json({ error: `cannot read ${p}` });
      res.type('text/plain').send(data);
    });
  });
};