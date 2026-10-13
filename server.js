// INTENTIONALLY VULNERABLE demo app for DAST testing. Never deploy with real data.
const express = require('express');
const cookieParser = require('cookie-parser');
const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
// VULN: wide-open CORS, no security headers (CSP, X-Frame-Options, etc.)
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Credentials', 'true');
  res.set('X-Powered-By', 'Express'); // VULN: tech disclosure
  next();
});

let db;
async function setupDb() {
  const SQL = await initSqlJs();
  db = new SQL.Database();
  db.run(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
          CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
          INSERT INTO users VALUES (1,'admin','s3cr3t-admin-pw','admin'),(2,'alice','alicepw','user'),(3,'bob','bobpw','user');
          INSERT INTO products VALUES (1,'Widget',9.99),(2,'Gadget',19.99),(3,'Gizmo',29.99);`);
}
const rows = (sql) => {
  const r = db.exec(sql);
  if (!r.length) return [];
  const { columns, values } = r[0];
  return values.map((v) => Object.fromEntries(v.map((x, i) => [columns[i], x])));
};

app.get('/', (req, res) => {
  res.send(`<!doctype html><html><head><title>DAST Demo App</title></head><body>
  <h1>DAST Demo App</h1><p>Intentionally vulnerable. Do not use in production.</p>
  <ul>
    <li><a href="/search?q=widget">/search?q=</a> (reflected XSS)</li>
    <li><a href="/api/products?name=Widget">/api/products?name=</a> (SQL injection)</li>
    <li><a href="/download?file=readme.txt">/download?file=</a> (path traversal)</li>
    <li><a href="/redirect?url=/">/redirect?url=</a> (open redirect)</li>
    <li><a href="/login">/login</a> (SQLi auth bypass, weak cookie)</li>
    <li><a href="/error">/error</a> (stack trace leak)</li>
    <li><a href="/api/health">/api/health</a> (safe)</li>
    <li><a href="/api/users/1">/api/users/:id</a> (IDOR, no auth)</li>
  </ul></body></html>`);
});

// Safe endpoint
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// VULN: Reflected XSS - unescaped input in HTML
app.get('/search', (req, res) => {
  res.send(`<html><body><h2>Results for: ${req.query.q || ''}</h2><p>No results found.</p></body></html>`);
});

// VULN: SQL injection (string concatenation), error messages returned
app.get('/api/products', (req, res) => {
  const name = req.query.name || '';
  try {
    res.json(rows(`SELECT id, name, price FROM products WHERE name LIKE '%${name}%'`));
  } catch (e) {
    res.status(500).json({ error: e.message, query: `name=${name}` });
  }
});

// VULN: SQLi auth bypass + insecure cookie (no HttpOnly/Secure/SameSite)
app.get('/login', (req, res) => {
  res.send(`<form method="POST" action="/login">
    <input name="username" placeholder="username"><input name="password" type="password" placeholder="password">
    <button>Login</button></form>`);
});
app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  try {
    const u = rows(`SELECT * FROM users WHERE username='${username}' AND password='${password}'`)[0];
    if (!u) return res.status(401).send('Invalid credentials');
    res.cookie('session', Buffer.from(`${u.id}:${u.role}`).toString('base64'));
    res.send(`Welcome ${u.username}!`); // VULN: also XSS-able via stored username
  } catch (e) {
    res.status(500).send(e.stack);
  }
});

// VULN: Path traversal
app.get('/download', (req, res) => {
  const file = req.query.file || 'readme.txt';
  const p = path.join(__dirname, 'files', file);
  fs.readFile(p, 'utf8', (err, data) => {
    if (err) return res.status(404).send(`Cannot read ${p}`);
    res.type('text/plain').send(data);
  });
});

// VULN: Open redirect
app.get('/redirect', (req, res) => res.redirect(req.query.url || '/'));

// VULN: IDOR / missing auth, exposes password field
app.get('/api/users/:id', (req, res) => {
  const id = req.params.id;
  try {
    const u = rows(`SELECT * FROM users WHERE id=${id}`)[0];
    u ? res.json(u) : res.status(404).json({ error: 'not found' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// VULN: Verbose error / stack trace disclosure
app.get('/error', (req, res, next) => next(new Error('Simulated failure in /error handler')));
app.use((err, req, res, next) => res.status(500).send(`<pre>${err.stack}</pre>`));

setupDb().then(() => app.listen(PORT, () => console.log(`Listening on ${PORT}`)));
