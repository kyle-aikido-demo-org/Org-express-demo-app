# DAST Demo App
Intentionally vulnerable Express app. Use only for demos; no real data/secrets.

## Run locally
    npm install && npm start   # http://localhost:8080

## Deploy to Cloud Run
    gcloud run deploy dast-demo --source . --region us-central1 --allow-unauthenticated

## Vulnerable endpoints
| Endpoint | Issue |
|---|---|
| GET /search?q= | Reflected XSS: `<script>alert(1)</script>` |
| GET /api/products?name= | SQLi: `' OR '1'='1`, `'` (error-based) |
| POST /login | SQLi auth bypass: user `admin' --` |
| GET /download?file= | Path traversal: `../server.js` |
| GET /redirect?url= | Open redirect: `https://example.com` |
| GET /api/users/:id | IDOR, no auth, leaks passwords, SQLi |
| GET /error | Stack trace disclosure |
| all | No CSP/HSTS/X-Frame-Options, CORS `*`, X-Powered-By, insecure cookie |
| GET /api/health | Clean endpoint |
