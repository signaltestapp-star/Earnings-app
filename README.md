# Simple Wallet App

This is a small Flask-based local wallet server + single-page UI for testing and prototyping.
**Not production-ready.** See security notes below.

## What it includes
- REST API for wallet create / deposit / withdraw / transfer / txs
- Admin JWT-based login and admin edit balance
- Simple SPA UI (served at `/`)
- SQLite persistence (wallets.db)
- Dockerfile + docker-compose for local run

## Quick start (local, without Docker)
1. Create a Python 3.11 venv:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Run:
   ```bash
   export WALLET_JWT_SECRET="your-jwt-secret"
   export WALLET_ADMIN_USER="admin"
   export WALLET_ADMIN_PASS="choose-a-strong-pass"
   python app.py
   ```
3. Open your browser at `http://127.0.0.1:5000`

## Quick start (Docker)
```bash
docker compose up --build
```
Then open `http://localhost:5000`.

## Default admin credentials (change before using)
- username: `admin`
- password: `adminpass`
- JWT secret: `change-me-jwt-secret`

## Security notes
- Do not use this to hold real funds.
- Secrets are stored in plaintext in the DB; rotate and secure them for real deployments.
- Add HTTPS, proper auth, rate limiting, auditing, and use a production DB for real usage.

## Files
- `app.py` - Flask server & API
- `templates/index.html` - UI
- `static/app.js` - UI JS
- `Dockerfile`, `docker-compose.yml`, `requirements.txt`

## Need hosting?
I can help you deploy this to a platform (Railway, Render, Fly, Heroku-like), or produce a Docker image. Tell me which provider you'd like and I'll give step-by-step deployment instructions.
