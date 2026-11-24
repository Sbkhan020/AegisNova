# AegisNova — Cyber Defense Platform (Final MVP)

A lightweight, locally runnable full-stack cybersecurity awareness and defensive analysis platform.

## Included
- React + TypeScript + Vite dashboard
- FastAPI backend, SQLAlchemy ORM, SQLite by default (PostgreSQL supported through `DATABASE_URL`)
- Registration/login, Argon2 password hashing, signed JWT access tokens, role-based access (`user` / `admin`)
- URL risk heuristics (does **not** visit/fetch submitted URLs)
- Phishing email text analysis
- File metadata + SHA-256 hashing (file is streamed, never executed or saved)
- Authorized network scope/CIDR validation and passive IP-range summary (no port scanning)
- Scan history, JSON reports, dashboard statistics, admin user overview
- Security headers, CORS allowlist, request-size limits, validation, login/scan rate limits
- Rule-based Nova explanations; no fake AI claims or invented evidence

## Requirements
- Python 3.10+
- Node.js 20+
- Windows, Linux, or macOS

## Run on Windows (PowerShell)
Terminal 1:
```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```
Terminal 2:
```powershell
cd frontend
npm install
npm run dev
```
Open http://localhost:5173. API docs: http://127.0.0.1:8000/docs

## First admin account
Register normally, then promote your account using the documented one-time bootstrap setting:
1. Stop the backend.
2. In `backend/.env`, set `BOOTSTRAP_ADMIN_EMAIL` to the exact email you registered with.
3. Start backend again. That account is promoted to admin at startup.
4. Remove `BOOTSTRAP_ADMIN_EMAIL` from `.env` and restart. Never leave bootstrap enabled on a public deployment.

## PostgreSQL
SQLite is the default for easy local setup. To use PostgreSQL, install a suitable driver (e.g. `psycopg[binary]`) and set `DATABASE_URL` in `.env` to a PostgreSQL SQLAlchemy URL. Back up your database before migrations/schema changes.

## Security and limitations — read before deployment
This is a functional academic MVP, **not a certified or production-hardened security product**. Use HTTPS, a managed secret store, PostgreSQL, database migrations, centralized logs, backups, monitoring, dependency scanning, penetration testing, and a reviewed deployment configuration before exposing it publicly. JWTs are held in browser memory (not localStorage); refresh-token rotation, email verification, password reset, MFA, and external identity providers are not implemented. The in-memory rate limiter is per-process and is not a substitute for a reverse-proxy/WAF limiter. SQLite is intended for local development.

Scanners are deliberately safe and passive: URL analysis never makes outbound requests (SSRF protection by design); file analysis never executes files or uploads them to third parties; network analysis validates the scope only and does not probe hosts/ports. Do not scan systems without explicit written authorization. Results are heuristic indicators, not a verdict or guarantee that a resource is safe/malicious.

## Project structure
```
backend/app/   FastAPI API, auth, models, analyzers
frontend/src/  React application and styles
```

## Run analyzer unit tests
From the backend directory after installing dependencies:
```powershell
py -m unittest discover -s tests
```
