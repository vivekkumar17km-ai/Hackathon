# SourceMark — Digital Content Provenance & Authenticity Platform

SourceMark is an enterprise-grade digital content provenance and tamper-detection platform built for digital forensics, media integrity verification, and evidentiary audit compliance.

![Backend](https://img.shields.io/badge/Backend-FastAPI%20%2B%20SQLite-009688?style=for-the-badge)
![Crypto](https://img.shields.io/badge/Crypto-Ed25519%20%2B%20SHA--256-00F0FF?style=for-the-badge)
![Frontend](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-61DAFB?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-19%20Passing-10B981?style=for-the-badge)

---

## Default Demo & Judge Credentials

| Account | Email | Password | Role |
|---------|-------|----------|------|
| **Chief Investigator (Admin)** | `admin@sourcemark.io` | `Admin@1234` | admin |
| **Forensic Analyst** | `analyst@sourcemark.io` | `Demo@1234` | analyst |

*Tip: You can also click the quick one-tap demo login buttons directly on the `/login` screen or skip authentication entirely to operate in unauthenticated inspection mode.*


---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Browser (React + Vite)                      │
│  • SHA-256 computed client-side via Web Crypto API               │
│  • Ed25519 signing via TweetNaCl (private key stays in memory)   │
│  • Falls back to localStorage demo mode when backend is offline  │
└───────────────────────┬─────────────────────────────────────────┘
                        │ JSON / multipart over HTTP
┌───────────────────────▼─────────────────────────────────────────┐
│                Python FastAPI Backend (:8000)                     │
│  • Real Ed25519 signature verification (cryptography library)    │
│  • SHA-256 fingerprint validation                                │
│  • Hash-linked audit ledger with server-side chain validation    │
│  • Pydantic request/response validation                          │
│  • CORS configured via environment variable                      │
└───────────────────────┬─────────────────────────────────────────┘
                        │ Parameterized SQL (WAL mode)
┌───────────────────────▼─────────────────────────────────────────┐
│                   SQLite (sourcemark.db)                         │
│  • sources — registered file provenance records                  │
│  • verification_events — every verify attempt                    │
│  • ledger_blocks — tamper-evident hash-linked chain              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick-Start

### Prerequisites

| Tool | Minimum Version |
|------|-----------------|
| Python | 3.10+ |
| Node.js | 18+ |
| npm | 9+ |

### 1 — Install Python Dependencies

```bash
cd Hackathon
pip install fastapi uvicorn pydantic cryptography python-multipart pytest httpx
```

Or install from the full requirement set:

```bash
pip install "fastapi>=0.100" "uvicorn[standard]>=0.23" "pydantic>=2.0" \
            "cryptography>=41.0" "python-multipart>=0.0.6" \
            "pytest>=7.0" "httpx>=0.24"
```

### 2 — Install Frontend Dependencies

```bash
cd Hackathon
npm install
```

### 3 — Start the Backend

> **Important:** Run uvicorn from the `Hackathon/` directory (one level above `backend/`), not from inside `backend/`. The module path must be `backend.main:app`.

```bash
cd Hackathon
uvicorn backend.main:app --reload --port 8000
```

The API will be available at `http://127.0.0.1:8000`.  
Interactive docs: `http://127.0.0.1:8000/docs`

The SQLite database (`sourcemark.db`) is created automatically on first startup, together with three demo sources seeded with mathematically valid Ed25519 signatures.

### 4 — Start the Frontend

In a separate terminal:

```bash
cd Hackathon
npm run dev
```

The UI launches at `http://localhost:5173`.

When the backend is running, the top navigation pill shows **API Connected** and all data is read from the live database. When offline, the UI falls back to localStorage demo mode automatically.

---

## Environment Variables

Copy `backend/.env.example` to `backend/.env` and adjust as needed. The backend reads these variables at startup via `backend/config.py`.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_PATH` | `./sourcemark.db` | Path to the SQLite file (relative to the working directory where uvicorn runs) |
| `MAX_UPLOAD_SIZE_MB` | `50` | Maximum file size accepted by `/api/compare` |
| `CORS_ORIGINS` | `http://localhost:5173,...` | Comma-separated list of allowed frontend origins |
| `ENVIRONMENT` | `development` | Runtime environment label |

Example:

```bash
# Windows PowerShell
$env:DATABASE_PATH = "C:\data\sourcemark.db"
$env:MAX_UPLOAD_SIZE_MB = "100"
$env:CORS_ORIGINS = "http://localhost:5173,http://localhost:3000"
uvicorn backend.main:app --reload --port 8000
```

---

## API Reference

All endpoints are prefixed with `/api`.

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/health` | Service health, version, and runtime telemetry |
| `POST` | `/api/register` | Register a new source with Ed25519 signature verification |
| `POST` | `/api/verify` | Verify a file fingerprint against the registered record |
| `POST` | `/api/compare` | Compare two files — SHA-256 diff + unified text diff |
| `GET`  | `/api/source/{id}` | Retrieve registered source metadata |
| `GET`  | `/api/history/{id}` | Full provenance lifecycle with chronological events |
| `GET`  | `/api/sources` | Paginated list of all registered sources |
| `GET`  | `/api/dashboard` | Live metrics from real database queries |
| `GET`  | `/api/ledger` | Full audit ledger block sequence |
| `GET`  | `/api/ledger/validate` | Server-side hash-chain validation of the full ledger |

### POST /api/register — Payload

```json
{
  "sourceId": "SRC-12345",
  "filename": "photo.jpg",
  "sha256": "e3b0c44298fc1c149...",
  "publicKey": "6ad4e0c582f2b4f9...",
  "signature": "abc123...",
  "fileType": "image/jpeg",
  "fileSize": 204800,
  "author": "Jane Doe",
  "description": "Original photograph"
}
```

The backend **verifies the Ed25519 signature** before accepting registration. The signing message is the raw 32 bytes of the SHA-256 hash (matching the TweetNaCl browser format). Registrations with invalid signatures are rejected with HTTP 400.

### POST /api/verify — Payload

```json
{
  "sourceId": "SRC-12345",
  "sha256": "e3b0c44298fc1c149...",
  "publicKey": "6ad4e0c582f2b4f9...",
  "signature": "abc123..."
}
```

Returns one of four `verdict` states:
- `ORIGINAL` — fingerprint matches; signature valid against the registered public key
- `EDITED` — fingerprint does not match the registered record
- `UNKNOWN` — source ID not found in the database
- `INVALID_SIGNATURE` — fingerprint matches but signature check fails

### POST /api/compare — Form Data

Accepts two files. Supported field name pairs: `file1`/`file2`, `fileA`/`fileB`, or `original`/`modified`.

Returns SHA-256 fingerprints for both files, byte-identity result, file sizes, and — for text files — a unified diff.

---

## Running Tests

Tests use an isolated in-memory-style temporary SQLite database. They do not touch `sourcemark.db`.

```bash
cd Hackathon
python -m pytest backend/tests -v
```

### Test Coverage (14 Tests)

| # | Test |
|---|------|
| 1 | Successful registration with a valid Ed25519 signature |
| 2 | Rejection of an invalid Ed25519 signature |
| 3 | Rejection of malformed hashes and public keys |
| 4 | Successful verification of an unchanged fingerprint |
| 5 | Detection of a changed fingerprint (EDITED verdict) |
| 6 | Unknown-source handling (UNKNOWN verdict) |
| 7 | File comparison for identical and different files |
| 8 | Text diff generation |
| 9 | Provenance-history retrieval with real persisted events |
| 10 | Ledger validation for a fully valid chain |
| 11 | Detection of a tampered block payload |
| 12 | Detection of a broken previous-hash link |
| 13 | Data persistence across simulated backend restarts |
| 14 | API error handling and upload-size limits |

---

## Frontend Build (Production)

```bash
cd Hackathon
npm run build
```

Output is written to `dist/`. A chunk-size warning for `recharts` may appear — this is informational only and does not affect functionality.

---

## Backend Module Reference

| Module | Responsibility |
|--------|---------------|
| `backend/config.py` | Environment variable settings with safe defaults |
| `backend/database.py` | SQLite init, schema migrations, seed data, connection management |
| `backend/schemas.py` | Pydantic request/response models with field validation |
| `backend/crypto_utils.py` | Real Ed25519 verification, SHA-256, key parsing, canonical JSON |
| `backend/ledger.py` | Block hash computation and full chain validation |
| `backend/service.py` | Business logic: register, verify, compare, history, dashboard |
| `backend/main.py` | FastAPI app, CORS, global error handler, all route handlers |
| `backend/tests/conftest.py` | pytest fixtures: isolated DB, TestClient, fresh keypairs |
| `backend/tests/test_backend.py` | 14 automated integration tests |

---

## Cryptography Details

### Signing Format

| Layer | Implementation |
|-------|---------------|
| Hashing | SHA-256 via browser Web Crypto API (client-side) |
| Signing message | Raw 32-byte SHA-256 digest (not hex string) |
| Signature algorithm | Ed25519 (TweetNaCl in browser, `cryptography` library on backend) |
| Key format | 32-byte raw hex encoding for both public key and signature seed |

The signing message is **32 raw bytes** (not the hex string). The backend verifies using `bytes.fromhex(sha256_hex)` as the message, matching the TweetNaCl `sign.detached` format exactly.

### Block Hash Format

```
SHA-256( "{id}|{block_number}|{block_type}|{prev_hash}|{timestamp}|{canonical_json(payload)}" )
```

Where `canonical_json` is JSON with sorted keys and no extra whitespace. Ledger validation recomputes this hash for every block and checks parent-child `prev_hash` linkage.

---

## Limitations & Security Notes

### Hash-Linked Ledger

The audit ledger is a **locally-stored hash chain**, not a distributed blockchain. A database administrator with write access to the entire SQLite file could reconstruct a coherent chain. The ledger provides strong tamper evidence under normal operating conditions but does **not** provide the cryptographic guarantees of an externally-anchored, decentralised blockchain.

### Public Key Trust

The backend only trusts the public key that was registered with the source. A public key supplied alongside an uploaded file during verification is used only to perform the signature check against the registered key — it does not override or replace the registered key.

### Private Keys

Private keys are generated in browser memory and never transmitted to the backend, stored in the database, or included in any API response. They exist only in the JavaScript runtime for the duration of the signing operation.

### File Integrity vs. Content Authenticity

Cryptographic verification confirms **file integrity** (the bits have not changed since registration) and **signing key continuity** (the same key signed this file). It does **not** prove that the content depicts a genuine real-world event or that the original file was not itself fabricated.

### Demo / Simulation Mode

The frontend falls back to localStorage-based demo mode automatically when the backend is unreachable. Demo mode preserves full UI functionality for offline demonstration. All data in demo mode is synthetic and clearly labelled.

---

## Project Structure

```
Hackathon/
├── backend/
│   ├── __init__.py
│   ├── .env.example          # Environment variable template
│   ├── config.py             # Settings loaded from env vars
│   ├── crypto_utils.py       # Ed25519 verification, SHA-256, canonical JSON
│   ├── database.py           # SQLite init, migrations, seed data
│   ├── ledger.py             # Block hash computation and chain validation
│   ├── main.py               # FastAPI app and all route handlers
│   ├── schemas.py            # Pydantic request/response models
│   ├── service.py            # Business logic layer
│   └── tests/
│       ├── conftest.py       # pytest fixtures
│       └── test_backend.py   # 14 automated integration tests
├── src/
│   ├── pages/
│   │   ├── Overview.jsx      # Dashboard (live DB metrics)
│   │   ├── Register.jsx      # Source registration workflow
│   │   ├── Verify.jsx        # File verification workflow
│   │   ├── Compare.jsx       # File comparison with server SHA-256
│   │   ├── ProvenanceHistory.jsx  # Provenance timeline (live backend events)
│   │   ├── AuditLedger.jsx   # Block chain viewer
│   │   ├── Reports.jsx       # Forensic report generation
│   │   └── Settings.jsx      # Key management and backend config
│   ├── services/
│   │   ├── api.js            # All backend HTTP calls
│   │   ├── crypto.js         # Browser-side Ed25519 + SHA-256
│   │   └── ledgerStorage.js  # localStorage fallback for demo mode
│   └── components/
│       ├── common/           # Shared UI components (StatCard, StatusBadge, …)
│       └── layout/           # AppLayout, Sidebar, TopNav
├── index.html
├── package.json
├── vite.config.js
└── README.md
```
