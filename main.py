"""
SourceMark Backend API v2 — FastAPI
Full-stack Digital Content Provenance & Forensic Intelligence Platform
"""

import datetime
import logging
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
import io

from .config import settings
from .database import get_db, init_db
from .schemas import (
    RegisterPayload, VerifyPayload, VerifyResponse, CompareResponse,
    HistoryResponse, DashboardResponse, LedgerBlockResponse,
    LedgerValidateResponse, HealthResponse, SourceListResponse,
    UserRegisterPayload, UserLoginPayload, TokenResponse, UserResponse,
    CaseCreatePayload, CaseAddFilePayload, CaseResponse,
    BatchVerifyPayload,
)
from .service import (
    register_source, verify_source, compare_files_data,
    get_source_history, get_dashboard_metrics,
    row_to_source_dict, row_to_block_dict,
    create_user, authenticate_user,
    create_case, get_cases, get_case_detail, add_file_to_case,
    generate_qr_code_bytes, generate_pdf_report,
    batch_verify, get_lan_ip, get_qr_verification_url,
)
from .ledger import validate_chain
from .auth import (
    create_access_token, get_current_user, get_current_user_optional, require_admin
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sourcemark.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing SourceMark persistent database...")
    init_db()
    logger.info("SourceMark v2 backend ready.")
    yield
    logger.info("SourceMark backend shutting down.")


app = FastAPI(
    title=settings.API_TITLE,
    description=settings.API_DESCRIPTION,
    version=settings.API_VERSION,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    logger.error(f"Unhandled error {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "An internal server error occurred."})


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/health", response_model=HealthResponse)
def health_check():
    return {
        "status": "healthy",
        "service": "SourceMark Forensic Intelligence Engine",
        "version": settings.API_VERSION,
        "database": "SQLite (persistent, WAL)",
        "curve": "Ed25519",
        "hasher": "SHA-256",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


# ─────────────────────────────────────────────────────────────────────────────
# Authentication
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/auth/register", response_model=TokenResponse)
def auth_register(payload: UserRegisterPayload):
    """Register a new user account and return JWT token."""
    with get_db() as conn:
        user = create_user(
            conn,
            username=payload.username,
            email=payload.email,
            password_plain=payload.password,
            full_name=payload.fullName or "",
            organization=payload.organization or "",
        )
        token = create_access_token(user["id"], user["email"], user["role"])
        return {"access_token": token, "token_type": "bearer", "user": user}


@app.post("/api/auth/login", response_model=TokenResponse)
def auth_login(payload: UserLoginPayload):
    """Authenticate with email/username + password, return JWT."""
    with get_db() as conn:
        user = authenticate_user(conn, payload.email, payload.password)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials. Please check your email/username and password."
            )
        token = create_access_token(user["id"], user["email"], user["role"])
        return {"access_token": token, "token_type": "bearer", "user": user}


@app.get("/api/auth/me", response_model=UserResponse)
def auth_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Return the currently authenticated user's profile."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?;", (current_user["id"],))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User profile not found.")
        from .service import row_to_user_dict
        return row_to_user_dict(row)


@app.get("/api/auth/users", response_model=List[UserResponse])
def list_users(current_user: Dict[str, Any] = Depends(require_admin)):
    """Admin: list all registered users."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY created_at DESC;")
        from .service import row_to_user_dict
        return [row_to_user_dict(r) for r in cursor.fetchall()]


# ─────────────────────────────────────────────────────────────────────────────
# Source Registration & Verification
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/register")
def register_file(
    payload: RegisterPayload,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Register a new digital source with Ed25519 cryptographic validation."""
    user_id = current_user["id"] if current_user else None
    with get_db() as conn:
        return register_source(conn, payload, user_id=user_id)


@app.post("/api/verify", response_model=VerifyResponse)
def verify_file(
    payload: VerifyPayload,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Verify file authenticity. Returns ORIGINAL, EDITED, UNKNOWN, or INVALID_SIGNATURE."""
    user_id = current_user["id"] if current_user else None
    with get_db() as conn:
        return verify_source(conn, payload, user_id=user_id)


@app.post("/api/verify/batch")
def verify_batch(
    payload: BatchVerifyPayload,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Batch verify up to 50 files. Returns array of verification results."""
    user_id = current_user["id"] if current_user else None
    items = [{"sha256": item.sha256, "sourceId": item.sourceId, "fileName": item.fileName}
             for item in payload.items]
    with get_db() as conn:
        results = batch_verify(conn, items, user_id=user_id)
    verified = sum(1 for r in results if r.get("verdict") == "ORIGINAL")
    modified = sum(1 for r in results if r.get("verdict") == "EDITED")
    unknown = sum(1 for r in results if r.get("verdict") == "UNKNOWN")
    return {
        "results": results,
        "total": len(results),
        "totalProcessed": len(results),
        "verifiedCount": verified,
        "modifiedCount": modified,
        "unknownCount": unknown
    }


# ─────────────────────────────────────────────────────────────────────────────
# File Comparison
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/compare", response_model=CompareResponse)
async def compare_files(
    file1: Optional[UploadFile] = File(None),
    file2: Optional[UploadFile] = File(None),
    fileA: Optional[UploadFile] = File(None),
    fileB: Optional[UploadFile] = File(None),
    original: Optional[UploadFile] = File(None),
    modified: Optional[UploadFile] = File(None),
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Compare two files — SHA-256, pixel diff for images, unified diff for text."""
    first = file1 or fileA or original
    second = file2 or fileB or modified

    if not first or not second:
        raise HTTPException(status_code=400,
                            detail="Two files are required (file1/file2, fileA/fileB, or original/modified).")

    user_id = current_user["id"] if current_user else None
    with get_db() as conn:
        result = await compare_files_data(first, second, user_id=user_id, conn=conn)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Source Queries
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/source/{source_id}")
def get_source(source_id: str):
    """Retrieve registered source metadata by Source ID."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sources WHERE UPPER(id) = UPPER(?);", (source_id.strip(),))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Source record '{source_id}' not found.")
        return row_to_source_dict(row)


@app.get("/api/history/{source_id}", response_model=HistoryResponse)
def get_history(source_id: str):
    """Full provenance lifecycle with chronological events and ledger anchors."""
    with get_db() as conn:
        return get_source_history(conn, source_id)


@app.get("/api/sources", response_model=SourceListResponse)
def get_sources(
    limit: int = 100,
    offset: int = 0,
    search: Optional[str] = None,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Paginated list of registered sources with optional search."""
    with get_db() as conn:
        cursor = conn.cursor()
        if search:
            pattern = f"%{search}%"
            cursor.execute("SELECT COUNT(*) FROM sources WHERE id LIKE ? OR file_name LIKE ? OR creator LIKE ?;",
                           (pattern, pattern, pattern))
            total = cursor.fetchone()[0]
            cursor.execute(
                "SELECT * FROM sources WHERE id LIKE ? OR file_name LIKE ? OR creator LIKE ? ORDER BY registered_at DESC LIMIT ? OFFSET ?;",
                (pattern, pattern, pattern, limit, offset)
            )
        else:
            cursor.execute("SELECT COUNT(*) FROM sources;")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT * FROM sources ORDER BY registered_at DESC LIMIT ? OFFSET ?;", (limit, offset))

        sources = [row_to_source_dict(r) for r in cursor.fetchall()]
        return {"total": total, "sources": sources}


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/dashboard", response_model=DashboardResponse)
def get_dashboard(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """Live database-driven forensic telemetry and integrity metrics."""
    with get_db() as conn:
        return get_dashboard_metrics(conn)


# ─────────────────────────────────────────────────────────────────────────────
# Audit Ledger
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/ledger", response_model=List[LedgerBlockResponse])
def get_ledger():
    """Full audit ledger block sequence."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ledger_blocks ORDER BY block_number ASC;")
        return [row_to_block_dict(r) for r in cursor.fetchall()]


@app.get("/api/ledger/validate", response_model=LedgerValidateResponse)
def validate_ledger():
    """Full server-side hash-chain validation of the audit ledger."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ledger_blocks ORDER BY block_number ASC;")
        blocks = [row_to_block_dict(r) for r in cursor.fetchall()]
        return validate_chain(blocks)


# ─────────────────────────────────────────────────────────────────────────────
# QR Code (Mobile-Scannable Evidence Anchoring)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/qr/{source_id}")
def get_qr_code(
    source_id: str,
    base_url: Optional[str] = None,
    download: bool = False
):
    """Generate a high-resolution, mobile-scannable QR code PNG linking to verification page."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM sources WHERE UPPER(id) = UPPER(?);", (source_id.strip(),))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Source '{source_id}' not found.")
        canonical_id = row["id"]

    verify_url = get_qr_verification_url(canonical_id, base_url)
    png_bytes = generate_qr_code_bytes(canonical_id, base_url)
    headers = {
        "Content-Type": "image/png",
        "X-Verification-Url": verify_url,
    }
    if download:
        headers["Content-Disposition"] = f'attachment; filename="sourcemark_qr_{canonical_id}.png"'

    return Response(content=png_bytes, media_type="image/png", headers=headers)


@app.get("/api/qr/{source_id}/info")
def get_qr_info(source_id: str, base_url: Optional[str] = None):
    """Retrieve metadata about the QR verification anchor, including the mobile-accessible URL."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, file_name, sha256 FROM sources WHERE UPPER(id) = UPPER(?);", (source_id.strip(),))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Source '{source_id}' not found.")
        canonical_id = row["id"]

    verify_url = get_qr_verification_url(canonical_id, base_url)
    return {
        "sourceId": canonical_id,
        "fileName": row["file_name"],
        "sha256": row["sha256"],
        "verificationUrl": verify_url,
        "lanIp": get_lan_ip(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# PDF Reports
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/report/{source_id}/pdf")
def download_pdf_report(
    source_id: str,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Generate and download a professional forensic PDF report for a source."""
    with get_db() as conn:
        history = get_source_history(conn, source_id)

    pdf_bytes = generate_pdf_report(
        source=history["source"],
        events=history["events"],
        blocks=history["ledgerBlocks"]
    )
    filename = f"sourcemark_report_{source_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


# ─────────────────────────────────────────────────────────────────────────────
# Investigation Cases
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/cases")
def list_cases(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """List investigation cases (own cases for analysts, all for admins)."""
    user_id = current_user["id"] if current_user else None
    role = current_user.get("role", "analyst") if current_user else "analyst"
    with get_db() as conn:
        cases = get_cases(conn, user_id=user_id, role=role)
    return {"cases": cases, "total": len(cases)}


@app.post("/api/cases", response_model=CaseResponse)
def create_new_case(
    payload: CaseCreatePayload,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Create a new investigation case."""
    user_id = current_user["id"] if current_user else None
    with get_db() as conn:
        case = create_case(conn, payload.title, payload.description or "", payload.priority or "NORMAL", user_id)
    return case


@app.get("/api/cases/{case_id}")
def get_case(case_id: str, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """Get full case details including attached files."""
    with get_db() as conn:
        return get_case_detail(conn, case_id)


@app.post("/api/cases/{case_id}/files")
def add_case_file(
    case_id: str,
    payload: CaseAddFilePayload,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Attach a registered source to an investigation case."""
    with get_db() as conn:
        return add_file_to_case(conn, case_id, payload.sourceId, payload.label or "")
