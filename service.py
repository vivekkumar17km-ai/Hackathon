"""
SourceMark Forensic Service Layer — v2
Enhanced with image forensics, document comparison, case management, QR codes, and PDF reports.
"""

import sqlite3
import json
import datetime
import uuid
import difflib
import base64
import io
import os
from typing import Dict, Any, List, Optional, Tuple
from fastapi import HTTPException, UploadFile

from .schemas import RegisterPayload, VerifyPayload
from .crypto_utils import verify_ed25519_signature, compute_sha256
from .ledger import compute_block_hash, validate_chain, GENESIS_PREV_HASH
from .config import settings

logger_name = "sourcemark.service"
import logging
logger = logging.getLogger(logger_name)


# ─────────────────────────────────────────────────────────────────────────────
# Row converters
# ─────────────────────────────────────────────────────────────────────────────

def row_to_source_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "fileName": row["file_name"],
        "fileType": row["file_type"],
        "fileSize": row["file_size"],
        "fileSizeFormatted": row["file_size_formatted"],
        "sha256": row["sha256"],
        "signature": row["signature"],
        "publicKey": row["public_key"],
        "keyId": row["key_id"],
        "creator": row["creator"],
        "creatorId": row["creator_id"],
        "category": row["category"],
        "description": row["description"],
        "sourceOrigin": row["source_origin"],
        "registeredAt": row["registered_at"],
        "status": row["status"],
        "verificationCount": row["verification_count"],
        "lastVerifiedAt": row["last_verified_at"],
        "userId": row["user_id"] if "user_id" in row.keys() else None,
    }


def row_to_block_dict(row: sqlite3.Row) -> Dict[str, Any]:
    payload = {}
    try:
        payload = json.loads(row["payload_json"])
    except Exception:
        payload = {"raw": row["payload_json"]}
    return {
        "id": row["id"],
        "blockNumber": row["block_number"],
        "type": row["type"],
        "title": row["title"],
        "timestamp": row["timestamp"],
        "prevHash": row["prev_hash"],
        "currentHash": row["current_hash"],
        "status": row["status"],
        "verified": bool(row["verified"]),
        "payload": payload
    }


def row_to_event_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "sourceId": row["source_id"],
        "fileName": row["file_name"],
        "searchedHash": row["searched_hash"],
        "verdict": row["verdict"],
        "status": row["status"],
        "message": row["message"],
        "details": row["details"],
        "hashMatch": bool(row["hash_match"]),
        "signatureValid": bool(row["signature_valid"]),
        "timestamp": row["timestamp"],
        "ledgerBlockId": row["ledger_block_id"]
    }


def row_to_user_dict(row: sqlite3.Row, include_hash: bool = False) -> Dict[str, Any]:
    d = {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"],
        "fullName": row["full_name"],
        "organization": row["organization"],
        "isActive": bool(row["is_active"]),
        "createdAt": row["created_at"],
        "lastLoginAt": row["last_login_at"],
    }
    if include_hash:
        d["passwordHash"] = row["password_hash"]
    return d


def row_to_case_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "status": row["status"],
        "priority": row["priority"],
        "userId": row["user_id"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
        "closedAt": row["closed_at"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Auth / User operations
# ─────────────────────────────────────────────────────────────────────────────

def create_user(conn: sqlite3.Connection, username: str, email: str, password_plain: str,
                full_name: str = "", organization: str = "", role: str = "analyst") -> Dict[str, Any]:
    from .auth import hash_password
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(?) OR LOWER(username) = LOWER(?);",
                   (email, username))
    if cursor.fetchone():
        raise HTTPException(status_code=409, detail="An account with this email or username already exists.")

    user_id = f"USR-{uuid.uuid4().hex[:8].upper()}"
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute("""
        INSERT INTO users (id, username, email, password_hash, role, full_name, organization, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?);
    """, (user_id, username.strip(), email.strip().lower(), hash_password(password_plain),
          role, full_name, organization, now))
    cursor.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
    return row_to_user_dict(cursor.fetchone())


def authenticate_user(conn: sqlite3.Connection, email_or_username: str, password_plain: str) -> Optional[Dict[str, Any]]:
    from .auth import verify_password
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE (LOWER(email) = LOWER(?) OR LOWER(username) = LOWER(?)) AND is_active = 1;",
        (email_or_username, email_or_username)
    )
    row = cursor.fetchone()
    if not row:
        return None
    user = row_to_user_dict(row, include_hash=True)
    if not verify_password(password_plain, user["passwordHash"]):
        return None
    # Update last login
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute("UPDATE users SET last_login_at = ? WHERE id = ?;", (now, user["id"]))
    user.pop("passwordHash", None)
    return user


# ─────────────────────────────────────────────────────────────────────────────
# Source registration & verification (existing, enhanced with user_id)
# ─────────────────────────────────────────────────────────────────────────────

def register_source(conn: sqlite3.Connection, payload: RegisterPayload,
                    user_id: Optional[str] = None) -> Dict[str, Any]:
    cursor = conn.cursor()

    is_valid_sig = verify_ed25519_signature(
        public_key_hex=payload.publicKey,
        signature_hex=payload.signature,
        sha256_hex=payload.sha256
    )
    if not is_valid_sig:
        raise HTTPException(
            status_code=400,
            detail="Cryptographic verification failed: the supplied Ed25519 signature does not match the fingerprint and public key."
        )

    source_id = (payload.id or f"SRC-{uuid.uuid4().hex[:5].upper()}").strip()
    cursor.execute("SELECT id FROM sources WHERE id = ?;", (source_id,))
    if cursor.fetchone():
        raise HTTPException(
            status_code=409,
            detail=f"Source ID '{source_id}' is already registered in the provenance database."
        )

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cursor.execute("""
        INSERT INTO sources (
            id, file_name, file_type, file_size, file_size_formatted,
            sha256, signature, public_key, key_id, creator, creator_id,
            category, description, source_origin, registered_at,
            status, verification_count, last_verified_at, user_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?);
    """, (
        source_id, payload.fileName, payload.fileType, payload.fileSize, payload.fileSizeFormatted,
        payload.sha256, payload.signature, payload.publicKey, payload.keyId, payload.creator, payload.creatorId,
        payload.category, payload.description, payload.sourceOrigin, now_iso,
        "ACTIVE_REGISTERED", user_id
    ))

    cursor.execute("SELECT current_hash, block_number FROM ledger_blocks ORDER BY block_number DESC LIMIT 1;")
    last_block = cursor.fetchone()
    prev_hash = last_block["current_hash"] if last_block else GENESIS_PREV_HASH
    next_num = (last_block["block_number"] + 1) if last_block else 1
    block_id = f"BLK-{next_num:04d}"

    block_payload = {
        "sourceId": source_id,
        "fileName": payload.fileName,
        "fingerprint": payload.sha256,
        "creatorId": payload.creatorId,
        "keyId": payload.keyId,
        "userId": user_id
    }
    block_type = "REGISTER"
    block_title = f"File Registration: {payload.fileName}"
    current_hash = compute_block_hash(block_id, next_num, block_type, prev_hash, now_iso, block_payload)

    cursor.execute("""
        INSERT INTO ledger_blocks (id, block_number, type, title, timestamp, prev_hash, current_hash, status, verified, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'CONFIRMED', 1, ?);
    """, (block_id, next_num, block_type, block_title, now_iso, prev_hash, current_hash, json.dumps(block_payload)))

    cursor.execute("SELECT * FROM sources WHERE id = ?;", (source_id,))
    source_dict = row_to_source_dict(cursor.fetchone())

    block_dict = {
        "id": block_id, "blockNumber": next_num, "type": block_type,
        "title": block_title, "timestamp": now_iso, "prevHash": prev_hash,
        "currentHash": current_hash, "status": "CONFIRMED", "verified": True, "payload": block_payload
    }

    return {"success": True, "data": source_dict, "block": block_dict}


def verify_source(conn: sqlite3.Connection, payload: VerifyPayload,
                  user_id: Optional[str] = None) -> Dict[str, Any]:
    cursor = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    searched_hash = payload.sha256.lower()
    searched_id = payload.sourceId.strip() if payload.sourceId else None

    matched_row = None
    if searched_id:
        cursor.execute("SELECT * FROM sources WHERE UPPER(id) = UPPER(?);", (searched_id,))
        matched_row = cursor.fetchone()
    else:
        cursor.execute("SELECT * FROM sources WHERE LOWER(sha256) = ?;", (searched_hash,))
        matched_row = cursor.fetchone()

    if not matched_row:
        block_id, block_dict = append_ledger_block(
            cursor, block_type="VERIFY_UNKNOWN", title="Verification Check: Unknown Content",
            payload={"searchedHash": searched_hash, "searchedSourceId": searched_id, "verdict": "UNKNOWN", "userId": user_id},
            status="ALERT", timestamp=now_iso
        )
        cursor.execute("""
            INSERT INTO verification_events (id, source_id, file_name, searched_hash, verdict, status, message, details,
                hash_match, signature_valid, timestamp, ledger_block_id, user_id)
            VALUES (?, NULL, ?, ?, 'UNKNOWN', 'warning', 'Unknown – No Trusted Source Found',
                    'This file fingerprint does not exist in the registered provenance registry.',
                    0, 0, ?, ?, ?);
        """, (f"VER-{uuid.uuid4().hex[:8].upper()}", payload.fileName or "inspected_asset",
              searched_hash, now_iso, block_id, user_id))
        return {
            "verdict": "UNKNOWN", "status": "warning",
            "message": "Unknown – No Trusted Source Found",
            "searchedHash": searched_hash, "searchedSourceId": searched_id,
            "details": "This file fingerprint does not exist in the registered provenance registry. No cryptographic relationship could be established.",
            "hashMatch": False, "signatureValid": False, "block": block_dict, "isDemoMode": False
        }

    matched_source = row_to_source_dict(matched_row)

    stored_sig_valid = verify_ed25519_signature(
        public_key_hex=matched_source["publicKey"],
        signature_hex=matched_source["signature"],
        sha256_hex=matched_source["sha256"]
    )

    if not stored_sig_valid:
        block_id, block_dict = append_ledger_block(
            cursor, block_type="TAMPER_DETECTED",
            title=f"Security Alert: Corrupted Master Signature for {matched_source['id']}",
            payload={"sourceId": matched_source["id"], "verdict": "INVALID_SIGNATURE",
                     "reason": "Stored Ed25519 master signature failed mathematical validation"},
            status="ALERT", timestamp=now_iso
        )
        cursor.execute("""
            INSERT INTO verification_events (id, source_id, file_name, searched_hash, verdict, status, message, details,
                hash_match, signature_valid, timestamp, ledger_block_id, user_id)
            VALUES (?, ?, ?, ?, 'INVALID_SIGNATURE', 'danger', 'Invalid Signature Detected',
                    'The registered master signature failed mathematical Ed25519 verification.',
                    0, 0, ?, ?, ?);
        """, (f"VER-{uuid.uuid4().hex[:8].upper()}", matched_source["id"],
              payload.fileName, searched_hash, now_iso, block_id, user_id))
        return {
            "verdict": "INVALID_SIGNATURE", "status": "danger",
            "message": "Invalid Signature – Provenance Integrity Compromised",
            "source": matched_source,
            "details": "The registered master record contains an invalid cryptographic signature.",
            "hashMatch": (matched_source["sha256"].lower() == searched_hash),
            "signatureValid": False, "block": block_dict, "isDemoMode": False
        }

    is_hash_match = (matched_source["sha256"].lower() == searched_hash)

    if is_hash_match:
        new_count = matched_source["verificationCount"] + 1
        cursor.execute("UPDATE sources SET verification_count = ?, last_verified_at = ? WHERE id = ?;",
                       (new_count, now_iso, matched_source["id"]))
        matched_source["verificationCount"] = new_count
        matched_source["lastVerifiedAt"] = now_iso

        block_id, block_dict = append_ledger_block(
            cursor, block_type="VERIFY_ORIGINAL",
            title=f"Integrity Verified: {matched_source['fileName']}",
            payload={"sourceId": matched_source["id"], "fileName": matched_source["fileName"],
                     "hash": searched_hash, "signatureValid": True, "verdict": "ORIGINAL", "userId": user_id},
            status="CONFIRMED", timestamp=now_iso
        )
        cursor.execute("""
            INSERT INTO verification_events (id, source_id, file_name, searched_hash, verdict, status, message, details,
                hash_match, signature_valid, timestamp, ledger_block_id, user_id)
            VALUES (?, ?, ?, ?, 'ORIGINAL', 'success', 'Original – Cryptographically Verified',
                    'The uploaded file bitstream matches the registered master fingerprint.',
                    1, 1, ?, ?, ?);
        """, (f"VER-{uuid.uuid4().hex[:8].upper()}", matched_source["id"],
              payload.fileName, searched_hash, now_iso, block_id, user_id))
        return {
            "verdict": "ORIGINAL", "status": "success",
            "message": "Original – Cryptographically Verified",
            "source": matched_source, "signatureValid": True, "hashMatch": True,
            "details": "The uploaded file bitstream matches the registered master fingerprint with a mathematically valid Ed25519 digital signature.",
            "block": block_dict, "isDemoMode": False
        }
    else:
        block_id, block_dict = append_ledger_block(
            cursor, block_type="TAMPER_DETECTED",
            title=f"Tamper Alert: Modified File for {matched_source['id']}",
            payload={"sourceId": matched_source["id"], "originalHash": matched_source["sha256"],
                     "uploadedHash": searched_hash, "verdict": "EDITED", "userId": user_id},
            status="ALERT", timestamp=now_iso
        )
        cursor.execute("""
            INSERT INTO verification_events (id, source_id, file_name, searched_hash, verdict, status, message, details,
                hash_match, signature_valid, timestamp, ledger_block_id, user_id)
            VALUES (?, ?, ?, ?, 'EDITED', 'danger', 'Edited – Content Difference Detected', ?, 0, 0, ?, ?, ?);
        """, (f"VER-{uuid.uuid4().hex[:8].upper()}", matched_source["id"], payload.fileName, searched_hash,
              f"The submitted file references Source ID {matched_source['id']} but has a modified binary fingerprint.",
              now_iso, block_id, user_id))
        return {
            "verdict": "EDITED", "status": "danger",
            "message": "Edited – Content Difference Detected",
            "source": matched_source, "originalHash": matched_source["sha256"],
            "uploadedHash": searched_hash, "signatureValid": False, "hashMatch": False,
            "details": f"The submitted file references Source ID {matched_source['id']} but has a modified binary fingerprint.",
            "block": block_dict, "isDemoMode": False
        }


def append_ledger_block(cursor: sqlite3.Cursor, block_type: str, title: str,
                        payload: Dict[str, Any], status: str = "CONFIRMED",
                        timestamp: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    now_iso = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute("SELECT current_hash, block_number FROM ledger_blocks ORDER BY block_number DESC LIMIT 1;")
    last_block = cursor.fetchone()
    prev_hash = last_block["current_hash"] if last_block else GENESIS_PREV_HASH
    next_num = (last_block["block_number"] + 1) if last_block else 1
    block_id = f"BLK-{next_num:04d}"

    current_hash = compute_block_hash(block_id, next_num, block_type, prev_hash, now_iso, payload)
    cursor.execute("""
        INSERT INTO ledger_blocks (id, block_number, type, title, timestamp, prev_hash, current_hash, status, verified, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?);
    """, (block_id, next_num, block_type, title, now_iso, prev_hash, current_hash, status, json.dumps(payload)))

    return block_id, {
        "id": block_id, "blockNumber": next_num, "type": block_type, "title": title,
        "timestamp": now_iso, "prevHash": prev_hash, "currentHash": current_hash,
        "status": status, "verified": True, "payload": payload
    }


# ─────────────────────────────────────────────────────────────────────────────
# Advanced File Comparison
# ─────────────────────────────────────────────────────────────────────────────

async def compare_files_data(file_a: UploadFile, file_b: UploadFile,
                             user_id: Optional[str] = None,
                             conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    content_a = await file_a.read()
    content_b = await file_b.read()

    max_size = settings.MAX_UPLOAD_SIZE_BYTES
    if len(content_a) > max_size or len(content_b) > max_size:
        raise HTTPException(status_code=413,
                            detail=f"Uploaded file exceeds maximum allowed threshold of {settings.MAX_UPLOAD_SIZE_MB}MB.")

    hash_a = compute_sha256(content_a)
    hash_b = compute_sha256(content_b)
    identical = (content_a == content_b)

    fname_a = file_a.filename or "fileA"
    fname_b = file_b.filename or "fileB"
    mime_a = file_a.content_type or "application/octet-stream"
    mime_b = file_b.content_type or "application/octet-stream"

    result: Dict[str, Any] = {
        "identical": identical,
        "sha256A": hash_a,
        "sha256B": hash_b,
        "fileNameA": fname_a,
        "fileNameB": fname_b,
        "fileSizeA": len(content_a),
        "fileSizeB": len(content_b),
        "sizeDiffBytes": len(content_b) - len(content_a),
        "sizeDiffPercent": round(((len(content_b) - len(content_a)) / max(len(content_a), 1)) * 100, 2),
        "fileTypeA": mime_a,
        "fileTypeB": mime_b,
        "isText": False,
        "isImage": False,
        "diff": None,
        "diffStats": None,
        "imageComparison": None,
        "metadataDiff": None,
        "disclaimer": (
            "Forensic Protocol Notice: Bitstream differences establish that the two files are not cryptographically "
            "identical. However, visual or byte differences alone do not prove malicious manipulation or hostile intent "
            "without contextual human investigation and verified chain of custody."
        ),
    }

    # ── Image comparison ───────────────────────────────────────────────────────
    image_exts = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tiff", ".tif"}
    ext_a = os.path.splitext(fname_a)[1].lower()
    ext_b = os.path.splitext(fname_b)[1].lower()

    if ext_a in image_exts and ext_b in image_exts:
        result["isImage"] = True
        result["imageComparison"] = _compare_images(content_a, content_b, fname_a, fname_b)

    # ── Text / code comparison ─────────────────────────────────────────────────
    elif not identical:
        # Try as text
        try:
            text_a = content_a.decode("utf-8")
            text_b = content_b.decode("utf-8")
            result["isText"] = True

            # Check if it's a PDF or DOCX (extract text first)
            if ext_a in {".pdf", ".docx", ".doc"}:
                text_a = _extract_text(content_a, ext_a)
                text_b = _extract_text(content_b, ext_b)
            elif ext_a in {".xlsx", ".xls", ".csv"}:
                comparison = _compare_spreadsheet(content_a, content_b, ext_a)
                result["spreadsheetComparison"] = comparison
                result["isText"] = False
            
            lines_a = text_a.splitlines(keepends=True)
            lines_b = text_b.splitlines(keepends=True)
            diff_gen = difflib.unified_diff(lines_a, lines_b, fromfile=fname_a, tofile=fname_b, n=3)
            diff_lines = [line.rstrip("\r\n") for line in diff_gen]

            added = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
            removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))

            result["diff"] = diff_lines
            result["diffStats"] = {
                "totalDiffLines": len(diff_lines),
                "linesAdded": added,
                "linesRemoved": removed,
                "linesModified": min(added, removed),
                "totalLinesA": len(lines_a),
                "totalLinesB": len(lines_b),
            }
        except (UnicodeDecodeError, Exception):
            result["isText"] = False

    # ── Binary comparison stats ────────────────────────────────────────────────
    if not result["isText"] and not result["isImage"] and not identical:
        # Byte-level stats for binary files
        min_len = min(len(content_a), len(content_b))
        diff_bytes = sum(1 for i in range(min_len) if content_a[i] != content_b[i])
        result["binaryDiff"] = {
            "differentBytes": diff_bytes + abs(len(content_a) - len(content_b)),
            "totalBytes": max(len(content_a), len(content_b)),
            "percentDifferent": round((diff_bytes / max(min_len, 1)) * 100, 2),
        }

    # ── Persist comparison record ──────────────────────────────────────────────
    if conn:
        try:
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            comp_id = f"CMP-{uuid.uuid4().hex[:8].upper()}"
            pixel_diff = None
            pixels_changed = None
            w_a = h_a = w_b = h_b = None
            if result.get("imageComparison"):
                ic = result["imageComparison"]
                pixel_diff = ic.get("percentChanged")
                pixels_changed = ic.get("pixelsChanged")
                w_a = ic.get("widthA"); h_a = ic.get("heightA")
                w_b = ic.get("widthB"); h_b = ic.get("heightB")
            conn.cursor().execute("""
                INSERT OR IGNORE INTO comparison_records (
                    id, file_name_a, file_name_b, sha256_a, sha256_b,
                    file_size_a, file_size_b, file_type_a, file_type_b,
                    identical, is_text, diff_lines_json,
                    pixel_diff_percent, pixels_changed,
                    image_width_a, image_height_a, image_width_b, image_height_b,
                    disclaimer, user_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                comp_id, fname_a, fname_b, hash_a, hash_b,
                len(content_a), len(content_b), mime_a, mime_b,
                1 if identical else 0, 1 if result["isText"] else 0,
                json.dumps(result.get("diff", [])),
                pixel_diff, pixels_changed, w_a, h_a, w_b, h_b,
                result["disclaimer"], user_id, now_iso
            ))
        except Exception as e:
            logger.warning(f"Could not persist comparison record: {e}")

    return result


def _compare_images(content_a: bytes, content_b: bytes,
                    fname_a: str, fname_b: str) -> Dict[str, Any]:
    """Pixel-level image comparison using Pillow."""
    try:
        from PIL import Image, ImageChops, ImageFilter
        import math

        img_a = Image.open(io.BytesIO(content_a)).convert("RGBA")
        img_b = Image.open(io.BytesIO(content_b)).convert("RGBA")

        w_a, h_a = img_a.size
        w_b, h_b = img_b.size

        # Resize b to match a for pixel diff (if sizes differ)
        if img_a.size != img_b.size:
            img_b_resized = img_b.resize(img_a.size, Image.LANCZOS)
        else:
            img_b_resized = img_b

        diff = ImageChops.difference(img_a, img_b_resized)

        # Count changed pixels
        pixels = list(diff.getdata())
        total_pixels = len(pixels)
        changed = sum(1 for p in pixels if any(c > 10 for c in p[:3]))
        percent_changed = round((changed / max(total_pixels, 1)) * 100, 4)

        # Create highlighted diff image
        diff_enhanced = diff.point(lambda x: min(255, x * 8))
        diff_rgb = diff_enhanced.convert("RGB")

        # Overlay red on changed regions
        import struct
        diff_overlay = Image.new("RGBA", img_a.size, (0, 0, 0, 0))
        diff_data = list(diff.getdata())
        overlay_data = []
        for i, px in enumerate(diff_data):
            if any(c > 10 for c in px[:3]):
                overlay_data.append((255, 0, 0, 180))  # red highlight
            else:
                overlay_data.append((0, 0, 0, 0))
        diff_overlay.putdata(overlay_data)

        highlighted = img_a.copy()
        highlighted.paste(diff_overlay, mask=diff_overlay)

        # Base64 encode images for frontend
        def img_to_b64(img: Image.Image) -> str:
            buf = io.BytesIO()
            img.convert("RGB").save(buf, format="PNG", optimize=True)
            return base64.b64encode(buf.getvalue()).decode()

        return {
            "widthA": w_a, "heightA": h_a,
            "widthB": w_b, "heightB": h_b,
            "pixelsChanged": changed,
            "totalPixels": total_pixels,
            "percentChanged": percent_changed,
            "identical": changed == 0,
            "imageA_b64": img_to_b64(img_a),
            "imageB_b64": img_to_b64(img_b),
            "diffImage_b64": img_to_b64(highlighted),
        }
    except ImportError:
        return {
            "error": "Pillow not installed. Run: pip install Pillow",
            "pixelsChanged": None, "percentChanged": None
        }
    except Exception as e:
        return {"error": str(e), "pixelsChanged": None, "percentChanged": None}


def _extract_text(content: bytes, ext: str) -> str:
    """Extract readable text from PDF or DOCX."""
    try:
        if ext == ".pdf":
            try:
                import fitz  # PyMuPDF
                doc = fitz.open(stream=content, filetype="pdf")
                return "\n".join(page.get_text() for page in doc)
            except ImportError:
                return content.decode("utf-8", errors="replace")
        elif ext in (".docx", ".doc"):
            try:
                from docx import Document
                doc = Document(io.BytesIO(content))
                return "\n".join(p.text for p in doc.paragraphs)
            except ImportError:
                return content.decode("utf-8", errors="replace")
    except Exception:
        pass
    return content.decode("utf-8", errors="replace")


def _compare_spreadsheet(content_a: bytes, content_b: bytes, ext: str) -> Dict[str, Any]:
    """Compare spreadsheet cells using openpyxl."""
    try:
        import openpyxl
        from io import BytesIO

        wb_a = openpyxl.load_workbook(BytesIO(content_a), data_only=True)
        wb_b = openpyxl.load_workbook(BytesIO(content_b), data_only=True)

        ws_a = wb_a.active
        ws_b = wb_b.active

        changed_cells = []
        max_row = max(ws_a.max_row or 0, ws_b.max_row or 0)
        max_col = max(ws_a.max_column or 0, ws_b.max_column or 0)

        for r in range(1, max_row + 1):
            for c in range(1, max_col + 1):
                val_a = ws_a.cell(r, c).value
                val_b = ws_b.cell(r, c).value
                if str(val_a) != str(val_b):
                    changed_cells.append({
                        "row": r, "col": c,
                        "original": str(val_a),
                        "modified": str(val_b)
                    })

        return {
            "sheetsA": wb_a.sheetnames,
            "sheetsB": wb_b.sheetnames,
            "changedCells": changed_cells[:200],  # limit for response size
            "totalChangedCells": len(changed_cells)
        }
    except ImportError:
        return {"error": "openpyxl not installed. Run: pip install openpyxl"}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# History, Dashboard, Cases
# ─────────────────────────────────────────────────────────────────────────────

def get_source_history(conn: sqlite3.Connection, source_id: str) -> Dict[str, Any]:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sources WHERE UPPER(id) = UPPER(?);", (source_id.strip(),))
    source_row = cursor.fetchone()
    if not source_row:
        raise HTTPException(status_code=404, detail=f"Source record '{source_id}' not found in registry.")

    source_dict = row_to_source_dict(source_row)

    cursor.execute("""
        SELECT * FROM verification_events WHERE UPPER(source_id) = UPPER(?) ORDER BY timestamp ASC;
    """, (source_id.strip(),))
    events = [row_to_event_dict(r) for r in cursor.fetchall()]

    cursor.execute("""
        SELECT * FROM ledger_blocks WHERE payload_json LIKE ? ORDER BY block_number ASC;
    """, (f'%"{source_dict["id"]}"%',))
    blocks = [row_to_block_dict(r) for r in cursor.fetchall()]

    return {"source": source_dict, "events": events, "ledgerBlocks": blocks}


def matched_source_found(row: Optional[sqlite3.Row]) -> bool:
    return row is not None


def get_dashboard_metrics(conn: sqlite3.Connection) -> Dict[str, Any]:
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM sources;")
    total_registered = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM verification_events;")
    total_verifications = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM verification_events WHERE verdict = 'ORIGINAL';")
    original_verified = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM verification_events WHERE verdict = 'EDITED';")
    edited_detected = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM verification_events WHERE verdict = 'UNKNOWN';")
    unknown_detected = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM verification_events WHERE verdict = 'INVALID_SIGNATURE';")
    invalid_sig_detected = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ledger_blocks;")
    ledger_block_count = cursor.fetchone()[0]

    # File type distribution
    cursor.execute("""
        SELECT file_type, COUNT(*) as cnt FROM sources GROUP BY file_type ORDER BY cnt DESC LIMIT 10;
    """)
    file_type_dist = [{"fileType": r["file_type"], "count": r["cnt"]} for r in cursor.fetchall()]

    # Recent activity (last 10 events)
    cursor.execute("""
        SELECT ve.*, s.file_name FROM verification_events ve
        LEFT JOIN sources s ON ve.source_id = s.id
        ORDER BY ve.timestamp DESC LIMIT 10;
    """)
    recent_activity = []
    for r in cursor.fetchall():
        recent_activity.append({
            "id": r["id"], "verdict": r["verdict"],
            "fileName": r["file_name"] or r["file_name"],
            "timestamp": r["timestamp"]
        })

    cursor.execute("SELECT * FROM ledger_blocks ORDER BY block_number ASC;")
    blocks = [row_to_block_dict(r) for r in cursor.fetchall()]
    validation_res = validate_chain(blocks)

    score = f"{((original_verified / total_verifications) * 100):.1f}%" if total_verifications > 0 else "100.0%"

    # Case count
    try:
        cursor.execute("SELECT COUNT(*) FROM investigation_cases;")
        case_count = cursor.fetchone()[0]
    except Exception:
        case_count = 0

    return {
        "totalRegistered": total_registered,
        "totalVerifications": total_verifications,
        "originalVerified": original_verified,
        "editedDetected": edited_detected,
        "unknownDetected": unknown_detected,
        "invalidSignatureDetected": invalid_sig_detected,
        "ledgerBlockCount": ledger_block_count,
        "ledgerValid": validation_res["isValid"],
        "integrityScore": score,
        "cryptographicEngine": "Ed25519 (RFC 8032) / SHA-256 (SQLite Persistent)",
        "fileTypeDistribution": file_type_dist,
        "recentActivity": recent_activity,
        "activeCases": case_count,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Investigation Cases
# ─────────────────────────────────────────────────────────────────────────────

def create_case(conn: sqlite3.Connection, title: str, description: str,
                priority: str = "NORMAL", user_id: Optional[str] = None) -> Dict[str, Any]:
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    case_id = f"CASE-{datetime.datetime.now().year}-{uuid.uuid4().hex[:4].upper()}"
    cursor.execute("""
        INSERT INTO investigation_cases (id, title, description, status, priority, user_id, created_at, updated_at)
        VALUES (?, ?, ?, 'OPEN', ?, ?, ?, ?);
    """, (case_id, title, description, priority, user_id, now, now))
    cursor.execute("SELECT * FROM investigation_cases WHERE id = ?;", (case_id,))
    return row_to_case_dict(cursor.fetchone())


def get_cases(conn: sqlite3.Connection, user_id: Optional[str] = None,
              role: str = "analyst") -> List[Dict[str, Any]]:
    cursor = conn.cursor()
    if role == "admin" or user_id is None:
        cursor.execute("SELECT * FROM investigation_cases ORDER BY created_at DESC LIMIT 100;")
    else:
        cursor.execute("SELECT * FROM investigation_cases WHERE user_id = ? OR user_id IS NULL ORDER BY created_at DESC;",
                       (user_id,))
    rows = cursor.fetchall()
    cases = []
    for row in rows:
        c = row_to_case_dict(row)
        # Attach file count
        cursor.execute("SELECT COUNT(*) FROM case_files WHERE case_id = ?;", (row["id"],))
        c["fileCount"] = cursor.fetchone()[0]
        cases.append(c)
    return cases


def get_case_detail(conn: sqlite3.Connection, case_id: str) -> Dict[str, Any]:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM investigation_cases WHERE id = ?;", (case_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    case = row_to_case_dict(row)

    cursor.execute("""
        SELECT cf.*, s.file_name, s.file_type, s.sha256, s.status
        FROM case_files cf
        LEFT JOIN sources s ON cf.source_id = s.id
        WHERE cf.case_id = ?;
    """, (case_id,))
    files = []
    for r in cursor.fetchall():
        files.append({
            "id": r["id"], "sourceId": r["source_id"], "label": r["label"],
            "addedAt": r["added_at"], "fileName": r["file_name"],
            "fileType": r["file_type"], "sha256": r["sha256"], "status": r["status"]
        })
    case["files"] = files
    return case


def add_file_to_case(conn: sqlite3.Connection, case_id: str, source_id: str,
                     label: str = "") -> Dict[str, Any]:
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM investigation_cases WHERE id = ?;", (case_id,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cf_id = f"CF-{uuid.uuid4().hex[:8].upper()}"
    cursor.execute("INSERT INTO case_files (id, case_id, source_id, label, added_at) VALUES (?, ?, ?, ?, ?);",
                   (cf_id, case_id, source_id, label, now))
    cursor.execute("UPDATE investigation_cases SET updated_at = ? WHERE id = ?;", (now, case_id))
    return {"id": cf_id, "caseId": case_id, "sourceId": source_id, "label": label, "addedAt": now}


# ─────────────────────────────────────────────────────────────────────────────
# QR Code Generation & Mobile Scannable Evidence Anchoring
# ─────────────────────────────────────────────────────────────────────────────

def get_lan_ip() -> str:
    """Detect the host machine's primary local area network (LAN) IPv4 address."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return "127.0.0.1"


def get_qr_verification_url(source_id: str, base_url: Optional[str] = None) -> str:
    """
    Construct a mobile-accessible verification URL.
    Never encodes localhost or 127.0.0.1; replaces with the host machine's LAN IP.
    """
    lan_ip = get_lan_ip()
    port = "3000"

    if base_url:
        clean = base_url.strip().rstrip("/")
        # Extract port if present in base_url
        parts = clean.split("//")[-1].split("/")
        host_port = parts[0]
        if ":" in host_port:
            port = host_port.split(":")[-1]

        if "localhost" in clean or "127.0.0.1" in clean:
            base_url = f"http://{lan_ip}:{port}"
        else:
            base_url = clean
    else:
        base_url = f"http://{lan_ip}:{port}"

    return f"{base_url}/verify?sourceId={source_id.strip()}"


def generate_qr_code_bytes(source_id: str, base_url: Optional[str] = None) -> bytes:
    """
    Generate a high-resolution, mobile-scannable QR code PNG linking to the verification page.
    Features:
    - High contrast: dark navy modules (#0A1628) on pure white (#FFFFFF) for standard iOS/Android cameras
    - Error correction: Level H (30% error recovery)
    - Quiet zone: border=4
    - Resolution: box_size=10 producing ~330x330px+ crisp PNG
    - Mobile accessible: LAN IP used automatically instead of localhost
    """
    try:
        import qrcode

        verify_url = get_qr_verification_url(source_id, base_url)

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4
        )
        qr.add_data(verify_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="#0A1628", back_color="#FFFFFF")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        raise HTTPException(status_code=500, detail="qrcode library not installed.")


# ─────────────────────────────────────────────────────────────────────────────
# PDF Report Generation
# ─────────────────────────────────────────────────────────────────────────────

def generate_pdf_report(source: Dict[str, Any], events: List[Dict[str, Any]],
                        blocks: List[Dict[str, Any]]) -> bytes:
    """Generate a professional forensic PDF report using reportlab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_LEFT, TA_CENTER

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)

        styles = getSampleStyleSheet()
        dark_blue = colors.HexColor("#0A1628")
        cyan = colors.HexColor("#00F0FF")
        white = colors.white
        light_gray = colors.HexColor("#E2E8F0")
        alert_red = colors.HexColor("#EF4444")
        green = colors.HexColor("#10B981")

        title_style = ParagraphStyle("Title", parent=styles["Title"],
                                     textColor=cyan, fontSize=18, spaceAfter=6)
        subtitle_style = ParagraphStyle("Sub", parent=styles["Normal"],
                                        textColor=light_gray, fontSize=10, spaceAfter=12)
        section_style = ParagraphStyle("Section", parent=styles["Heading2"],
                                       textColor=cyan, fontSize=12, spaceBefore=12, spaceAfter=6)
        body_style = ParagraphStyle("Body", parent=styles["Normal"],
                                    textColor=colors.HexColor("#CBD5E1"), fontSize=9, leading=14)
        mono_style = ParagraphStyle("Mono", parent=styles["Normal"],
                                    textColor=colors.HexColor("#7DD3FC"), fontSize=7.5,
                                    fontName="Courier", leading=11)

        story = []
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Header
        story.append(Paragraph("SOURCEMARK — FORENSIC VERIFICATION REPORT", title_style))
        story.append(Paragraph(f"Generated: {now_str} | Classification: FORENSIC EVIDENCE DOCUMENT", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1, color=cyan, spaceAfter=12))

        # Source metadata table
        story.append(Paragraph("Registered Source — Provenance Record", section_style))
        meta_data = [
            ["Field", "Value"],
            ["Source ID", source.get("id", "—")],
            ["File Name", source.get("fileName", "—")],
            ["File Type", source.get("fileType", "—")],
            ["File Size", source.get("fileSizeFormatted") or f"{source.get('fileSize', 0):,} bytes"],
            ["Registered At", source.get("registeredAt", "—")],
            ["Creator", source.get("creator", "—")],
            ["Creator ID", source.get("creatorId", "—")],
            ["Category", source.get("category", "—")],
            ["Status", source.get("status", "—")],
            ["Verification Count", str(source.get("verificationCount", 0))],
            ["Last Verified", source.get("lastVerifiedAt") or "Never"],
        ]
        t = Table(meta_data, colWidths=[4*cm, 13*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), dark_blue),
            ("TEXTCOLOR", (0, 0), (-1, 0), cyan),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TEXTCOLOR", (0, 1), (0, -1), light_gray),
            ("TEXTCOLOR", (1, 1), (1, -1), colors.HexColor("#CBD5E1")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0D1527")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0D1527"), colors.HexColor("#0A1120")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1E3A5F")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 12))

        # SHA-256 fingerprint
        story.append(Paragraph("Cryptographic Fingerprint (SHA-256)", section_style))
        story.append(Paragraph(source.get("sha256", "—"), mono_style))
        story.append(Spacer(1, 8))

        story.append(Paragraph("Ed25519 Public Key", section_style))
        story.append(Paragraph(source.get("publicKey", "—"), mono_style))
        story.append(Spacer(1, 8))

        # Verification events
        if events:
            story.append(Paragraph("Verification Event History", section_style))
            ev_data = [["Timestamp", "Verdict", "File Name", "Hash Match", "Sig Valid"]]
            for ev in events:
                verdict_color = green if ev.get("verdict") == "ORIGINAL" else alert_red
                ev_data.append([
                    ev.get("timestamp", "")[:19],
                    ev.get("verdict", ""),
                    (ev.get("fileName") or "—")[:30],
                    "✓" if ev.get("hashMatch") else "✗",
                    "✓" if ev.get("signatureValid") else "✗",
                ])
            ev_table = Table(ev_data, colWidths=[4*cm, 3.5*cm, 5*cm, 2*cm, 2.5*cm])
            ev_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), dark_blue),
                ("TEXTCOLOR", (0, 0), (-1, 0), cyan),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#1E3A5F")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0D1527")),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0D1527"), colors.HexColor("#0A1120")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(ev_table)
            story.append(Spacer(1, 12))

        # Ledger blocks
        if blocks:
            story.append(Paragraph("Audit Ledger Blocks", section_style))
            for blk in blocks[:10]:
                story.append(Paragraph(
                    f"<b>Block #{blk.get('blockNumber')} — {blk.get('type')}</b> | {blk.get('timestamp', '')[:19]}",
                    body_style
                ))
                story.append(Paragraph(f"Hash: {blk.get('currentHash', '')}", mono_style))
                story.append(Spacer(1, 4))

        # Disclaimer
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#1E3A5F"), spaceBefore=12))
        story.append(Paragraph(
            "LEGAL DISCLAIMER: This forensic report is generated by the SourceMark Digital Provenance Platform. "
            "Cryptographic verification confirms file integrity and signing key continuity at the time of registration. "
            "It does not constitute proof that the content depicts a genuine real-world event or was not fabricated "
            "prior to registration. All verification results should be considered in the context of a complete "
            "forensic investigation with verified chain of custody.",
            ParagraphStyle("Disclaimer", parent=body_style, fontSize=7.5,
                           textColor=colors.HexColor("#94A3B8"), spaceBefore=8)
        ))

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        raise HTTPException(status_code=500,
                            detail="reportlab not installed. Run: pip install reportlab")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


# ─────────────────────────────────────────────────────────────────────────────
# Batch verification
# ─────────────────────────────────────────────────────────────────────────────

def batch_verify(conn: sqlite3.Connection, items: List[Dict[str, Any]],
                 user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Verify multiple files in one call. Each item: {sha256, sourceId?, fileName?}"""
    from .schemas import VerifyPayload
    results = []
    for item in items[:50]:  # cap at 50
        try:
            payload = VerifyPayload(
                sha256=item.get("sha256", ""),
                sourceId=item.get("sourceId"),
                fileName=item.get("fileName", "batch_file")
            )
            result = verify_source(conn, payload, user_id)
            results.append(result)
        except HTTPException as e:
            results.append({"verdict": "ERROR", "error": e.detail,
                            "sha256": item.get("sha256", ""), "fileName": item.get("fileName", "")})
        except Exception as e:
            results.append({"verdict": "ERROR", "error": "Internal verification error",
                            "sha256": item.get("sha256", ""), "fileName": item.get("fileName", "")})
    return results
