"""
SourceMark Database Module — v2
Manages SQLite schema, migrations, connection lifecycle, and parameterized queries.
Adds: users, cases, comparison_records, reports tables.
Preserves all existing tables without data loss.
"""

import sqlite3
import os
import json
import logging
import datetime
from typing import Generator, Dict, Any, List, Optional
from contextlib import contextmanager

from .config import settings
from .ledger import compute_block_hash, GENESIS_PREV_HASH

logger = logging.getLogger("sourcemark.database")


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Create a new SQLite connection with foreign keys and Row factory enabled."""
    path = db_path or settings.DATABASE_PATH
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


@contextmanager
def get_db(db_path: Optional[str] = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite database operations with auto-commit and rollback."""
    conn = get_db_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None):
    """
    Initialize SQLite database tables, indexes, and initial verifiable seed data.
    Ensures safe idempotency via schema_migrations table.
    Never deletes existing data.
    """
    path = db_path or settings.DATABASE_PATH
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    with get_db(path) as conn:
        cursor = conn.cursor()

        # 1. Migration tracking table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
        """)

        # ── Migration 001: Initial SourceMark schema ──────────────────────────
        cursor.execute("SELECT version FROM schema_migrations WHERE version = 1;")
        if cursor.fetchone() is None:
            logger.info("Applying Migration 001: Initial SourceMark schema...")
            _apply_migration_001(cursor)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cursor.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?);",
                (1, "initial_schema", now_iso)
            )
            logger.info("Migration 001 applied successfully.")

        # ── Migration 002: Users & Auth ───────────────────────────────────────
        cursor.execute("SELECT version FROM schema_migrations WHERE version = 2;")
        if cursor.fetchone() is None:
            logger.info("Applying Migration 002: Users & Auth tables...")
            _apply_migration_002(cursor)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cursor.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?);",
                (2, "users_auth", now_iso)
            )
            logger.info("Migration 002 applied successfully.")

        # ── Migration 003: Cases & Comparisons ───────────────────────────────
        cursor.execute("SELECT version FROM schema_migrations WHERE version = 3;")
        if cursor.fetchone() is None:
            logger.info("Applying Migration 003: Cases, comparisons & reports...")
            _apply_migration_003(cursor)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cursor.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?);",
                (3, "cases_comparisons_reports", now_iso)
            )
            logger.info("Migration 003 applied successfully.")


# ─────────────────────────────────────────────────────────────────────────────
# Migration implementations
# ─────────────────────────────────────────────────────────────────────────────

def _apply_migration_001(cursor: sqlite3.Cursor):
    """Create original schema: sources, verification_events, ledger_blocks."""

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sources (
            id TEXT PRIMARY KEY,
            file_name TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_size_formatted TEXT,
            sha256 TEXT NOT NULL,
            signature TEXT NOT NULL,
            public_key TEXT NOT NULL,
            key_id TEXT NOT NULL,
            creator TEXT NOT NULL,
            creator_id TEXT NOT NULL,
            category TEXT,
            description TEXT,
            source_origin TEXT,
            registered_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE_REGISTERED',
            verification_count INTEGER NOT NULL DEFAULT 0,
            last_verified_at TEXT
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sources_sha256 ON sources(sha256);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sources_registered_at ON sources(registered_at);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sources_creator_id ON sources(creator_id);")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS verification_events (
            id TEXT PRIMARY KEY,
            source_id TEXT,
            file_name TEXT,
            searched_hash TEXT NOT NULL,
            verdict TEXT NOT NULL,
            status TEXT NOT NULL,
            message TEXT NOT NULL,
            details TEXT,
            hash_match INTEGER NOT NULL,
            signature_valid INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            ledger_block_id TEXT,
            FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE SET NULL,
            FOREIGN KEY(ledger_block_id) REFERENCES ledger_blocks(id) ON DELETE SET NULL
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_verifications_source_id ON verification_events(source_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_verifications_searched_hash ON verification_events(searched_hash);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_verifications_verdict ON verification_events(verdict);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_verifications_timestamp ON verification_events(timestamp);")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ledger_blocks (
            id TEXT PRIMARY KEY,
            block_number INTEGER UNIQUE NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'CONFIRMED',
            verified INTEGER NOT NULL DEFAULT 1,
            payload_json TEXT NOT NULL
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ledger_block_number ON ledger_blocks(block_number);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ledger_current_hash ON ledger_blocks(current_hash);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ledger_blocks(timestamp);")

    seed_initial_data(cursor)


def _apply_migration_002(cursor: sqlite3.Cursor):
    """Create users table and add user_id FK columns to existing tables."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            full_name TEXT,
            organization TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login_at TEXT
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")

    # Add user_id to sources (nullable — existing records owned by system)
    try:
        cursor.execute("ALTER TABLE sources ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE SET NULL;")
    except sqlite3.OperationalError:
        pass  # column already exists

    # Add user_id to verification_events
    try:
        cursor.execute("ALTER TABLE verification_events ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE SET NULL;")
    except sqlite3.OperationalError:
        pass

    # Seed default admin account (password: Admin@1234)
    from .auth import hash_password
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    admin_pass = hash_password("Admin@1234")
    demo_pass = hash_password("Demo@1234")
    try:
        cursor.execute("""
            INSERT OR IGNORE INTO users (id, username, email, password_hash, role, full_name, organization, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?);
        """, ("USR-ADMIN-001", "admin", "admin@sourcemark.io", admin_pass,
              "admin", "SourceMark Administrator", "SourceMark Platform", now_iso))
        cursor.execute("""
            INSERT OR IGNORE INTO users (id, username, email, password_hash, role, full_name, organization, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?);
        """, ("USR-DEMO-001", "analyst", "analyst@sourcemark.io", demo_pass,
              "analyst", "Dr. Evelyn Vance", "National Geospatial Imaging", now_iso))
    except Exception as e:
        logger.warning(f"Could not seed users: {e}")


def _apply_migration_003(cursor: sqlite3.Cursor):
    """Create investigation cases, comparison_records, and reports tables."""

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigation_cases (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'OPEN',
            priority TEXT NOT NULL DEFAULT 'NORMAL',
            user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            closed_at TEXT
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cases_user_id ON investigation_cases(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON investigation_cases(status);")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_files (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES investigation_cases(id) ON DELETE CASCADE,
            source_id TEXT REFERENCES sources(id) ON DELETE SET NULL,
            label TEXT,
            added_at TEXT NOT NULL
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_files_case_id ON case_files(case_id);")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comparison_records (
            id TEXT PRIMARY KEY,
            file_name_a TEXT NOT NULL,
            file_name_b TEXT NOT NULL,
            sha256_a TEXT NOT NULL,
            sha256_b TEXT NOT NULL,
            file_size_a INTEGER NOT NULL,
            file_size_b INTEGER NOT NULL,
            file_type_a TEXT,
            file_type_b TEXT,
            identical INTEGER NOT NULL DEFAULT 0,
            is_text INTEGER NOT NULL DEFAULT 0,
            diff_lines_json TEXT,
            pixel_diff_percent REAL,
            pixels_changed INTEGER,
            image_width_a INTEGER,
            image_height_a INTEGER,
            image_width_b INTEGER,
            image_height_b INTEGER,
            metadata_diff_json TEXT,
            diff_image_path TEXT,
            disclaimer TEXT,
            user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
            case_id TEXT REFERENCES investigation_cases(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_comparisons_user_id ON comparison_records(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_comparisons_created_at ON comparison_records(created_at);")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            report_type TEXT NOT NULL,
            source_id TEXT REFERENCES sources(id) ON DELETE SET NULL,
            comparison_id TEXT REFERENCES comparison_records(id) ON DELETE SET NULL,
            case_id TEXT REFERENCES investigation_cases(id) ON DELETE SET NULL,
            user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
            file_path TEXT,
            summary_json TEXT,
            created_at TEXT NOT NULL
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_source_id ON reports(source_id);")

    # Seed a demo investigation case (no user_id FK — users may not exist yet in test DBs)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute("""
        INSERT OR IGNORE INTO investigation_cases (id, title, description, status, priority, user_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, NULL, ?, ?);
    """, (
        "CASE-2026-001",
        "Orbital Reconnaissance Image Integrity Review",
        "Investigation into possible tampering of satellite imagery from Sector 4B survey area.",
        "OPEN", "HIGH", now_iso, now_iso
    ))
    cursor.execute("""
        INSERT OR IGNORE INTO case_files (id, case_id, source_id, label, added_at)
        VALUES (?, ?, ?, ?, ?);
    """, ("CF-001", "CASE-2026-001", "SRC-98214", "Primary Evidence — Orbital Image", now_iso))
    cursor.execute("""
        INSERT OR IGNORE INTO case_files (id, case_id, source_id, label, added_at)
        VALUES (?, ?, ?, ?, ?);
    """, ("CF-002", "CASE-2026-001", "SRC-77402", "Supporting Evidence — Firmware Package", now_iso))


# ─────────────────────────────────────────────────────────────────────────────
# Seed Data (existing unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def seed_initial_data(cursor: sqlite3.Cursor):
    """Seed initial demonstrable records with mathematically valid Ed25519 signatures and hash chains."""
    demo_sources = [
        {
            "id": "SRC-98214",
            "file_name": "satellite_recon_orbital_07.png",
            "file_type": "image/png",
            "file_size": 2458920,
            "file_size_formatted": "2.34 MB",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "public_key": "6ad4e0c582f2b4f9880ad925880b4a1241cca73642681fa782e768536014db06",
            "signature": "bcef92c198dc65cc8cd440aac8f3cb17ca6a5e66ea76aaf074fd887cd64d9028d15434e6222b675681649fc0982683d9f8c70deede96164dc0d56165168cbf07",
            "key_id": "ED25519-6AD4E0C5",
            "creator": "Dr. Evelyn Vance (Chief Geoint Analyst)",
            "creator_id": "AGY-USR-0042",
            "category": "Satellite Intelligence",
            "description": "High-resolution multispectral imagery of Sector 4B survey area.",
            "source_origin": "National Geospatial Imaging Pipeline / Node Alpha",
            "registered_at": "2026-10-24T09:15:22.000Z",
            "status": "ACTIVE_REGISTERED",
            "verification_count": 8,
            "last_verified_at": "2026-10-29T14:30:11.000Z"
        },
        {
            "id": "SRC-77402",
            "file_name": "secure_firmware_release_v4.2.1.bin",
            "file_type": "application/octet-stream",
            "file_size": 524288,
            "file_size_formatted": "512 KB",
            "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "public_key": "31954624ebfc9f27275a7079c05f081fe98fcaeb06608feea930f76aeb872615",
            "signature": "9c62d96bb274ac61dfe22450e04ab7369fe7334ce5827dd1c0eab575b0b2c50c33384d4b325ddf4cd6e8909a69d1d48e8d54246687f6b80866b54ce062673f0f",
            "key_id": "ED25519-31954624",
            "creator": "SecOps Build Automation",
            "creator_id": "SYSTEM-CI-BUILD",
            "category": "System Firmware",
            "description": "Cryptographically signed IoT Gateway production kernel package.",
            "source_origin": "Air-gapped Key Ceremonies HSM #3",
            "registered_at": "2026-10-26T11:42:05.000Z",
            "status": "ACTIVE_REGISTERED",
            "verification_count": 24,
            "last_verified_at": "2026-10-30T08:05:19.000Z"
        },
        {
            "id": "SRC-55109",
            "file_name": "acquisition_term_sheet_final.pdf",
            "file_type": "application/pdf",
            "file_size": 1845100,
            "file_size_formatted": "1.76 MB",
            "sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "public_key": "340d2070ec3f9cdc4f9a199345db7e5ba8d59d90c181213494c658008b9fe816",
            "signature": "7f57f5d15e70f31894b628ba5fec288e9db4ec8994305a3e48073e1174d4c76af34fe235f6d5d1b7fcf3d3e80dbd49c712c0f79cf89b9c6009632091c5282305",
            "key_id": "ED25519-340D2070",
            "creator": "Sarah Jenkins, Esq. (Legal Counsel)",
            "creator_id": "AGY-USR-0119",
            "category": "Legal Document",
            "description": "Binding mutual merger terms, executed with biometric digital witness.",
            "source_origin": "Corporate Legal Vault / Dublin Office",
            "registered_at": "2026-10-28T16:20:44.000Z",
            "status": "ACTIVE_REGISTERED",
            "verification_count": 5,
            "last_verified_at": "2026-10-30T04:12:00.000Z"
        }
    ]

    for s in demo_sources:
        cursor.execute("""
            INSERT INTO sources (
                id, file_name, file_type, file_size, file_size_formatted,
                sha256, signature, public_key, key_id, creator, creator_id,
                category, description, source_origin, registered_at,
                status, verification_count, last_verified_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            s["id"], s["file_name"], s["file_type"], s["file_size"], s["file_size_formatted"],
            s["sha256"], s["signature"], s["public_key"], s["key_id"], s["creator"], s["creator_id"],
            s["category"], s["description"], s["source_origin"], s["registered_at"],
            s["status"], s["verification_count"], s["last_verified_at"]
        ))

    # Sequential Ledger Blocks
    b1_id = "BLK-0001"; b1_num = 1; b1_type = "GENESIS"
    b1_title = "Genesis Ledger Node Initialized"; b1_time = "2026-10-20T00:00:00.000Z"; b1_prev = GENESIS_PREV_HASH
    b1_payload = {"action": "LEDGER_INITIALIZATION", "engine": "Ed25519-EdDSA", "digest": "SHA-256", "version": "1.0.0"}
    b1_hash = compute_block_hash(b1_id, b1_num, b1_type, b1_prev, b1_time, b1_payload)
    cursor.execute("INSERT INTO ledger_blocks (id, block_number, type, title, timestamp, prev_hash, current_hash, status, verified, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                   (b1_id, b1_num, b1_type, b1_title, b1_time, b1_prev, b1_hash, "CONFIRMED", 1, json.dumps(b1_payload)))

    b2_id = "BLK-0002"; b2_num = 2; b2_type = "REGISTER"
    b2_title = "File Registration: satellite_recon_orbital_07.png"; b2_time = "2026-10-24T09:15:22.000Z"; b2_prev = b1_hash
    b2_payload = {"sourceId": "SRC-98214", "fileName": "satellite_recon_orbital_07.png", "fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "creatorId": "AGY-USR-0042", "keyId": "ED25519-6AD4E0C5"}
    b2_hash = compute_block_hash(b2_id, b2_num, b2_type, b2_prev, b2_time, b2_payload)
    cursor.execute("INSERT INTO ledger_blocks (id, block_number, type, title, timestamp, prev_hash, current_hash, status, verified, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                   (b2_id, b2_num, b2_type, b2_title, b2_time, b2_prev, b2_hash, "CONFIRMED", 1, json.dumps(b2_payload)))

    b3_id = "BLK-0003"; b3_num = 3; b3_type = "VERIFY_ORIGINAL"
    b3_title = "Integrity Check: Cryptographically Verified"; b3_time = "2026-10-25T14:10:05.000Z"; b3_prev = b2_hash
    b3_payload = {"sourceId": "SRC-98214", "verdict": "ORIGINAL", "hashMatch": True, "signatureValid": True, "auditor": "Client Gate Inspection"}
    b3_hash = compute_block_hash(b3_id, b3_num, b3_type, b3_prev, b3_time, b3_payload)
    cursor.execute("INSERT INTO ledger_blocks (id, block_number, type, title, timestamp, prev_hash, current_hash, status, verified, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                   (b3_id, b3_num, b3_type, b3_title, b3_time, b3_prev, b3_hash, "CONFIRMED", 1, json.dumps(b3_payload)))

    cursor.execute("""INSERT INTO verification_events (id, source_id, file_name, searched_hash, verdict, status, message, details, hash_match, signature_valid, timestamp, ledger_block_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
        ("VER-0001", "SRC-98214", "satellite_recon_orbital_07.png", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "ORIGINAL", "success", "Original – Cryptographically Verified", "Bitstream matched registered master asset with authentic Ed25519 digital signature.", 1, 1, "2026-10-25T14:10:05.000Z", "BLK-0003"))

    b4_id = "BLK-0004"; b4_num = 4; b4_type = "REGISTER"
    b4_title = "File Registration: secure_firmware_release_v4.2.1.bin"; b4_time = "2026-10-26T11:42:05.000Z"; b4_prev = b3_hash
    b4_payload = {"sourceId": "SRC-77402", "fileName": "secure_firmware_release_v4.2.1.bin", "fingerprint": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "creatorId": "SYSTEM-CI-BUILD", "keyId": "ED25519-31954624"}
    b4_hash = compute_block_hash(b4_id, b4_num, b4_type, b4_prev, b4_time, b4_payload)
    cursor.execute("INSERT INTO ledger_blocks (id, block_number, type, title, timestamp, prev_hash, current_hash, status, verified, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                   (b4_id, b4_num, b4_type, b4_title, b4_time, b4_prev, b4_hash, "CONFIRMED", 1, json.dumps(b4_payload)))

    b5_id = "BLK-0005"; b5_num = 5; b5_type = "TAMPER_DETECTED"
    b5_title = "Security Alert: Modified Content Intercepted"; b5_time = "2026-10-27T08:14:30.000Z"; b5_prev = b4_hash
    b5_payload = {"sourceId": "SRC-98214", "verdict": "EDITED", "detectedAnomaly": "Hash mismatch - altered bitstream in target payload", "submittedHash": "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78", "originalHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    b5_hash = compute_block_hash(b5_id, b5_num, b5_type, b5_prev, b5_time, b5_payload)
    cursor.execute("INSERT INTO ledger_blocks (id, block_number, type, title, timestamp, prev_hash, current_hash, status, verified, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                   (b5_id, b5_num, b5_type, b5_title, b5_time, b5_prev, b5_hash, "ALERT", 1, json.dumps(b5_payload)))

    cursor.execute("""INSERT INTO verification_events (id, source_id, file_name, searched_hash, verdict, status, message, details, hash_match, signature_valid, timestamp, ledger_block_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
        ("VER-0002", "SRC-98214", "satellite_recon_orbital_07_mod.png", "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78",
         "EDITED", "danger", "Edited – Content Difference Detected", "File references Source ID SRC-98214 but submitted fingerprint does not match master asset.", 0, 0, "2026-10-27T08:14:30.000Z", "BLK-0005"))

    b6_id = "BLK-0006"; b6_num = 6; b6_type = "REGISTER"
    b6_title = "File Registration: acquisition_term_sheet_final.pdf"; b6_time = "2026-10-28T16:20:44.000Z"; b6_prev = b5_hash
    b6_payload = {"sourceId": "SRC-55109", "fileName": "acquisition_term_sheet_final.pdf", "fingerprint": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "creatorId": "AGY-USR-0119", "keyId": "ED25519-340D2070"}
    b6_hash = compute_block_hash(b6_id, b6_num, b6_type, b6_prev, b6_time, b6_payload)
    cursor.execute("INSERT INTO ledger_blocks (id, block_number, type, title, timestamp, prev_hash, current_hash, status, verified, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                   (b6_id, b6_num, b6_type, b6_title, b6_time, b6_prev, b6_hash, "CONFIRMED", 1, json.dumps(b6_payload)))
