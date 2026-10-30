"""
SourceMark Cryptographic Utilities
Implements SHA-256 digest calculation, Ed25519 digital signature validation (RFC 8032),
and canonical JSON serialization for tamper-evident ledger hashing.
"""

import hashlib
import json
from typing import Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 digest in lowercase hexadecimal format."""
    return hashlib.sha256(data).hexdigest()


def canonical_json(data: Any) -> str:
    """
    Produce canonical, deterministic JSON string.
    Keys are sorted, and separators have no extra whitespace.
    """
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def is_valid_hex(hex_str: str, expected_length: int) -> bool:
    """Validate that a string is valid hex of exact length."""
    if not isinstance(hex_str, str):
        return False
    clean = hex_str.strip()
    if len(clean) != expected_length:
        return False
    try:
        int(clean, 16)
        return True
    except ValueError:
        return False


def verify_ed25519_signature(public_key_hex: str, signature_hex: str, sha256_hex: str) -> bool:
    """
    Cryptographically verify an Ed25519 detached signature against a SHA-256 fingerprint.
    
    Format:
    - public_key_hex: 64 hex characters (32 bytes public key)
    - signature_hex: 128 hex characters (64 bytes detached signature)
    - sha256_hex: 64 hex characters (32 bytes message digest)
    
    The signed message is the raw 32 bytes of the SHA-256 digest, exactly as produced
    by tweetnacl's `nacl.sign.detached(hexToUint8Array(hashHex), secretKey)`.
    """
    if not is_valid_hex(public_key_hex, 64):
        return False
    if not is_valid_hex(signature_hex, 128):
        return False
    if not is_valid_hex(sha256_hex, 64):
        return False

    try:
        public_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        message_bytes = bytes.fromhex(sha256_hex)

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(sig_bytes, message_bytes)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


def generate_keypair() -> Tuple[str, str]:
    """
    Generate a new Ed25519 keypair.
    Returns: (private_key_hex, public_key_hex)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_hex = private_key.private_bytes_raw().hex()
    public_hex = public_key.public_bytes_raw().hex()
    return private_hex, public_hex


def sign_hash(private_key_hex: str, sha256_hex: str) -> str:
    """
    Sign a 32-byte SHA-256 hash using an Ed25519 private key.
    Returns 128-hex-character detached signature.
    """
    private_bytes = bytes.fromhex(private_key_hex)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    message_bytes = bytes.fromhex(sha256_hex)
    signature_bytes = private_key.sign(message_bytes)
    return signature_bytes.hex()

