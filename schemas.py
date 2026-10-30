"""
SourceMark Pydantic Schemas v2
Adds auth, cases, batch verify, and enhanced compare response models.
"""

from pydantic import BaseModel, Field, field_validator, EmailStr
from typing import Optional, List, Dict, Any
from .crypto_utils import is_valid_hex


# ─── Auth ────────────────────────────────────────────────────────────────────

class UserRegisterPayload(BaseModel):
    username: str = Field(..., min_length=3, max_length=40)
    email: str = Field(..., min_length=5, max_length=120)
    password: str = Field(..., min_length=6, max_length=128)
    fullName: Optional[str] = ""
    organization: Optional[str] = ""

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v.replace("_", "").replace("-", "").replace(".", "").isalnum():
            raise ValueError("Username may only contain letters, numbers, underscores, hyphens, and dots.")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email address.")
        return v


class UserLoginPayload(BaseModel):
    email: str = Field(..., description="Email or username")
    password: str = Field(..., min_length=1)


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    fullName: Optional[str] = None
    organization: Optional[str] = None
    isActive: bool
    createdAt: str
    lastLoginAt: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ─── Source Registration & Verification ──────────────────────────────────────

class RegisterPayload(BaseModel):
    id: Optional[str] = None
    fileName: str = Field(..., min_length=1)
    fileType: Optional[str] = "application/octet-stream"
    fileSize: int = Field(..., ge=0)
    fileSizeFormatted: Optional[str] = None
    sha256: str = Field(..., min_length=64, max_length=64)
    signature: str = Field(..., min_length=128, max_length=128)
    publicKey: str = Field(..., min_length=64, max_length=64)
    keyId: str = Field(..., min_length=1)
    creator: str = Field(..., min_length=1)
    creatorId: str = Field(..., min_length=1)
    category: Optional[str] = "General"
    description: Optional[str] = ""
    sourceOrigin: Optional[str] = ""

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        clean = v.strip().lower()
        if not is_valid_hex(clean, 64):
            raise ValueError("sha256 must be a valid 64-character hexadecimal digest")
        return clean

    @field_validator("publicKey")
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        clean = v.strip().lower()
        if not is_valid_hex(clean, 64):
            raise ValueError("publicKey must be a valid 64-character hexadecimal string")
        return clean

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, v: str) -> str:
        clean = v.strip().lower()
        if not is_valid_hex(clean, 128):
            raise ValueError("signature must be a valid 128-character hexadecimal string")
        return clean


class VerifyPayload(BaseModel):
    sha256: str = Field(..., min_length=64, max_length=64)
    sourceId: Optional[str] = None
    fileName: Optional[str] = "inspected_asset"

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        clean = v.strip().lower()
        if not is_valid_hex(clean, 64):
            raise ValueError("sha256 must be a valid 64-character hexadecimal digest")
        return clean


class BatchVerifyItem(BaseModel):
    sha256: str = Field(..., min_length=64, max_length=64)
    sourceId: Optional[str] = None
    fileName: Optional[str] = "batch_file"

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        clean = v.strip().lower()
        if not is_valid_hex(clean, 64):
            raise ValueError("sha256 must be a valid 64-character hexadecimal digest")
        return clean


class BatchVerifyPayload(BaseModel):
    items: List[BatchVerifyItem] = Field(..., min_length=1, max_length=50)


# ─── Response Models ─────────────────────────────────────────────────────────

class SourceResponse(BaseModel):
    id: str
    fileName: str
    fileType: str
    fileSize: int
    fileSizeFormatted: Optional[str] = None
    sha256: str
    signature: str
    publicKey: str
    keyId: str
    creator: str
    creatorId: str
    category: Optional[str] = None
    description: Optional[str] = None
    sourceOrigin: Optional[str] = None
    registeredAt: str
    status: str
    verificationCount: int
    lastVerifiedAt: Optional[str] = None


class VerifyResponse(BaseModel):
    verdict: str
    status: str
    message: str
    details: str
    source: Optional[Dict[str, Any]] = None
    originalHash: Optional[str] = None
    uploadedHash: Optional[str] = None
    searchedHash: Optional[str] = None
    searchedSourceId: Optional[str] = None
    hashMatch: bool = False
    signatureValid: bool = False
    block: Optional[Dict[str, Any]] = None
    isDemoMode: bool = False


class CompareResponse(BaseModel):
    identical: bool
    sha256A: str
    sha256B: str
    fileNameA: str
    fileNameB: str
    fileSizeA: int
    fileSizeB: int
    sizeDiffBytes: int = 0
    sizeDiffPercent: float = 0.0
    fileTypeA: Optional[str] = None
    fileTypeB: Optional[str] = None
    isText: bool
    isImage: bool = False
    diff: Optional[List[str]] = None
    diffStats: Optional[Dict[str, Any]] = None
    imageComparison: Optional[Dict[str, Any]] = None
    binaryDiff: Optional[Dict[str, Any]] = None
    metadataDiff: Optional[Dict[str, Any]] = None
    spreadsheetComparison: Optional[Dict[str, Any]] = None
    disclaimer: str


class HistoryResponse(BaseModel):
    source: Dict[str, Any]
    events: List[Dict[str, Any]]
    ledgerBlocks: List[Dict[str, Any]]


class DashboardResponse(BaseModel):
    totalRegistered: int
    totalVerifications: int
    originalVerified: int
    editedDetected: int
    unknownDetected: int
    invalidSignatureDetected: int
    ledgerBlockCount: int
    ledgerValid: bool
    integrityScore: str
    cryptographicEngine: str
    fileTypeDistribution: List[Dict[str, Any]] = []
    recentActivity: List[Dict[str, Any]] = []
    activeCases: int = 0


class LedgerBlockResponse(BaseModel):
    id: str
    blockNumber: int
    type: str
    title: str
    timestamp: str
    prevHash: str
    currentHash: str
    status: str
    verified: bool
    payload: Dict[str, Any]


class LedgerValidateResponse(BaseModel):
    isValid: bool
    totalBlocks: int
    brokenAtBlock: Optional[str] = None
    details: List[Dict[str, Any]]
    limitationsNotice: str
    timestamp: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    database: str
    curve: str
    hasher: str
    timestamp: str


class SourceListResponse(BaseModel):
    total: int
    sources: List[Dict[str, Any]]


# ─── Cases ───────────────────────────────────────────────────────────────────

class CaseCreatePayload(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: Optional[str] = ""
    priority: Optional[str] = "NORMAL"


class CaseAddFilePayload(BaseModel):
    sourceId: str = Field(..., min_length=1)
    label: Optional[str] = ""


class CaseResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    status: str
    priority: str
    userId: Optional[str] = None
    createdAt: str
    updatedAt: str
    closedAt: Optional[str] = None
    fileCount: Optional[int] = 0
