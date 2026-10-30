"""
SourceMark Configuration Module
Loads settings from environment variables with safe defaults.
"""

import os
import secrets
from typing import List


class Settings:
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", os.getenv("DATABASE_URL", "./sourcemark.db")).replace("sqlite:///", "")
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))
    MAX_UPLOAD_SIZE_BYTES: int = MAX_UPLOAD_SIZE_MB * 1024 * 1024

    # CORS Configuration
    CORS_ORIGINS_RAW: str = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000,*"
    )

    @property
    def cors_origins(self) -> List[str]:
        if not self.CORS_ORIGINS_RAW:
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS_RAW.split(",") if origin.strip()]

    API_TITLE: str = "SourceMark Provenance Engine API"
    API_VERSION: str = "2.0.0"
    API_DESCRIPTION: str = "Digital Content Provenance & Forensic Intelligence Platform"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # JWT Authentication
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))  # 8 hours

    # File storage
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "./uploads")


settings = Settings()

