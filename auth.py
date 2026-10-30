"""
SourceMark Authentication Module
JWT-based authentication with bcrypt password hashing.
Supports role-based access: admin, analyst (user).
"""

import datetime
import uuid
import logging
from typing import Optional, Dict, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from .config import settings

logger = logging.getLogger("sourcemark.auth")

# Password hashing context — bcrypt with sha256 fallback
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="passlib")
try:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    # Test bcrypt works
    pwd_context.hash("test")
except Exception:
    # Fallback to pbkdf2_sha256 if bcrypt fails
    pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# OAuth2 token scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def hash_password(plain: str) -> str:
    """Hash a plain-text password with bcrypt."""
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against bcrypt hash."""
    return pwd_context.verify(plain, hashed)


def create_access_token(user_id: str, email: str, role: str, expires_minutes: Optional[int] = None) -> str:
    """Create a signed JWT access token."""
    exp_minutes = expires_minutes or settings.JWT_EXPIRE_MINUTES
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=exp_minutes)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": expire,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT token. Returns payload dict or None."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


def get_current_user_optional(token: Optional[str] = Depends(oauth2_scheme)) -> Optional[Dict[str, Any]]:
    """Dependency: returns current user dict if authenticated, else None (for optional auth)."""
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    return {
        "id": payload.get("sub"),
        "email": payload.get("email"),
        "role": payload.get("role", "analyst"),
    }


def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """Dependency: requires authenticated user. Raises 401 if not authenticated."""
    user = get_current_user_optional(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Dependency: requires admin role."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required for this operation."
        )
    return current_user

