import uuid
import time
import structlog
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from app.config import settings

log = structlog.get_logger()
security = HTTPBearer(auto_error=False)


def require_role(*roles: str):
    """Dependency factory that enforces JWT role."""
    async def _check(request: Request):
        claims = getattr(request.state, "jwt_claims", None)
        if claims is None:
            # Parse JWT directly for non-proxy endpoints
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                raise HTTPException(status_code=401, detail={"error": "missing_token"})
            token = auth.removeprefix("Bearer ").strip()
            try:
                claims = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
            except jwt.InvalidTokenError as exc:
                raise HTTPException(status_code=401, detail={"error": "invalid_token", "message": str(exc)})
            request.state.jwt_claims = claims

        role = claims.get("role", "user")
        if role not in roles:
            raise HTTPException(
                status_code=403,
                detail={"error": "insufficient_role", "required": list(roles), "actual": role},
            )
        return claims
    return _check


def require_admin():
    return require_role("admin")


def require_compliance_or_admin():
    return require_role("compliance_officer", "admin")
