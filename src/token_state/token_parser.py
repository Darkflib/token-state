"""Token parsing and masking utilities."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
import re
from typing import Any

import jwt

from .models import Platform, TokenInfo, TokenSource, TokenStatus, TokenType


JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+")
API_KEY_PATTERN = re.compile(r"sk-ant-[a-zA-Z0-9\-_]{6,}")
SESSION_PATTERN = re.compile(r"sess-[a-zA-Z0-9\-_]{20,}")


def mask_token(
    token: str,
    show_full: bool = False,
    *,
    visible_prefix: int = 4,
    visible_suffix: int = 6,
) -> str:
    """Return a masked representation of the token unless show_full is True."""

    if show_full:
        return token

    visible_total = visible_prefix + visible_suffix
    if len(token) <= visible_total:
        return "*" * len(token)

    return f"{token[:visible_prefix]}...{token[-visible_suffix:]}"


def detect_token_type(token: str) -> TokenType:
    """Classify a token string into a TokenType."""
    if JWT_PATTERN.fullmatch(token):
        return TokenType.JWT
    if API_KEY_PATTERN.fullmatch(token):
        # Distinguish OAuth access vs refresh based on third segment markers
        if "-oat01-" in token:
            return TokenType.OAUTH_ACCESS
        if "-ort01-" in token:
            return TokenType.OAUTH_REFRESH
        return TokenType.API_KEY
    if SESSION_PATTERN.fullmatch(token):
        return TokenType.SESSION
    if token.startswith("sk-"):
        if "-oat01-" in token:
            return TokenType.OAUTH_ACCESS
        if "-ort01-" in token:
            return TokenType.OAUTH_REFRESH
        return TokenType.API_KEY
    return TokenType.UNKNOWN


def _extract_datetime(claims: dict[str, Any], key: str) -> datetime | None:
    value = claims.get(key)
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (TypeError, ValueError, OSError):
        return None


def _coerce_datetime(value: Any) -> datetime | None:
    """Attempt to coerce common timestamp formats to datetime (UTC)."""

    if value is None:
        return None

    if isinstance(value, datetime):
        return value

    # Epoch seconds or milliseconds
    if isinstance(value, (int, float)):
        try:
            ts = float(value)
            # Heuristic: treat large numbers as milliseconds
            if ts > 1e12:
                ts /= 1000.0
            return datetime.fromtimestamp(ts, tz=UTC)
        except (OSError, ValueError):
            return None

    if isinstance(value, str):
        # Try ISO-8601
        try:
            dt = datetime.fromisoformat(value)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
        # Try numeric string
        try:
            num = float(value)
            return _coerce_datetime(num)
        except ValueError:
            return None

    return None


def parse_token(
    token: str,
    metadata: dict[str, Any],
    platform: Platform,
    *,
    show_full: bool = False,
) -> TokenInfo:
    """Parse a single token string into TokenInfo, decoding JWT claims when possible."""
    override_type = metadata.get("token_type_override")
    token_type = None
    if override_type:
        try:
            token_type = TokenType(override_type)
        except Exception:
            token_type = None

    if token_type is None:
        source_key = (metadata.get("source_key") or metadata.get("json_path") or "").lower()
        service = (metadata.get("service") or "").lower()
        if service == "codex" and source_key:
            if any(k in source_key for k in ["id_token", "identitytoken", "idtoken"]):
                token_type = TokenType.JWT_IDENTITY
            elif any(k in source_key for k in ["access_token", "accesstoken"]):
                token_type = TokenType.JWT_ACCESS
            elif any(k in source_key for k in ["refresh_token", "refreshtoken"]):
                token_type = TokenType.OAUTH_REFRESH

    # Codex heuristic fallback when still undetermined but we know it's a codex JWT
    if token_type is None:
        service = (metadata.get("service") or "").lower()
        source_key = (metadata.get("source_key") or metadata.get("json_path") or "").lower()
        if service == "codex" and JWT_PATTERN.fullmatch(token):
            if any(
                fragment in source_key
                for fragment in ["id_token", "identitytoken", "idtoken", "tokens.id"]
            ):
                token_type = TokenType.JWT_IDENTITY
            elif "refresh" in source_key:
                token_type = TokenType.OAUTH_REFRESH
            else:
                token_type = TokenType.JWT_ACCESS

    if token_type is None:
        token_type = detect_token_type(token)

    masked = mask_token(token, show_full=show_full)

    claims: dict[str, Any] = {}
    expires_at: datetime | None = None
    issued_at: datetime | None = None
    issuer: str | None = None
    subject: str | None = None
    scopes: list[str] = []
    status = TokenStatus.UNKNOWN

    metadata_expires = _coerce_datetime(metadata.get("expires_at"))

    if token_type in {TokenType.JWT, TokenType.JWT_ACCESS, TokenType.JWT_IDENTITY}:
        try:
            claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
            expires_at = metadata_expires or _extract_datetime(claims, "exp")
            issued_at = _extract_datetime(claims, "iat")
            issuer = claims.get("iss")
            subject = claims.get("sub")

            raw_scope = claims.get("scope") or claims.get("scp") or claims.get("permissions")
            if isinstance(raw_scope, str):
                scopes = raw_scope.replace(",", " ").split()
            elif isinstance(raw_scope, (list, tuple)):
                scopes = [str(s) for s in raw_scope]

            if expires_at:
                status = (
                    TokenStatus.EXPIRED if datetime.now(UTC) >= expires_at else TokenStatus.VALID
                )
            else:
                status = TokenStatus.VALID
        except Exception:
            if metadata_expires:
                expires_at = metadata_expires
                status = (
                    TokenStatus.EXPIRED
                    if datetime.now(UTC) >= metadata_expires
                    else TokenStatus.VALID
                )
            else:
                status = TokenStatus.INVALID
    else:
        # Non-JWT tokens: derive validity from metadata if available
        if metadata_expires:
            expires_at = metadata_expires
            status = (
                TokenStatus.EXPIRED if datetime.now(UTC) >= metadata_expires else TokenStatus.VALID
            )
        else:
            status = TokenStatus.VALID

    service = metadata.get("service") or "claude"
    source = metadata.get("source", TokenSource.UNKNOWN)
    location = metadata.get("location")

    return TokenInfo(
        service=service,
        token_type=token_type,
        status=status,
        source=source,
        location=location,
        raw_token=token,
        masked_token=masked,
        expires_at=expires_at,
        issued_at=issued_at,
        issuer=issuer,
        subject=subject,
        scopes=scopes,
        claims=claims,
        platform=platform,
    )


def parse_tokens(
    raw_tokens: Iterable[tuple[str, dict[str, Any]]],
    platform: Platform,
    *,
    show_full: bool = False,
) -> list[TokenInfo]:
    """Parse a collection of raw tokens into TokenInfo objects."""
    parsed: list[TokenInfo] = []
    for token, metadata in raw_tokens:
        try:
            info = parse_token(token, metadata, platform, show_full=show_full)

            # Final codex-specific normalization using path hints
            service = (metadata.get("service") or "").lower()
            path_hint = (metadata.get("source_key") or metadata.get("json_path") or "").lower()
            if service == "codex" and path_hint:
                if "refresh_token" in path_hint or "refreshtoken" in path_hint:
                    info.token_type = TokenType.OAUTH_REFRESH
                elif "id_token" in path_hint or "identitytoken" in path_hint or ".id" in path_hint:
                    info.token_type = TokenType.JWT_IDENTITY
                elif "access_token" in path_hint or "accesstoken" in path_hint:
                    info.token_type = TokenType.JWT_ACCESS

            parsed.append(info)
        except Exception:
            # If parsing fails, store a minimal invalid token entry
            parsed.append(
                TokenInfo(
                    service=metadata.get("service") or "claude",
                    token_type=detect_token_type(token),
                    status=TokenStatus.INVALID,
                    source=metadata.get("source", TokenSource.UNKNOWN),
                    location=metadata.get("location"),
                    raw_token=token,
                    masked_token=mask_token(token, show_full=show_full),
                    platform=platform,
                )
            )
    return parsed
