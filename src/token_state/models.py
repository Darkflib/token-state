"""Data models for token information."""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class TokenStatus(str, Enum):
    """Token validity status."""

    VALID = "valid"
    EXPIRED = "expired"
    INVALID = "invalid"
    MISSING = "missing"
    UNKNOWN = "unknown"


class TokenType(str, Enum):
    """Type of token discovered."""

    JWT = "jwt"
    JWT_IDENTITY = "jwt_identity"
    JWT_ACCESS = "jwt_access"
    BEARER = "bearer"
    API_KEY = "api_key"
    OAUTH_ACCESS = "oauth_access"
    OAUTH_REFRESH = "oauth_refresh"
    SESSION = "session"
    UNKNOWN = "unknown"


class TokenSource(str, Enum):
    """Source where token was discovered."""

    VSCODE_EXTENSION = "vscode_extension"
    ENVIRONMENT = "environment"
    CONFIG_FILE = "config_file"
    BROWSER_COOKIE = "browser_cookie"
    UNKNOWN = "unknown"


class Platform(str, Enum):
    """Operating system platform."""

    WINDOWS = "windows"
    WSL = "wsl"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class TokenInfo(BaseModel):
    """Information about a discovered token."""

    service: str = Field(..., description="Service name (e.g., 'claude', 'codex')")
    token_type: TokenType = Field(default=TokenType.UNKNOWN, description="Type of token")
    status: TokenStatus = Field(default=TokenStatus.UNKNOWN, description="Token validity status")
    source: TokenSource = Field(default=TokenSource.UNKNOWN, description="Where token was found")
    location: Path | None = Field(default=None, description="File path where token was found")

    # Token data
    raw_token: str = Field(..., description="Raw token string")
    masked_token: str = Field(..., description="Masked token for display")

    # JWT-specific fields
    expires_at: datetime | None = Field(default=None, description="Token expiration time")
    issued_at: datetime | None = Field(default=None, description="Token issue time")
    issuer: str | None = Field(default=None, description="Token issuer")
    subject: str | None = Field(default=None, description="Token subject/user")
    scopes: list[str] = Field(default_factory=list, description="Token scopes/permissions")

    # Additional metadata
    claims: dict[str, Any] = Field(default_factory=dict, description="Additional JWT claims")
    platform: Platform = Field(default=Platform.UNKNOWN, description="Detected platform")

    @property
    def is_valid(self) -> bool:
        """Check if token is currently valid."""
        if self.status == TokenStatus.VALID:
            if self.expires_at:
                return datetime.utcnow() < self.expires_at
            return True
        return False

    @property
    def time_remaining(self) -> str | None:
        """Get human-readable time remaining until expiration."""
        if not self.expires_at:
            return None

        delta = self.expires_at - datetime.utcnow()
        if delta.total_seconds() < 0:
            return "Expired"

        days = delta.days
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, _ = divmod(remainder, 60)

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")

        return " ".join(parts) if parts else "< 1m"


class TokenSearchResult(BaseModel):
    """Results from token discovery operation."""

    platform: Platform = Field(..., description="Detected platform")
    raw_tokens: list[tuple[str, dict[str, Any]]] = Field(
        default_factory=list,
        description="Raw token strings with metadata before parsing",
    )
    tokens: list[TokenInfo] = Field(default_factory=list, description="Discovered tokens")
    errors: list[str] = Field(default_factory=list, description="Errors encountered")
    search_paths: list[Path] = Field(default_factory=list, description="Paths searched")

    @property
    def has_valid_tokens(self) -> bool:
        """Check if any valid tokens were found."""
        return any(token.is_valid for token in self.tokens)

    @property
    def claude_tokens(self) -> list[TokenInfo]:
        """Get only Claude tokens."""
        return [t for t in self.tokens if t.service.lower() == "claude"]

    @property
    def codex_tokens(self) -> list[TokenInfo]:
        """Get only Codex tokens."""
        return [t for t in self.tokens if t.service.lower() == "codex"]
