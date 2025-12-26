import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt

from token_state.token_parser import mask_token, parse_token
from token_state.models import Platform, TokenSource, TokenStatus, TokenType


def test_mask_token_masks_middle() -> None:
    token = "abcdefghijklmnopqrstuvwxyz"
    masked = mask_token(token)
    assert masked.startswith("abcd")
    assert masked.endswith("wxyz")
    assert "..." in masked


def test_parse_token_decodes_jwt_and_sets_status_valid() -> None:
    exp = datetime.now(UTC) + timedelta(minutes=5)
    payload = {"sub": "user", "iss": "tester", "exp": int(exp.timestamp())}
    token = jwt.encode(payload, key="", algorithm="none")

    info = parse_token(
        token,
        metadata={"service": "claude", "source": TokenSource.VSCODE_EXTENSION},
        platform=Platform.LINUX,
    )

    assert info.token_type == TokenType.JWT
    assert info.status == TokenStatus.VALID
    assert info.expires_at is not None
    assert info.subject == "user"
    assert info.issuer == "tester"


def test_parse_token_marks_expired() -> None:
    exp = datetime.now(UTC) - timedelta(minutes=1)
    token = jwt.encode({"exp": int(exp.timestamp())}, key="", algorithm="none")

    info = parse_token(token, metadata={}, platform=Platform.LINUX)

    assert info.status == TokenStatus.EXPIRED
