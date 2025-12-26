"""Token discovery across different platforms and storage locations."""

import json
import os
import platform
import re
from pathlib import Path
from typing import Any

from .models import Platform, TokenSearchResult, TokenSource, TokenType


def detect_platform() -> Platform:
    """Detect the current operating system platform.

    Returns:
        Platform enum value indicating the detected OS.
    """
    system = platform.system().lower()

    # Check for WSL
    if system == "linux":
        try:
            with open("/proc/version", "r") as f:
                version_info = f.read().lower()
                if "microsoft" in version_info or "wsl" in version_info:
                    return Platform.WSL
        except (FileNotFoundError, PermissionError):
            pass
        return Platform.LINUX

    if system == "windows":
        return Platform.WINDOWS
    if system == "darwin":
        return Platform.MACOS

    return Platform.UNKNOWN


def get_vscode_paths(plat: Platform) -> list[Path]:
    """Get VS Code configuration paths for the given platform.

    Args:
        plat: The platform to get paths for.

    Returns:
        List of Path objects to search for VS Code configuration.
    """
    paths: list[Path] = []
    home = Path.home()

    if plat in (Platform.WSL, Platform.LINUX):
        # WSL/Linux VS Code Server paths (when using Remote-WSL)
        paths.extend(
            [
                home / ".vscode-server" / "data" / "User" / "globalStorage",
                home / ".vscode-server" / "extensions",
                # Native Linux VS Code paths
                home / ".config" / "Code" / "User" / "globalStorage",
                home / ".config" / "Code" / "extensions",
                # VS Code Insiders
                home / ".config" / "Code - Insiders" / "User" / "globalStorage",
                home / ".vscode-server-insiders" / "data" / "User" / "globalStorage",
            ]
        )

        if plat == Platform.WSL:
            # Also check Windows-side VS Code paths via /mnt/c for WSL users
            paths.extend(_get_wsl_windows_code_paths())

    elif plat == Platform.WINDOWS:
        appdata = Path(os.getenv("APPDATA", ""))
        if appdata.exists():
            paths.extend(
                [
                    appdata / "Code" / "User" / "globalStorage",
                    appdata / "Code - Insiders" / "User" / "globalStorage",
                ]
            )

        # Local AppData for extensions
        localappdata = Path(os.getenv("LOCALAPPDATA", ""))
        if localappdata.exists():
            paths.extend(
                [
                    localappdata / "Programs" / "Microsoft VS Code" / "resources",
                ]
            )

    elif plat == Platform.MACOS:
        paths.extend(
            [
                home / "Library" / "Application Support" / "Code" / "User" / "globalStorage",
                home
                / "Library"
                / "Application Support"
                / "Code - Insiders"
                / "User"
                / "globalStorage",
            ]
        )

    return [p for p in paths if p.exists()]


def get_claude_cli_paths(plat: Platform) -> list[Path]:
    """Return likely Claude CLI config paths for the platform."""

    home = Path.home()
    paths: list[Path] = []

    # Cross-platform default locations
    paths.extend(
        [
            home / ".claude" / ".credentials.json",
            home / ".anthropic" / "claude.json",
            home / ".anthropic" / "config.json",
            home / ".anthropic" / "keys.json",
            home / ".config" / "claude" / "config.json",
            home / ".config" / "claude" / "claude.json",
        ]
    )

    if plat == Platform.WINDOWS:
        appdata = Path(os.getenv("APPDATA", ""))
        if appdata.exists():
            paths.extend(
                [
                    appdata / "claude" / "config.json",
                    appdata / "Claude" / "config.json",
                    appdata / "Anthropic" / "claude.json",
                ]
            )

    if plat == Platform.WSL:
        # Also consider Windows-side config under /mnt/c/Users
        win_users = Path("/mnt/c/Users")
        if win_users.exists():
            for user_dir in win_users.iterdir():
                if not user_dir.is_dir():
                    continue
                appdata = user_dir / "AppData" / "Roaming"
                paths.extend(
                    [
                        user_dir / ".claude" / ".credentials.json",
                        appdata / "claude" / "config.json",
                        appdata / "Claude" / "config.json",
                        appdata / "Anthropic" / "claude.json",
                    ]
                )

    return [p for p in paths if p.exists()]


def get_codex_auth_paths(plat: Platform) -> list[Path]:
    """Return likely Codex/Copilot auth config paths."""

    home = Path.home()
    paths: list[Path] = [home / ".codex" / "auth.json"]

    if plat == Platform.WINDOWS:
        appdata = Path(os.getenv("APPDATA", ""))
        if appdata.exists():
            paths.append(appdata / "codex" / "auth.json")

    if plat == Platform.WSL:
        win_users = Path("/mnt/c/Users")
        if win_users.exists():
            for user_dir in win_users.iterdir():
                if not user_dir.is_dir():
                    continue
                appdata = user_dir / "AppData" / "Roaming"
                paths.extend(
                    [
                        user_dir / ".codex" / "auth.json",
                        appdata / "codex" / "auth.json",
                    ]
                )

    return [p for p in paths if p.exists()]


def _get_wsl_windows_code_paths() -> list[Path]:
    """Return VS Code paths on the Windows side when running inside WSL.

    Tries to locate the Windows user directory via common environment variables
    and falls back to scanning /mnt/c/Users.
    """

    usernames: list[str] = []
    for var in ("WINUSER", "WIN_USERNAME", "USERNAME", "USER"):
        val = os.getenv(var)
        if val:
            usernames.append(val)

    # Deduplicate while preserving order
    usernames = list(dict.fromkeys(usernames))

    candidates: list[Path] = []
    base_users = Path("/mnt/c/Users")

    if base_users.exists():
        if usernames:
            for user in usernames:
                candidates.append(base_users / user)
        else:
            # Fallback: include all directories under /mnt/c/Users
            candidates.extend([p for p in base_users.iterdir() if p.is_dir()])

    paths: list[Path] = []
    for user_dir in candidates:
        roaming = user_dir / "AppData" / "Roaming"
        paths.extend(
            [
                roaming / "Code" / "User" / "globalStorage",
                roaming / "Code - Insiders" / "User" / "globalStorage",
            ]
        )

    return [p for p in paths if p.exists()]


def get_claude_extension_paths(vscode_base_paths: list[Path]) -> list[Path]:
    """Get paths where Claude extension might store tokens.

    Args:
        vscode_base_paths: Base VS Code configuration paths.

    Returns:
        List of paths to check for Claude tokens.
    """
    claude_paths: list[Path] = []

    # Common Claude extension identifiers
    claude_extensions = [
        "saoudrizwan.claude-dev",  # Claude Dev extension
        "anthropic.claude",  # Official Anthropic extension
        "claude-ai.claude-ai",  # Alternative naming
    ]

    for base_path in vscode_base_paths:
        # Check globalStorage directories
        if "globalStorage" in str(base_path):
            for ext_id in claude_extensions:
                ext_path = base_path / ext_id
                if ext_path.exists():
                    claude_paths.append(ext_path)

        # Check extensions directories
        if "extensions" in str(base_path):
            for item in base_path.iterdir():
                if item.is_dir() and any(
                    ext_id in item.name.lower() for ext_id in claude_extensions
                ):
                    claude_paths.append(item)

    return claude_paths


def find_json_files(directory: Path) -> list[Path]:
    """Recursively find all JSON files in a directory.

    Args:
        directory: Directory to search.

    Returns:
        List of JSON file paths.
    """
    json_files: list[Path] = []

    try:
        for item in directory.rglob("*.json"):
            if item.is_file():
                json_files.append(item)
    except (PermissionError, OSError):
        pass

    return json_files


def extract_tokens_from_json(file_path: Path) -> list[tuple[str, dict[str, Any]]]:
    """Extract potential tokens from a JSON file.

    Args:
        file_path: Path to JSON file.

    Returns:
        List of tuples (token_string, metadata_dict).
    """
    tokens: list[tuple[str, dict[str, Any]]] = []

    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)

        # Recursively search for token-like strings
        tokens.extend(_search_dict_for_tokens(data, file_path, source=TokenSource.VSCODE_EXTENSION))
    except (json.JSONDecodeError, UnicodeDecodeError, PermissionError, OSError):
        pass

    return tokens


def _extract_tokens_from_cli_config(data: Any, file_path: Path) -> list[tuple[str, dict[str, Any]]]:
    """Look for Claude CLI access/refresh tokens in known fields."""

    tokens: list[tuple[str, dict[str, Any]]] = []

    def add_token(
        value: str | None,
        *,
        token_type_override: TokenType | None = None,
        expires_at: Any | None = None,
    ) -> None:
        if isinstance(value, str) and len(value) > 20:
            meta: dict[str, Any] = {
                "source": TokenSource.CONFIG_FILE,
                "location": file_path,
                "service": "claude",
            }
            if token_type_override:
                meta["token_type_override"] = token_type_override.value
            if expires_at is not None:
                meta["expires_at"] = expires_at
            tokens.append((value, meta))

    if isinstance(data, dict):
        # Known Claude CLI structure
        oauth = data.get("claudeAiOauth")
        if isinstance(oauth, dict):
            access_token = oauth.get("accessToken")
            access_expires = (
                oauth.get("accessTokenExpiresAt")
                or oauth.get("access_token_expires_at")
                or oauth.get("expiresAt")
                or oauth.get("accessTokenExpiry")
            )
            add_token(
                access_token, token_type_override=TokenType.OAUTH_ACCESS, expires_at=access_expires
            )

            # Also collect refreshToken (typed later in parser)
            refresh_token = oauth.get("refreshToken")
            refresh_expires = oauth.get("refreshTokenExpiresAt") or oauth.get(
                "refresh_token_expires_at"
            )
            add_token(
                refresh_token,
                token_type_override=TokenType.OAUTH_REFRESH,
                expires_at=refresh_expires,
            )

        # Fallback: look for generic access/token fields
        candidate_fields = [
            "access_token",
            "token",
            "api_key",
            "anthropic_api_key",
            "claude_token",
            "refresh_token",
        ]
        for key in candidate_fields:
            value = data.get(key)
            add_token(value)

        # Also search nested dictionaries (mark as config source)
        tokens.extend(
            _search_dict_for_tokens(
                data,
                file_path,
                source=TokenSource.CONFIG_FILE,
            )
        )

    return tokens


def _extract_codex_tokens(data: Any, file_path: Path) -> list[tuple[str, dict[str, Any]]]:
    """Extract Codex/Copilot tokens from auth.json style structures."""
    tokens: list[tuple[str, dict[str, Any]]] = []

    if isinstance(data, (list, tuple)):
        for item in data:
            tokens.extend(_extract_codex_tokens(item, file_path))
        return tokens

    def first_present(obj: dict[str, Any], keys: list[str]) -> Any | None:
        for key in keys:
            if key in obj and obj[key] is not None:
                return obj[key]
        return None

    def normalize_token_and_expiry(
        value: Any, expiry_keys: list[str]
    ) -> tuple[str | None, Any | None]:
        token_value: str | None = None
        expires: Any | None = None

        if isinstance(value, dict):
            token_value = value.get("token") or value.get("value") or value.get("access_token")
            expires = (
                first_present(value, expiry_keys)
                or value.get("expires_at")
                or value.get("expiresAt")
            )
        else:
            token_value = value if isinstance(value, str) else None

        return token_value, expires

    def add_token(
        value: str | None,
        *,
        token_type_override: TokenType | None = None,
        expires_at: Any | None = None,
        source_key: str | None = None,
    ) -> None:
        if isinstance(value, str):
            # Allow slightly shorter refresh tokens; keep JWT/API strict by length
            min_len = (
                8
                if token_type_override
                in (TokenType.OAUTH_REFRESH, TokenType.JWT_IDENTITY, TokenType.JWT_ACCESS)
                else 20
            )
            if len(value) < min_len:
                return
            meta: dict[str, Any] = {
                "source": TokenSource.CONFIG_FILE,
                "location": file_path,
                "service": "codex",
            }
            if token_type_override:
                meta["token_type_override"] = token_type_override.value
            if expires_at is not None:
                meta["expires_at"] = expires_at
            if source_key:
                meta["source_key"] = source_key
                meta["json_path"] = source_key
            tokens.append((value, meta))

    if isinstance(data, dict):
        # Direct fields commonly present in auth.json
        direct_fields: list[tuple[str, TokenType | None, list[str]]] = [
            (
                "id_token",
                TokenType.JWT_IDENTITY,
                ["id_token_expires_at", "idTokenExpiresAt", "id_expires_at"],
            ),
            (
                "access_token",
                TokenType.JWT_ACCESS,
                ["access_token_expires_at", "accessTokenExpiresAt", "expires_at", "expiresAt"],
            ),
            (
                "refresh_token",
                TokenType.OAUTH_REFRESH,
                ["refresh_token_expires_at", "refreshTokenExpiresAt"],
            ),
            ("token", None, ["expires_at", "expiresAt"]),
            ("bearer_token", TokenType.BEARER, ["expires_at", "expiresAt"]),
            ("codex_token", None, ["expires_at", "expiresAt"]),
        ]

        for field, override_type, expiry_keys in direct_fields:
            raw_value = data.get(field)
            token_value, nested_expiry = normalize_token_and_expiry(raw_value, expiry_keys)
            expiry_value = nested_expiry or first_present(data, expiry_keys)
            add_token(
                token_value,
                token_type_override=override_type,
                expires_at=expiry_value,
                source_key=field,
            )

        # Handle camelCase variants alongside sibling expiry fields
        camel_mappings: list[tuple[str, TokenType | None, list[str]]] = [
            (
                "idToken",
                TokenType.JWT_IDENTITY,
                ["idTokenExpiresAt", "idTokenExpiry", "idExpiresAt"],
            ),
            (
                "identityToken",
                TokenType.JWT_IDENTITY,
                ["identityTokenExpiresAt", "identityTokenExpiry"],
            ),
            (
                "accessToken",
                TokenType.JWT_ACCESS,
                ["accessTokenExpiresAt", "accessTokenExpiry", "expiresAt"],
            ),
            ("bearerToken", TokenType.BEARER, ["bearerTokenExpiresAt", "expiresAt"]),
            (
                "refreshToken",
                TokenType.OAUTH_REFRESH,
                ["refreshTokenExpiresAt", "refreshTokenExpiry"],
            ),
        ]

        for field, override_type, expiry_keys in camel_mappings:
            raw_value = data.get(field)
            token_value, nested_expiry = normalize_token_and_expiry(raw_value, expiry_keys)
            expiry_value = nested_expiry or first_present(data, expiry_keys)
            add_token(
                token_value,
                token_type_override=override_type,
                expires_at=expiry_value,
                source_key=field,
            )

        # Per-key fallback when a token-like string appears under a typed key
        for key, value in data.items():
            if not (isinstance(value, str) and len(value) > 20):
                continue
            key_lower = key.lower()
            expiry_candidates = [f"{key}ExpiresAt", f"{key}_expires_at", "expires_at", "expiresAt"]
            expiry_value = first_present(data, expiry_candidates)

            if any(fragment in key_lower for fragment in ["idtoken", "identity_token", "id_token"]):
                add_token(
                    value,
                    token_type_override=TokenType.JWT_IDENTITY,
                    expires_at=expiry_value,
                    source_key=key,
                )
            elif any(fragment in key_lower for fragment in ["accesstoken", "access_token"]):
                add_token(
                    value,
                    token_type_override=TokenType.JWT_ACCESS,
                    expires_at=expiry_value,
                    source_key=key,
                )
            elif "refresh_token" in key_lower or "refreshtoken" in key_lower:
                add_token(
                    value,
                    token_type_override=TokenType.OAUTH_REFRESH,
                    expires_at=expiry_value,
                    source_key=key,
                )

        # Recurse into common container fields
        for container_key in ("accounts", "sessions", "clients", "tokens"):
            container = data.get(container_key)
            if isinstance(container, dict):
                if container_key == "tokens":
                    tokens.extend(_extract_codex_tokens(container, file_path))
                else:
                    for nested in container.values():
                        tokens.extend(_extract_codex_tokens(nested, file_path))
            elif isinstance(container, (list, tuple)):
                for nested in container:
                    tokens.extend(_extract_codex_tokens(nested, file_path))

    # Generic search for token-like strings; annotate service as codex
    nested_tokens = _search_dict_for_tokens(
        data,
        file_path,
        source=TokenSource.CONFIG_FILE,
    )
    for token, meta in nested_tokens:
        meta["service"] = "codex"
        if "json_path" in meta:
            meta["source_key"] = meta.get("json_path")
        tokens.append((token, meta))

    return tokens


def _search_dict_for_tokens(
    obj: Any,
    source_path: Path,
    current_path: str = "",
    source: TokenSource = TokenSource.VSCODE_EXTENSION,
) -> list[tuple[str, dict[str, Any]]]:
    """Recursively search dictionary/list structures for token-like strings.

    Args:
        obj: Object to search (dict, list, or primitive).
        source_path: Path to the source file.
        current_path: Current JSON path for metadata.

    Returns:
        List of tuples (token_string, metadata_dict).
    """
    tokens: list[tuple[str, dict[str, Any]]] = []

    # Token patterns to look for
    token_patterns = [
        r"sk-ant-[a-zA-Z0-9\-_]{20,}",  # Anthropic API key pattern
        r"sess-[a-zA-Z0-9\-_]{20,}",  # Session token pattern
        r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",  # JWT pattern
    ]

    if isinstance(obj, dict):
        for key, value in obj.items():
            new_path = f"{current_path}.{key}" if current_path else key

            lower_key = key.lower()
            # Check if key suggests it contains a token
            if any(
                keyword in lower_key for keyword in ["token", "key", "auth", "session", "bearer"]
            ):
                if isinstance(value, str) and len(value) > 20:
                    # Check if value matches token patterns
                    for pattern in token_patterns:
                        if re.match(pattern, value):
                            metadata = {
                                "source": source,
                                "location": source_path,
                                "json_path": new_path,
                            }
                            tokens.append((value, metadata))
                            break

            # Recurse into nested structures
            tokens.extend(_search_dict_for_tokens(value, source_path, new_path))

    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            new_path = f"{current_path}[{idx}]"
            tokens.extend(_search_dict_for_tokens(item, source_path, new_path))

    elif isinstance(obj, str) and len(obj) > 20:
        # Check if the string itself is a token
        for pattern in token_patterns:
            if re.match(pattern, obj):
                metadata = {
                    "source": source,
                    "location": source_path,
                    "json_path": current_path,
                }
                tokens.append((obj, metadata))
                break

    return tokens


def check_environment_variables() -> list[tuple[str, dict[str, Any]]]:
    """Check environment variables for Claude/Codex tokens.

    Returns:
        List of tuples (token_string, metadata_dict).
    """
    tokens: list[tuple[str, dict[str, Any]]] = []

    env_vars_to_check = [
        "ANTHROPIC_API_KEY",
        "CLAUDE_API_KEY",
        "CLAUDE_TOKEN",
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
    ]

    for var_name in env_vars_to_check:
        value = os.getenv(var_name)
        if value and len(value) > 20:
            service = (
                "claude"
                if "claude" in var_name.lower() or "anthropic" in var_name.lower()
                else "codex"
            )
            metadata = {
                "source": TokenSource.ENVIRONMENT,
                "location": None,
                "env_var": var_name,
                "service": service,
            }
            tokens.append((value, metadata))

    return tokens


def find_tokens(platform_override: Platform | None = None) -> TokenSearchResult:
    """Find all tokens for Claude and Codex on the current system.

    Args:
        platform_override: Optional platform override for testing.

    Returns:
        TokenSearchResult with discovered tokens and metadata.
    """
    plat = platform_override if platform_override else detect_platform()
    result = TokenSearchResult(platform=plat)

    # Get VS Code paths
    vscode_paths = get_vscode_paths(plat)
    result.search_paths.extend(vscode_paths)

    # Find Claude extension paths
    claude_extension_paths = get_claude_extension_paths(vscode_paths)

    # Search for tokens in Claude extensions
    raw_tokens: list[tuple[str, dict[str, Any]]] = []

    for ext_path in claude_extension_paths:
        json_files = find_json_files(ext_path)
        for json_file in json_files:
            tokens_found = extract_tokens_from_json(json_file)
            raw_tokens.extend(tokens_found)

    # Search for tokens in Claude CLI config files
    cli_paths = get_claude_cli_paths(plat)
    result.search_paths.extend(cli_paths)
    for cli_path in cli_paths:
        try:
            with open(cli_path, encoding="utf-8") as f:
                data = json.load(f)
            raw_tokens.extend(_extract_tokens_from_cli_config(data, cli_path))
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            FileNotFoundError,
            PermissionError,
            OSError,
        ) as exc:
            result.errors.append(f"Failed to read {cli_path}: {exc}")

    # Search for tokens in Codex auth config
    codex_paths = get_codex_auth_paths(plat)
    result.search_paths.extend(codex_paths)
    for codex_path in codex_paths:
        try:
            with open(codex_path, encoding="utf-8") as f:
                data = json.load(f)
            raw_tokens.extend(_extract_codex_tokens(data, codex_path))
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            FileNotFoundError,
            PermissionError,
            OSError,
        ) as exc:
            result.errors.append(f"Failed to read {codex_path}: {exc}")

    # Check environment variables
    env_tokens = check_environment_variables()
    raw_tokens.extend(env_tokens)

    # Deduplicate by token/location pair
    result.raw_tokens = _dedup_raw_tokens(raw_tokens)

    return result


def _dedup_raw_tokens(
    raw_tokens: list[tuple[str, dict[str, Any]]],
) -> list[tuple[str, dict[str, Any]]]:
    """Remove duplicate token/location pairs while preserving order."""

    seen: set[tuple[str, str | None]] = set()
    deduped: list[tuple[str, dict[str, Any]]] = []

    for token, meta in raw_tokens:
        location = meta.get("location")
        key = (token, str(location) if location is not None else None)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((token, meta))

    return deduped
