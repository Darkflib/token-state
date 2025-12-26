# token-state

CLI to discover and inspect local tokens for Claude (standalone extension prioritized) and Codex/GitHub Copilot.

## Features (MVP)

- Discovers Claude tokens from VS Code extension storage (standalone Claude first) and environment variables.
- Platform coverage: Windows, WSL (priority), Linux, macOS.
- Masks tokens by default; use `--show-full` to reveal (dangerous).
- Outputs a rich table or JSON (`--json`).

## Installation

Requires Python 3.12+ and `uv`.

```bash
uv tool install token-state
```

## Usage

```bash
token-state [--claude] [--codex] [--json] [--show-full] [-v]
```

Options:

- `--claude` / `--codex`: Filter services (default: show both).
- `--json`: Emit JSON instead of a table.
- `--show-full`: Show full tokens (off by default; tokens are masked otherwise).
- `-v, --verbose`: Show search paths and any discovery errors.

## Notes

- Primary discovery targets: VS Code globalStorage and extension folders, plus environment variables.
- WSL prioritizes both Linux-side VS Code Server paths and Windows-side paths under `/mnt/c/Users/...`.
- Token parsing attempts to decode JWTs to show issuer, subject, and expiry when available.

## License
MIT. See [LICENSE](LICENSE).

