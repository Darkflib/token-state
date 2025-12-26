# AGENTS.md

This file serves as a comprehensive guide for AI agents working within the `token-state` repository. It outlines the project's purpose, technical stack, code hygiene practices, and operational guidelines.

## Project Overview

The `token-state` project is a Command Line Interface (CLI) tool designed to discover and inspect local authentication tokens, primarily for services like Claude (focusing on standalone VS Code extension storage) and Codex/GitHub Copilot.

### Key Features:
- **Token Discovery:** Locates Claude tokens from VS Code extension storage and environment variables.
- **Platform Support:** Compatible with Windows, WSL, Linux, and macOS.
- **Security:** Masks tokens by default; full token display is an opt-in (and dangerous) option.
- **Output Formats:** Provides output in a rich table format or JSON.
- **Token Parsing:** Attempts to decode JWTs to extract and display issuer, subject, and expiry information.

### Core Modules:
- `src/token_state/cli.py`: Defines the command-line interface using `typer`.
- `src/token_state/models.py`: Contains data models for tokens and related states (e.g., `Token`, `TokenState`).
- `src/token_state/token_finder.py`: Implements the logic for locating tokens across various paths and environments.
- `src/token_state/token_parser.py`: Handles the parsing and decoding of discovered tokens.

## Technical Stack and Toolchain

### Language:
- Python 3.12+

### Dependency Management:
- **`uv`**: Used for installing and managing project dependencies. The `uv.lock` file ensures reproducible environments.
- **`hatchling`**: Build backend for the project.

### Core Libraries:
- **`typer`**: For building the command-line interface.
- **`rich`**: For rich text and beautiful formatting in the terminal output.
- **`pyjwt`**: For handling JSON Web Tokens (JWT) parsing and decoding.
- **`pydantic`**: For data validation and settings management.
- **`pydantic-settings`**: For managing application settings.
- **`cryptography`**: Provides cryptographic primitives, used by `pyjwt`.

## Code Hygiene and Quality Assurance

The project enforces strict code hygiene through a set of automated tools and pre-commit hooks.

### Formatting:
- **`ruff format`**: An extremely fast Python formatter, written in Rust.
  - Configuration: `line-length = 100`, `target-version = "py312"`.
  - Replaces `black` and `isort`.

### Linting:
- **`ruff`**: An extremely fast Python linter, written in Rust.
  - Configuration: `line-length = 100`, `target-version = "py312"`.
  - Selects various `pycodestyle`, `pyflakes`, `isort`, `flake8-bugbear`, `flake8-comprehensions`, and `pyupgrade` rules.
  - Ignores `E501` (line too long, handled by formatter) and `B008` (function calls in argument defaults).
  - Ignores `F401` (unused imports) in `__init__.py` files.

### Type Checking:
- **`mypy`**: A static type checker for Python.
  - Configuration: `python_version = "3.12"`, with strict settings including `warn_return_any`, `disallow_untyped_defs`, `disallow_incomplete_defs`, `check_untyped_defs`, `disallow_untyped_calls`, `disallow_any_generics`, `no_implicit_optional`, `warn_redundant_casts`, `warn_unused_ignores`, `warn_no_return`.

### Testing:
- **`pytest`**: A mature full-featured Python testing framework.
  - Configuration: `minversion = "8.0"`, `testpaths = ["tests"]`.
  - **`pytest-cov`**: Plugin for measuring code coverage.
    - Generates HTML coverage reports.
    - Excludes specific lines/patterns from coverage reports (e.g., `pragma: no cover`, `if __name__ == "__main__":`).

### Pre-commit Hooks:
The project utilizes `pre-commit` to automatically run checks before commits, ensuring code quality and consistency.
- **Standard Hooks**: `trailing-whitespace`, `end-of-file-fixer`, `check-yaml`, `check-added-large-files`, `check-json`, `check-toml`, `check-merge-conflict`, `detect-private-key`.
- **Tool-specific Hooks**: `ruff` (with `--fix` and `--exit-non-zero-on-fix`), `ruff-format`, `mypy`.

## Development Guidelines for Agents

- **Adhere to Existing Conventions:** Always follow the established code style, structure, and architectural patterns.
- **Utilize Pre-commit Hooks:** Ensure `pre-commit install` is run in the environment to catch issues early.
- **Write Tests:** New features and bug fixes must be accompanied by comprehensive unit tests.
- **Maintain Coverage:** Strive for high code coverage, especially for critical logic.
- **Documentation:** Keep `README.md` and other documentation up-to-date with any changes.

## How to Set Up the Development Environment

1.  **Install `uv`**:
    ```bash
    pip install uv
    ```
2.  **Create and Activate Virtual Environment**:
    ```bash
    uv venv
    source .venv/bin/activate
    ```
3.  **Install Dependencies**:
    ```bash
    uv pip install -e .[dev]
    ```
    (This installs both runtime and development dependencies defined in `pyproject.toml`.)
4.  **Install Pre-commit Hooks**:
    ```bash
    pre-commit install
    ```

## How to Run Checks Manually

- **Run Tests**:
    ```bash
    pytest
    ```
- **Run Linting**:
    ```bash
    ruff check .
    ```
- **Run Formatting (check only)**:
    ```bash
    ruff format --check .
    ```
- **Run Type Checking**:
    ```bash
    mypy src/
    ```
