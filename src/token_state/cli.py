"""Command line interface for token-state."""

from __future__ import annotations

import json

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from .models import TokenInfo, TokenSource, TokenStatus
from .token_finder import find_tokens
from .token_parser import parse_tokens

app = typer.Typer(add_completion=False, help="Inspect Claude/Codex tokens on this machine.")
console = Console()


def _status_style(status: TokenStatus) -> str:
    return {
        TokenStatus.VALID: "green",
        TokenStatus.EXPIRED: "red",
        TokenStatus.INVALID: "red",
        TokenStatus.MISSING: "yellow",
        TokenStatus.UNKNOWN: "grey50",
    }.get(status, "white")


def _render_table(tokens: list[TokenInfo]) -> None:
    table = Table(title="Discovered Tokens", box=box.ROUNDED, highlight=True)
    table.add_column("Service", style="cyan")
    table.add_column("Status")
    table.add_column("Type")
    table.add_column("Expires")
    table.add_column("Source")
    table.add_column("Location", overflow="fold")
    table.add_column("Token", overflow="fold")

    for token in tokens:
        expires = token.expires_at.isoformat() if token.expires_at else "--"
        source = token.source.value if isinstance(token.source, TokenSource) else str(token.source)
        location = str(token.location) if token.location else "--"
        table.add_row(
            token.service,
            f"[{_status_style(token.status)}]{token.status.value}[/]",
            token.token_type.value,
            expires,
            source,
            location,
            token.masked_token,
        )

    console.print(table)


def _filter_services(tokens: list[TokenInfo], claude: bool, codex: bool) -> list[TokenInfo]:
    if claude and not codex:
        return [t for t in tokens if t.service.lower() == "claude"]
    if codex and not claude:
        return [t for t in tokens if t.service.lower() == "codex"]
    return tokens


@app.command()
def main(
    claude: bool = typer.Option(False, "--claude", help="Show only Claude tokens."),
    codex: bool = typer.Option(False, "--codex", help="Show only Codex tokens."),
    show_full: bool = typer.Option(
        False,
        "--show-full",
        help="Display full tokens (dangerous). Default is masked.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON instead of table."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show search paths and errors."),
) -> None:
    """Discover and display tokens for Claude/Codex."""

    result = find_tokens()
    tokens = parse_tokens(result.raw_tokens, result.platform, show_full=show_full)
    result.tokens = tokens

    filtered = _filter_services(tokens, claude, codex)

    if json_output:
        payload = [t.model_dump() for t in filtered]
        console.print_json(json.dumps(payload, default=str))
    else:
        if not filtered:
            console.print("[yellow]No tokens found.[/]")
        else:
            _render_table(filtered)

    if verbose:
        console.print("[bold]Platform:[/]", result.platform.value)
        if result.search_paths:
            console.print("[bold]Searched paths:[/]")
            for path in result.search_paths:
                console.print(f" - {path}")
        if result.errors:
            console.print("[bold red]Errors:[/]")
            for err in result.errors:
                console.print(f" - {err}")


if __name__ == "__main__":
    app()
