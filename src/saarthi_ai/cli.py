import asyncio

import typer
from rich.console import Console
from rich.markdown import Markdown

from saarthi_ai.config import get_settings
from saarthi_ai.llm import OllamaUnavailableError, SaarthiOllamaClient
from saarthi_ai.schemas import Message

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command()
def doctor() -> None:
    """Check the local Ollama service and configured model."""

    async def run() -> None:
        client = SaarthiOllamaClient(get_settings())
        try:
            status = await client.health()
        except OllamaUnavailableError as exc:
            console.print(f"[bold red]Failed:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc

        console.print("[bold green]Ollama is reachable.[/bold green]")
        console.print(status)
        if not status["model_available"]:
            console.print(
                "[yellow]Configured model is missing. Run:[/yellow] "
                f"ollama pull {status['configured_model']}"
            )
            raise typer.Exit(code=1)

    asyncio.run(run())


@app.command()
def chat(think: bool = typer.Option(False, help="Enable model thinking output.")) -> None:
    """Start a local terminal chat with Saarthi."""

    async def run() -> None:
        client = SaarthiOllamaClient(get_settings())
        history: list[Message] = []
        console.print("[bold]Saarthi local chat[/bold] — type /exit to quit.")

        while True:
            user_input = console.input("\n[bold cyan]You>[/bold cyan] ").strip()
            if user_input.lower() in {"/exit", "/quit"}:
                break
            if not user_input:
                continue

            history.append(Message(role="user", content=user_input))
            try:
                content, thinking = await client.chat(history, think=think)
            except OllamaUnavailableError as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                continue

            if think and thinking:
                console.print("\n[dim]Model thinking received (not stored in chat history).[/dim]")
            console.print("\n[bold green]Saarthi>[/bold green]")
            console.print(Markdown(content))
            history.append(Message(role="assistant", content=content))

    asyncio.run(run())
