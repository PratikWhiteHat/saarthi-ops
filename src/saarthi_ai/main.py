from fastapi import FastAPI, HTTPException

from saarthi_ai.assessments.router import router as assessment_router
from saarthi_ai.config import get_settings
from saarthi_ai.execution.router import router as execution_router
from saarthi_ai.llm import OllamaUnavailableError, SaarthiOllamaClient
from saarthi_ai.schemas import ChatRequest, ChatResponse

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.3.0",
)

app.include_router(assessment_router)
app.include_router(execution_router)

llm = SaarthiOllamaClient(settings)


@app.get("/health")
async def health() -> dict[str, str]:
    """Return the Saarthi API health status."""

    return {
        "status": "ok",
        "service": settings.app_name,
        "environment": settings.environment,
    }


@app.get("/health/model")
async def model_health() -> dict[str, object]:
    """Check whether Ollama and the configured model are available."""

    try:
        return await llm.health()
    except OllamaUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc


@app.post("/v1/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """Send a message to the configured Saarthi model."""

    try:
        content, thinking = await llm.chat(
            request.messages,
            think=request.think,
        )
    except OllamaUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    return ChatResponse(
        model=settings.ollama_model,
        content=content,
        thinking=thinking,
    )
