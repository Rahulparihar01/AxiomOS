import os
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

class KernelSettings(BaseModel):
    # System settings
    os_name: str = "AxiomOS"
    version: str = "1.0.0"
    log_level: str = os.getenv("AIOS_LOG_LEVEL", "INFO")
    
    # Process & Scheduling Limits
    default_token_budget: int = int(os.getenv("DEFAULT_TOKEN_BUDGET", "50000"))
    default_max_steps: int = int(os.getenv("DEFAULT_MAX_STEPS", "15"))
    default_timeout_seconds: float = float(os.getenv("DEFAULT_TIMEOUT_SECONDS", "60.0"))
    
    # Model Provider Settings
    default_provider: str = os.getenv("DEFAULT_PROVIDER", "mock")  # mock, gemini, openai, ollama
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model_name: str = os.getenv("MODEL_NAME", "gemini-1.5-flash")
    reasoning_model: str = os.getenv("REASONING_MODEL", "gemini-1.5-pro")
    fast_model: str = os.getenv("FAST_MODEL", "gemini-1.5-flash")
    default_workers: int = int(os.getenv("DEFAULT_WORKERS", "4"))
    
    # HTTP Client & Connection Pooling
    http_pool_max_keepalive: int = int(os.getenv("HTTP_POOL_MAX_KEEPALIVE", "20"))
    http_pool_max_connections: int = int(os.getenv("HTTP_POOL_MAX_CONNECTIONS", "100"))
    http_timeout_seconds: float = float(os.getenv("HTTP_TIMEOUT_SECONDS", "45.0"))

    # Pluggable Vectorizer & Memory Embeddings
    embedding_provider: str = os.getenv("EMBEDDING_PROVIDER", "hash")  # hash, openai, gemini
    embedding_model: str = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")

    # Sandbox Execution Backend
    sandbox_backend: str = os.getenv("SANDBOX_BACKEND", "local")  # local, docker
    sandbox_docker_image: str = os.getenv("SANDBOX_DOCKER_IMAGE", "python:3.11-slim")

    # Security & Control Plane
    admin_token: Optional[str] = os.getenv("AIOS_ADMIN_TOKEN", None)
    allowed_cors_origins: List[str] = [
        o.strip()
        for o in os.getenv(
            "AIOS_CORS_ORIGINS",
            "http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000"
        ).split(",")
        if o.strip()
    ]
    trace_retention_days: int = int(os.getenv("TRACE_RETENTION_DAYS", "14"))

    # Paths
    workspace_root: Path = Path(__file__).resolve().parent.parent

settings = KernelSettings()
