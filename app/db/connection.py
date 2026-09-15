from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("PSYCOPG_IMPL", "python")

import psycopg

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - fallback for minimal shell environments
    load_dotenv = None


def _load_environment() -> None:
    """Load environment variables from the project .env file if present."""
    project_root = Path(__file__).resolve().parents[2]
    env_path = project_root / ".env"
    if load_dotenv is not None:
        load_dotenv(env_path)
        load_dotenv()
        return
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def get_database_url() -> str:
    _load_environment()
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL não definido.")
    return database_url


def get_connection() -> psycopg.Connection:
    return psycopg.connect(get_database_url())
