from __future__ import annotations

import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

os.environ.setdefault("PSYCOPG_IMPL", "python")

from app.api.auth import auth_middleware
from app.api.public_review import public_review_middleware
from app.api.routes import router

app = FastAPI(
    title="RouteBrain API",
    description="API interna de consulta para observabilidade BGP, mudanças de rota e enriquecimento com inventário.",
    version="0.1.0",
)

app.middleware("http")(public_review_middleware)
app.middleware("http")(auth_middleware)
app.include_router(router)

static_dir = Path(__file__).resolve().parents[1] / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
