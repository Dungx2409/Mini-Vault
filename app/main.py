from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app.config import get_settings
from app.core.vault_state import vault_state
from app.database import Base, engine
from app.exceptions import install_handlers
from app.router import router


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(engine)
    vault_state.lock()
    yield
    vault_state.lock()


app = FastAPI(title="Mini Vault", version="1.0.0", lifespan=lifespan,
              description="Secure storage and transit cryptography REST API")
install_handlers(app)


@app.middleware("http")
async def request_size_limit(request: Request, call_next):
    length = request.headers.get("content-length")
    try:
        too_large = bool(length) and int(length) > get_settings().max_request_bytes + 8192
    except ValueError:
        too_large = True
    if too_large:
        return JSONResponse({"success": False, "data": None,
                             "error": {"code": "VALIDATION_ERROR", "message": "Request is too large"}}, 413)
    return await call_next(request)


@app.get("/health", tags=["Health"], summary="Health check")
async def health():
    return {"status": "ok"}


app.include_router(router)
