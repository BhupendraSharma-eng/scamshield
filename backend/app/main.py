"""ScamShield backend entry point.  Run: .venv/bin/uvicorn app.main:app --port 8000"""

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.call_stream import router as call_router
from app.api.routes import router
from app.db import init_db
from app.tier0.local_model import local_models
from app.tier0.voice_deepfake import voice_detector
from app.tier1.decision_client import decision_client
from app.tier2.auditor import auditor

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    await asyncio.to_thread(local_models.load)
    await asyncio.to_thread(voice_detector.load)
    await decision_client.start()
    await auditor.start()
    logging.getLogger("scamshield").info(
        "models=%s tier1=%s/%s llm=%s deepfake=%s",
        local_models.status, decision_client.provider, decision_client.status, auditor.available, voice_detector.status,
    )
    yield
    await decision_client.close()
    await auditor.close()


app = FastAPI(title="ScamShield API", version="0.1.0", lifespan=lifespan)
# allow_private_network: lets the hosted UI (GitHub Pages, https) call a backend on localhost/LAN
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"], allow_private_network=True,
)

app.include_router(router)
app.include_router(call_router)

# Serve the built frontend (frontend/dist) at / with SPA fallback, so one server runs the whole demo.
DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str) -> FileResponse:
        target = (DIST / path).resolve()
        if path and target.is_file() and DIST in target.parents:
            return FileResponse(target)
        return FileResponse(DIST / "index.html")
