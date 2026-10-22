"""ScamShield backend entry point.  Run: .venv/bin/uvicorn app.main:app --port 8000"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.db import init_db
from app.tier0.local_model import local_models
from app.tier1.decision_client import decision_client
from app.tier2.auditor import auditor

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    await asyncio.to_thread(local_models.load)
    await decision_client.start()
    await auditor.start()
    logging.getLogger("scamshield").info("models=%s tier1=%s/%s llm=%s", local_models.status, decision_client.provider, decision_client.status, auditor.available)
    yield
    await decision_client.close()
    await auditor.close()


app = FastAPI(title="ScamShield API", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(router)
