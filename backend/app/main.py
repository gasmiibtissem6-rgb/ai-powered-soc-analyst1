from fastapi import FastAPI
from app.api import wazuh
from app.api.incidents import router as incidents_router
from app.api.alerts import router as alerts_router
from app.api.auth import router as auth_router
from app.api.ai_analysis import router as ai_analysis_router
from app.api import ml
from app.api import threat_intelligence
from app.api import mitre
from app.api import agents
from app.api import reports
from app.api import soar
from app.api import suricata
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.services.workflow_retry_service import workflow_retry_loop
@asynccontextmanager
async def lifespan(app: FastAPI):
    retry_task = asyncio.create_task(
        workflow_retry_loop()
    )

    try:
        yield

    finally:
        retry_task.cancel()

        try:
            await retry_task

        except asyncio.CancelledError:
            pass
app = FastAPI(
    title="AI-Powered SOC Analyst API",
    description="Backend API for the intelligent SOC platform",
    version="1.0.0",
    lifespan=lifespan,
)


# =========================================================
# ROUTERS
# =========================================================
app.include_router(ml.router)
app.include_router(auth_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(ai_analysis_router)
app.include_router(soar.router)
app.include_router(threat_intelligence.router)
app.include_router(mitre.router)
app.include_router(agents.router)
app.include_router(wazuh.router)
app.include_router(suricata.router)
# SOC Reports
app.include_router(reports.router)


# =========================================================
# ROOT
# =========================================================

@app.get("/")
async def root():
    return {
        "message": "AI-Powered SOC Analyst API is running 🚀",
        "status": "ok",
    }


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
async def health():
    return {
        "status": "healthy",
    }
