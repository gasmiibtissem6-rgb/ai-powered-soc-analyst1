import asyncio
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from app.api import agents
from app.api import analyst
from app.api import metrics
from app.api import mitre
from app.api import ml
from app.api import reports
from app.api import soar
from app.api import suricata
from app.api import threat_intelligence
from app.api import wazuh
from app.api.ai_analysis import router as ai_analysis_router
from app.api.alerts import router as alerts_router
from app.api.auth import router as auth_router
from app.api.incidents import router as incidents_router
from app.observability.prometheus import REQUEST_COUNT, REQUEST_LATENCY
from app.services.workflow_retry_service import workflow_retry_loop


# =========================================================
# LIFESPAN
# =========================================================

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


# =========================================================
# APPLICATION
# =========================================================

app = FastAPI(
    title="AI-Powered SOC Analyst API",
    description="Backend API for the intelligent SOC platform",
    version="1.0.0",
    lifespan=lifespan,
)


# =========================================================
# PROMETHEUS MIDDLEWARE
# =========================================================

@app.middleware("http")
async def prometheus_middleware(
    request: Request,
    call_next,
):
    start_time = time.perf_counter()

    response = await call_next(request)

    duration = (
        time.perf_counter()
        - start_time
    )

    REQUEST_COUNT.labels(
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
    ).inc()

    REQUEST_LATENCY.labels(
        method=request.method,
        path=request.url.path,
    ).observe(duration)

    return response


# =========================================================
# PROMETHEUS ENDPOINT
# =========================================================

@app.get(
    "/prometheus",
    include_in_schema=False,
)
async def prometheus_metrics():
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
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
app.include_router(metrics.router)
app.include_router(analyst.router)

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