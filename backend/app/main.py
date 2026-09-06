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
from app.database.session import SessionLocal
from app.observability.prometheus import (
    AVERAGE_MTTD,
    AVERAGE_MTTR,
    FALSE_POSITIVE_COUNT,
    FALSE_POSITIVE_RATE,
    INCIDENTS_BY_SEVERITY,
    INCIDENTS_WITH_MTTD,
    INCIDENTS_WITH_MTTR,
    REQUEST_COUNT,
    REQUEST_LATENCY,
    REVIEWED_INCIDENTS,
    TOTAL_INCIDENTS,
    TRUE_POSITIVE_COUNT,
)
from app.services.metrics_service import MetricsService
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
    db = SessionLocal()

    try:
        global_metrics = MetricsService.get_global_metrics(db)
        severity_distribution = (
            MetricsService.get_severity_distribution(db)
        )

        # --------------------------------------------------
        # Global SOC metrics
        # --------------------------------------------------

        TOTAL_INCIDENTS.set(
            global_metrics["total_incidents"]
        )

        INCIDENTS_WITH_MTTD.set(
            global_metrics["incidents_with_mttd"]
        )

        INCIDENTS_WITH_MTTR.set(
            global_metrics["incidents_with_mttr"]
        )

        average_mttd = global_metrics[
            "average_mttd_seconds"
        ]

        average_mttr = global_metrics[
            "average_mttr_seconds"
        ]

        AVERAGE_MTTD.set(
            average_mttd
            if average_mttd is not None
            else float("nan")
        )

        AVERAGE_MTTR.set(
            average_mttr
            if average_mttr is not None
            else float("nan")
        )

        # --------------------------------------------------
        # Incident quality metrics
        # --------------------------------------------------

        REVIEWED_INCIDENTS.set(
            global_metrics["reviewed_incidents"]
        )

        FALSE_POSITIVE_COUNT.set(
            global_metrics["false_positive_count"]
        )

        TRUE_POSITIVE_COUNT.set(
            global_metrics["true_positive_count"]
        )

        false_positive_rate = global_metrics[
            "false_positive_rate"
        ]

        FALSE_POSITIVE_RATE.set(
            false_positive_rate
            if false_positive_rate is not None
            else float("nan")
        )

        # --------------------------------------------------
        # Severity distribution
        # --------------------------------------------------

        for severity, count in severity_distribution.items():
            INCIDENTS_BY_SEVERITY.labels(
                severity=severity
            ).set(count)

        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )

    finally:
        db.close()


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