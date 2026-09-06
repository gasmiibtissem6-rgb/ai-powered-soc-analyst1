import asyncio
import logging

from fastapi import HTTPException

from app.database.session import SessionLocal
from app.models.incident import Incident


logger = logging.getLogger(__name__)


# =========================================================
# CONFIGURATION
# =========================================================

# 30 minutes between retry cycles.
# The first retry is also delayed by 30 minutes,
# so starting FastAPI does NOT immediately call the LLM provider.
RETRY_INTERVAL_SECONDS = 1800


# =========================================================
# RETRY ONE INCIDENT
# =========================================================

def retry_incident(incident_id: int) -> None:
    """
    Retry one incident whose workflow was rate-limited.

    A new database session is created because this function
    runs outside the normal FastAPI request lifecycle.
    """

    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(
                Incident.id == incident_id
            )
            .first()
        )

        if not incident:
            logger.warning(
                "Retry skipped: incident %s not found.",
                incident_id,
            )
            return

        if incident.workflow_status != "rate_limited":
            logger.info(
                "Retry skipped for incident %s: "
                "workflow_status=%s",
                incident.id,
                incident.workflow_status,
            )
            return

        # Local import avoids importing the agents router
        # when this module itself is imported by FastAPI.
        from app.api.agents import run_soc_workflow

        logger.info(
            "Retrying SOC workflow for incident %s.",
            incident.id,
        )

        try:
            result = run_soc_workflow(
                db=db,
                incident=incident,
                request=None,
            )

            logger.info(
                "SOC workflow retry finished for incident %s "
                "with status=%s.",
                incident.id,
                result.get("status"),
            )

        except HTTPException as exc:

            if exc.status_code == 429:
                # run_soc_workflow already persisted:
                # workflow_status = rate_limited
                logger.warning(
                    "Incident %s is still rate-limited.",
                    incident.id,
                )

            else:
                # run_soc_workflow already persists failed
                # for genuine workflow failures.
                logger.error(
                    "Retry failed for incident %s: HTTP %s - %s",
                    incident.id,
                    exc.status_code,
                    exc.detail,
                )

        except Exception as exc:
            logger.exception(
                "Unexpected retry error for incident %s: %s",
                incident.id,
                exc,
            )

    finally:
        db.close()


# =========================================================
# RETRY ALL RATE-LIMITED INCIDENTS
# =========================================================

def retry_rate_limited_incidents() -> None:
    """
    Find rate-limited incidents and retry each one once.
    """

    db = SessionLocal()

    try:
        incident_ids = [
            row[0]
            for row in (
                db.query(Incident.id)
                .filter(
                    Incident.workflow_status == "rate_limited"
                )
                .order_by(Incident.id.asc())
                .all()
            )
        ]

    finally:
        db.close()

    if not incident_ids:
        logger.info(
            "No rate-limited SOC workflows to retry."
        )
        return

    logger.info(
        "Found %s rate-limited SOC workflow(s).",
        len(incident_ids),
    )

    for incident_id in incident_ids:
        retry_incident(
            incident_id=incident_id
        )


# =========================================================
# BACKGROUND RETRY LOOP
# =========================================================

async def workflow_retry_loop() -> None:
    """
    Periodically retry rate-limited SOC workflows.

    Important:
    - no immediate retry at application startup;
    - one retry per incident per cycle;
    - synchronous workflow execution is moved to a thread;
    - FastAPI event loop is not blocked.
    """

    logger.info(
        "SOC workflow retry service started. "
        "Interval=%s seconds.",
        RETRY_INTERVAL_SECONDS,
    )

    while True:

        # Wait BEFORE the retry.
        # Starting/restarting FastAPI therefore does not
        # immediately consume LLM provider quota.
        await asyncio.sleep(
            RETRY_INTERVAL_SECONDS
        )

        try:
            await asyncio.to_thread(
                retry_rate_limited_incidents
            )

        except asyncio.CancelledError:
            logger.info(
                "SOC workflow retry service stopped."
            )
            raise

        except Exception:
            logger.exception(
                "Unexpected error in SOC workflow retry loop."
            )
