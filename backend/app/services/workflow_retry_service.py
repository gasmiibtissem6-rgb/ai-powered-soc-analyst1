import asyncio
import logging
from typing import Literal

from fastapi import HTTPException

from app.database.session import SessionLocal
from app.models.incident import Incident


logger = logging.getLogger(__name__)


# =========================================================
# CONFIGURATION
# =========================================================

# 30 minutes between retry cycles.
#
# The first retry is also delayed by 30 minutes, so starting
# FastAPI does NOT immediately consume LLM provider quota.
RETRY_INTERVAL_SECONDS = 1800

# Maximum number of rate-limited incidents retried during
# one background cycle.
#
# This prevents a large backlog from generating a burst of
# requests against the LLM provider.
RETRY_BATCH_SIZE = 5


RetryResult = Literal[
    "completed",
    "rate_limited",
    "failed",
    "skipped",
]


# =========================================================
# RETRY ONE INCIDENT
# =========================================================

def retry_incident(
    incident_id: int,
) -> RetryResult:
    """
    Retry one incident whose workflow was rate-limited.

    A new database session is created because this function
    runs outside the normal FastAPI request lifecycle.

    Returns:
        completed:
            Workflow retry returned successfully.

        rate_limited:
            LLM provider is still rate-limiting requests.

        failed:
            Workflow failed for another reason.

        skipped:
            Incident does not exist or is no longer
            rate-limited.
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
            return "skipped"

        if (
            incident.workflow_status
            != "rate_limited"
        ):
            logger.info(
                "Retry skipped for incident %s: "
                "workflow_status=%s",
                incident.id,
                incident.workflow_status,
            )
            return "skipped"

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
                "SOC workflow retry finished for "
                "incident %s with status=%s.",
                incident.id,
                result.get("status"),
            )

            return "completed"

        except HTTPException as exc:

            if exc.status_code == 429:
                # run_soc_workflow already persisted:
                # workflow_status = rate_limited
                logger.warning(
                    "Incident %s is still rate-limited.",
                    incident.id,
                )

                return "rate_limited"

            # run_soc_workflow already persists failed
            # for genuine workflow failures.
            logger.error(
                "Retry failed for incident %s: "
                "HTTP %s - %s",
                incident.id,
                exc.status_code,
                exc.detail,
            )

            return "failed"

        except Exception as exc:
            logger.exception(
                "Unexpected retry error for "
                "incident %s: %s",
                incident.id,
                exc,
            )

            return "failed"

    finally:
        db.close()


# =========================================================
# RETRY RATE-LIMITED INCIDENT BATCH
# =========================================================

def retry_rate_limited_incidents() -> None:
    """
    Retry a small batch of rate-limited incidents.

    Protection against provider saturation:
    - only RETRY_BATCH_SIZE incidents are selected;
    - oldest rate-limited incidents are retried first;
    - if the provider returns another rate limit, the
      current cycle stops immediately.
    """

    db = SessionLocal()

    try:
        incident_ids = [
            row[0]
            for row in (
                db.query(Incident.id)
                .filter(
                    Incident.workflow_status
                    == "rate_limited"
                )
                .order_by(
                    Incident.id.asc()
                )
                .limit(
                    RETRY_BATCH_SIZE
                )
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
        "Retrying batch of %s rate-limited "
        "SOC workflow(s). Batch limit=%s.",
        len(incident_ids),
        RETRY_BATCH_SIZE,
    )

    for incident_id in incident_ids:

        result = retry_incident(
            incident_id=incident_id
        )

        # If the provider is still rate-limited,
        # do not waste the remaining requests in
        # this cycle.
        if result == "rate_limited":
            logger.warning(
                "LLM provider is still rate-limited. "
                "Stopping current retry cycle."
            )
            break


# =========================================================
# BACKGROUND RETRY LOOP
# =========================================================

async def workflow_retry_loop() -> None:
    """
    Periodically retry rate-limited SOC workflows.

    Important:
    - no immediate retry at application startup;
    - small retry batch per cycle;
    - cycle stops after the first provider rate limit;
    - synchronous workflow execution is moved to a thread;
    - FastAPI event loop is not blocked.
    """

    logger.info(
        "SOC workflow retry service started. "
        "Interval=%s seconds. Batch size=%s.",
        RETRY_INTERVAL_SECONDS,
        RETRY_BATCH_SIZE,
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
                "Unexpected error in "
                "SOC workflow retry loop."
            )
