from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.core.security import require_analyst
from app.models.user import User
from app.services.metrics_service import MetricsService


router = APIRouter(
    prefix="/metrics",
    tags=["metrics"],
)


@router.get("")
def get_soc_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    return MetricsService.get_global_metrics(
        db
    )
@router.get(
    "/severity",
)
def get_severity_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Return incident distribution by severity.
    """

    return MetricsService.get_severity_distribution(
        db
    )

@router.get(
    "/dashboard",
)
def get_dashboard_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Return complete SOC dashboard metrics.

    Includes:
    - operational metrics (MTTD / MTTR)
    - quality metrics
    - severity distribution
    """

    global_metrics = (
        MetricsService
        .get_global_metrics(db)
    )

    severity_distribution = (
        MetricsService
        .get_severity_distribution(db)
    )

    return {
        "operational": {
            "total_incidents": (
                global_metrics[
                    "total_incidents"
                ]
            ),
            "incidents_with_mttd": (
                global_metrics[
                    "incidents_with_mttd"
                ]
            ),
            "incidents_with_mttr": (
                global_metrics[
                    "incidents_with_mttr"
                ]
            ),
            "average_mttd_seconds": (
                global_metrics[
                    "average_mttd_seconds"
                ]
            ),
            "average_mttr_seconds": (
                global_metrics[
                    "average_mttr_seconds"
                ]
            ),
        },

        "quality": {
            "reviewed_incidents": (
                global_metrics[
                    "reviewed_incidents"
                ]
            ),
            "true_positive_count": (
                global_metrics[
                    "true_positive_count"
                ]
            ),
            "false_positive_count": (
                global_metrics[
                    "false_positive_count"
                ]
            ),
            "false_positive_rate": (
                global_metrics[
                    "false_positive_rate"
                ]
            ),
        },

        "severity": severity_distribution,
    }