from datetime import datetime, timezone
from typing import Optional


def parse_iso8601_utc(
    value: Optional[str],
) -> Optional[datetime]:
    """
    Parse an ISO 8601 timestamp and normalize it
    to a naive UTC datetime for SQLAlchemy DateTime.

    Supported examples:
    2025-02-04T14:25:34.416117Z
    2022-02-07T00:00:00+00:00
    """

    if not value:
        return None

    try:
        timestamp = str(value).strip()

        if timestamp.endswith("Z"):
            timestamp = (
                timestamp[:-1]
                + "+00:00"
            )

        parsed = datetime.fromisoformat(
            timestamp
        )

        if parsed.tzinfo is not None:
            parsed = (
                parsed.astimezone(
                    timezone.utc
                )
                .replace(
                    tzinfo=None
                )
            )

        return parsed

    except (
        TypeError,
        ValueError,
    ):
        return None
