import json
import logging
import os
import time
import urllib.error
import urllib.request


EVE_PATH = "/var/log/suricata/eve.json"
API_URL = "http://127.0.0.1:8000/suricata/alerts"

logger = logging.getLogger(__name__)


SOC_INGESTION_API_KEY = os.getenv(
    "SOC_INGESTION_API_KEY",
    "",
)


def send_alert(alert: dict) -> None:
    payload = json.dumps(
        alert
    ).encode("utf-8")

    request = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-SOC-Ingestion-Key": SOC_INGESTION_API_KEY,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=30,
        ) as response:
            logger.info(
                "Suricata alert sent successfully"
            )

    except urllib.error.HTTPError as exc:
        logger.error(
            "FastAPI HTTP error code=%s",
            exc.code,
        )

    except Exception:
        logger.error(
            "Unable to send Suricata alert"
        )


def follow_eve_file() -> None:
    """
    Follow Suricata eve.json and forward
    only event_type='alert' records.
    """

    logger.info(
        "Suricata EVE forwarder started"
    )

    with open(
        EVE_PATH,
        "r",
        encoding="utf-8",
    ) as eve_file:

        # Start at the end of the file.
        # Existing historical events are ignored.
        eve_file.seek(
            0,
            2,
        )

        while True:
            line = eve_file.readline()

            if not line:
                time.sleep(0.5)
                continue

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(
                    line
                )

            except json.JSONDecodeError:
                continue

            if event.get(
                "event_type"
            ) != "alert":
                continue

            logger.info(
                "New Suricata alert detected"
            )

            send_alert(
                event
            )


if __name__ == "__main__":
    follow_eve_file()

