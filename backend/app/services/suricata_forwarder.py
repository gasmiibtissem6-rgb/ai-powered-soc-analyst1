import json
import os
import time
import urllib.error
import urllib.request


EVE_PATH = "/var/log/suricata/eve.json"
API_URL = "http://127.0.0.1:8000/suricata/alerts"

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
            print(
                "Suricata alert sent successfully"
            )

    except urllib.error.HTTPError as exc:
        print(
            f"FastAPI HTTP error "
            f"{exc.code}"
        )

    except Exception as exc:
        print(
            "Unable to send Suricata alert:"
        )
        print(str(exc))


def follow_eve_file() -> None:
    """
    Follow Suricata eve.json and forward
    only event_type='alert' records.
    """

    print(
        f"Watching {EVE_PATH}"
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

            print(
                "New Suricata alert detected:"
            )

            alert_data = (
                event.get("alert")
                or {}
            )

            print(
                alert_data.get(
                    "signature",
                    "Unknown signature",
                )
            )

            send_alert(
                event
            )


if __name__ == "__main__":
    follow_eve_file()

