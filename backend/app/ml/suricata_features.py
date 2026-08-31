from datetime import datetime
from typing import Any, Dict


def _duration_seconds(start: str, end: str) -> float:
    """
    Calculate flow duration in seconds from
    Suricata ISO-8601 timestamps.
    """
    if not start or not end:
        return 0.0

    try:
        start_dt = datetime.fromisoformat(start)
        end_dt = datetime.fromisoformat(end)

        duration = (
            end_dt - start_dt
        ).total_seconds()

        return max(duration, 0.0)

    except (TypeError, ValueError):
        return 0.0


def extract_suricata_flow_features(
    event: Dict[str, Any],
) -> Dict[str, float]:
    """
    Convert a Suricata EVE flow event into a compact
    numeric feature vector for real-time anomaly detection.

    These features are intentionally separate from the
    78 CICIDS2017 features used by the supervised
    Random Forest model.
    """

    if event.get("event_type") != "flow":
        raise ValueError(
            "Expected a Suricata event_type='flow'."
        )

    flow = event.get("flow") or {}
    tcp = event.get("tcp") or {}

    pkts_to_server = float(
        flow.get("pkts_toserver") or 0
    )

    pkts_to_client = float(
        flow.get("pkts_toclient") or 0
    )

    bytes_to_server = float(
        flow.get("bytes_toserver") or 0
    )

    bytes_to_client = float(
        flow.get("bytes_toclient") or 0
    )

    duration = _duration_seconds(
        flow.get("start"),
        flow.get("end"),
    )

    if duration <= 0:
        duration = float(
            flow.get("age") or 0
        )

    total_packets = (
        pkts_to_server
        + pkts_to_client
    )

    total_bytes = (
        bytes_to_server
        + bytes_to_client
    )

    if duration > 0:
        packets_per_second = (
            total_packets / duration
        )

        bytes_per_second = (
            total_bytes / duration
        )

    else:
        packets_per_second = 0.0
        bytes_per_second = 0.0

    return {
        "destination_port": float(
            event.get("dest_port") or 0
        ),
        "duration_seconds": duration,
        "pkts_to_server": pkts_to_server,
        "pkts_to_client": pkts_to_client,
        "bytes_to_server": bytes_to_server,
        "bytes_to_client": bytes_to_client,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "syn_flag": float(
            bool(tcp.get("syn"))
        ),
        "fin_flag": float(
            bool(tcp.get("fin"))
        ),
        "psh_flag": float(
            bool(tcp.get("psh"))
        ),
        "ack_flag": float(
            bool(tcp.get("ack"))
        ),
        "alerted": float(
            bool(flow.get("alerted"))
        ),
    }