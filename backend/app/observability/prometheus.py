from prometheus_client import Counter, Gauge, Histogram


# ==========================================================
# HTTP METRICS
# ==========================================================

REQUEST_COUNT = Counter(
    "soc_http_requests_total",
    "Total HTTP requests",
    [
        "method",
        "path",
        "status_code",
    ],
)


REQUEST_LATENCY = Histogram(
    "soc_http_request_duration_seconds",
    "HTTP request latency in seconds",
    [
        "method",
        "path",
    ],
)


# ==========================================================
# SOC OPERATIONAL METRICS
# ==========================================================

TOTAL_INCIDENTS = Gauge(
    "soc_total_incidents",
    "Total number of SOC incidents",
)

INCIDENTS_WITH_MTTD = Gauge(
    "soc_incidents_with_mttd",
    "Number of incidents with calculated MTTD",
)

INCIDENTS_WITH_MTTR = Gauge(
    "soc_incidents_with_mttr",
    "Number of incidents with calculated MTTR",
)

AVERAGE_MTTD = Gauge(
    "soc_average_mttd_seconds",
    "Average Mean Time To Detect in seconds",
)

AVERAGE_MTTR = Gauge(
    "soc_average_mttr_seconds",
    "Average Mean Time To Respond in seconds",
)


# ==========================================================
# INCIDENT QUALITY METRICS
# ==========================================================

REVIEWED_INCIDENTS = Gauge(
    "soc_reviewed_incidents",
    "Number of incidents reviewed by analysts",
)

FALSE_POSITIVE_COUNT = Gauge(
    "soc_false_positive_count",
    "Number of incidents classified as false positives",
)

TRUE_POSITIVE_COUNT = Gauge(
    "soc_true_positive_count",
    "Number of incidents classified as true positives",
)

FALSE_POSITIVE_RATE = Gauge(
    "soc_false_positive_rate",
    "Percentage of reviewed incidents classified as false positives",
)


# ==========================================================
# INCIDENT SEVERITY
# ==========================================================

INCIDENTS_BY_SEVERITY = Gauge(
    "soc_incidents_by_severity",
    "Number of SOC incidents grouped by severity",
    [
        "severity",
    ],
)