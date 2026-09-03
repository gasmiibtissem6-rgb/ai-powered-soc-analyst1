from prometheus_client import Counter, Histogram


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