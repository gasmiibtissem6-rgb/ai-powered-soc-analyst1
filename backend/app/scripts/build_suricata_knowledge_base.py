from pathlib import Path


def main() -> None:
    project_root = Path(__file__).resolve().parents[3]

    output_directory = (
        project_root
        / "data"
        / "knowledge_base"
        / "suricata"
    )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = (
        output_directory
        / "suricata_soc_reference.md"
    )

    sections = [
        {
            "id": "eve-json",
            "title": "EVE JSON Output",
            "url": (
                "https://docs.suricata.io/en/latest/"
                "output/eve/eve-json-output.html"
            ),
            "content": """
Suricata EVE is the main JSON event output facility.

EVE can record alerts, anomalies, metadata, file
information, flow information, and protocol-specific
events.

A common configuration writes these records into:

/var/log/suricata/eve.json

Each EVE record contains an event_type field that identifies
the type of event, such as alert, flow, dns, http, tls, or
anomaly.

EVE JSON is particularly useful for SOC pipelines because
events can be consumed by log collectors, SIEM platforms,
analytics systems, and custom security applications.
""",
        },
        {
            "id": "alert-events",
            "title": "Alert Events",
            "url": (
                "https://docs.suricata.io/en/latest/"
                "output/eve/eve-json-output.html"
            ),
            "content": """
Suricata generates alert events when network traffic matches
a detection rule.

An EVE alert record can contain network information such as
source and destination IP addresses, ports, protocol, flow
identifier, timestamp, and application-layer protocol.

The alert object contains information related to the
matching signature, including signature information,
category, severity, and identifiers when available.

SOC analysts can use this information to understand which
rule fired, which systems communicated, and how the event
should be prioritized.
""",
        },
        {
            "id": "rules-format",
            "title": "Rules and Signatures",
            "url": (
                "https://docs.suricata.io/en/latest/"
                "rules/intro.html"
            ),
            "content": """
Suricata detection signatures are also called rules.

A Suricata rule contains three main elements:

1. An action.
2. A rule header.
3. Rule options.

The header defines information such as protocol, source and
destination addresses, source and destination ports, and
traffic direction.

Rule options define the specific detection conditions and
metadata associated with the signature.
""",
        },
        {
            "id": "rule-actions",
            "title": "Rule Actions",
            "url": (
                "https://docs.suricata.io/en/latest/"
                "rules/intro.html"
            ),
            "content": """
Suricata rules support actions that determine how matching
traffic is handled.

The alert action generates an alert when the rule matches.

The pass action can stop further inspection for matching
traffic.

In IPS deployments, actions such as drop and reject can
actively prevent or reject matching traffic.

For a passive SOC IDS deployment, alert rules are commonly
used to identify suspicious or malicious network activity
without blocking the traffic.
""",
        },
        {
            "id": "rule-metadata",
            "title": "Rule Metadata",
            "url": (
                "https://docs.suricata.io/en/latest/"
                "rules/meta.html"
            ),
            "content": """
Suricata signatures include metadata keywords that help
identify and classify detections.

The msg keyword provides the human-readable description of
the signature.

The sid keyword uniquely identifies a signature.

The rev keyword represents the revision of a signature.

The classtype keyword associates a signature with a security
classification.

Additional metadata such as priority and references can
provide useful context for SOC investigation and
prioritization.
""",
        },
        {
            "id": "network-direction",
            "title": "Network Direction and Variables",
            "url": (
                "https://docs.suricata.io/en/latest/"
                "rules/intro.html"
            ),
            "content": """
Suricata rule headers define the traffic source,
destination, ports, protocol, and direction.

Variables such as HOME_NET and EXTERNAL_NET can be defined
in suricata.yaml and reused by detection rules.

The arrow in a rule determines the direction in which the
signature is evaluated.

Correct HOME_NET configuration is important because it
allows rules to distinguish protected internal systems from
external network traffic.
""",
        },
        {
            "id": "suricata-update",
            "title": "Rule Management with Suricata Update",
            "url": (
                "https://docs.suricata.io/en/latest/"
                "quickstart.html"
            ),
            "content": """
The suricata-update utility is used to download, update, and
manage Suricata detection rulesets.

A common command is:

suricata-update

The default rule installation can use:

/var/lib/suricata/rules/suricata.rules

After updating rules, Suricata can be restarted so that the
new detection rules are loaded.
""",
        },
        {
            "id": "operational-logs",
            "title": "Operational Logs",
            "url": (
                "https://docs.suricata.io/en/latest/"
                "quickstart.html"
            ),
            "content": """
Suricata maintains operational logs that can be used for
health monitoring and troubleshooting.

The main engine log is commonly located at:

/var/log/suricata/suricata.log

Statistics can be inspected through:

/var/log/suricata/stats.log

The EVE JSON file contains security and protocol events,
while suricata.log is useful for engine status and
operational troubleshooting.
""",
        },
        {
            "id": "soc-investigation",
            "title": "SOC Investigation of Suricata Alerts",
            "url": (
                "https://docs.suricata.io/en/latest/"
                "output/eve/eve-json-output.html"
            ),
            "content": """
A SOC investigation can correlate Suricata alert events with
other EVE records that share network or flow context.

Useful investigation fields can include timestamp,
source IP, destination IP, source port, destination port,
protocol, application protocol, flow identifier, signature,
category, and severity.

These fields can be correlated with endpoint alerts,
threat-intelligence results, incident records, and other
network telemetry to produce a more complete security
incident timeline.
""",
        },
    ]

    lines = [
        "# Suricata SOC Knowledge Reference",
        "",
        "**Source:** Official Suricata documentation",
        "**Documentation branch:** latest",
        "**Purpose:** SOC network alert analysis and RAG retrieval",
        "",
        (
            "This document contains a curated Suricata "
            "technical reference for the AI-Powered SOC "
            "Analyst knowledge base."
        ),
        "",
    ]

    for section in sections:
        lines.extend(
            [
                (
                    "## SURICATA-"
                    + section["id"]
                    + " - "
                    + section["title"]
                ),
                "",
                (
                    "**Suricata Topic ID:** SURICATA-"
                    + section["id"]
                ),
                (
                    "**Topic:** "
                    + section["title"]
                ),
                (
                    "**Official Source:** "
                    + section["url"]
                ),
                "",
                "### SOC Reference",
                "",
                section["content"].strip(),
                "",
            ]
        )

    output_path.write_text(
        "\n".join(lines).strip() + "\n",
        encoding="utf-8",
    )

    print("Suricata knowledge base generated: OK")
    print("Output:", output_path)
    print("Topics generated:", len(sections))
    print(
        "Size:",
        output_path.stat().st_size,
        "bytes",
    )


if __name__ == "__main__":
    main()
