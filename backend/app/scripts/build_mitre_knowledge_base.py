import json
from pathlib import Path
from typing import Dict, List, Optional


BACKEND_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

PROJECT_ROOT = (
    BACKEND_ROOT.parent
)

MITRE_SOURCE = (
    BACKEND_ROOT
    / "data"
    / "enterprise-attack.json"
)

OUTPUT_DIRECTORY = (
    PROJECT_ROOT
    / "data"
    / "knowledge_base"
    / "mitre"
)

OUTPUT_FILE = (
    OUTPUT_DIRECTORY
    / "mitre_enterprise_attack.md"
)


def get_external_id(
    technique: Dict,
) -> Optional[str]:

    for reference in technique.get(
        "external_references",
        [],
    ):
        if (
            reference.get("source_name")
            == "mitre-attack"
        ):
            return reference.get(
                "external_id"
            )

    return None


def get_mitre_url(
    technique: Dict,
) -> Optional[str]:

    for reference in technique.get(
        "external_references",
        [],
    ):
        if (
            reference.get("source_name")
            == "mitre-attack"
        ):
            return reference.get("url")

    return None


def get_tactics(
    technique: Dict,
) -> List[str]:

    tactics = []

    for phase in technique.get(
        "kill_chain_phases",
        [],
    ):
        if (
            phase.get("kill_chain_name")
            == "mitre-attack"
        ):
            phase_name = phase.get(
                "phase_name"
            )

            if phase_name:
                tactics.append(
                    phase_name
                )

    return sorted(
        set(tactics)
    )


def clean_description(
    description: str,
) -> str:

    return (
        description
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .strip()
    )


def build_knowledge_base() -> None:

    if not MITRE_SOURCE.exists():
        raise FileNotFoundError(
            "MITRE ATT&CK source not found: "
            + str(MITRE_SOURCE)
        )

    data = json.loads(
        MITRE_SOURCE.read_text(
            encoding="utf-8"
        )
    )

    techniques = []

    for obj in data.get(
        "objects",
        [],
    ):
        if obj.get("type") != "attack-pattern":
            continue

        # Ignore deprecated/revoked ATT&CK objects.
        if obj.get("revoked", False):
            continue

        if obj.get(
            "x_mitre_deprecated",
            False,
        ):
            continue

        technique_id = get_external_id(
            obj
        )

        if not technique_id:
            continue

        techniques.append(
            (
                technique_id,
                obj,
            )
        )

    techniques.sort(
        key=lambda item: item[0]
    )

    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    lines = [
        "# MITRE ATT&CK Enterprise Knowledge Base",
        "",
        (
            "Generated from the local "
            "`enterprise-attack.json` STIX bundle."
        ),
        "",
        (
            "This document is used by the SOC "
            "RAG pipeline for semantic retrieval."
        ),
        "",
        "---",
        "",
    ]

    for technique_id, technique in techniques:

        name = technique.get(
            "name",
            "Unknown technique",
        )

        description = clean_description(
            technique.get(
                "description",
                "",
            )
        )

        tactics = get_tactics(
            technique
        )

        mitre_url = get_mitre_url(
            technique
        )

        lines.extend(
            [
                (
                    "## "
                    + technique_id
                    + " - "
                    + name
                ),
                "",
                "**Technique ID:** "
                + technique_id,
                "",
                "**Name:** "
                + name,
                "",
            ]
        )

        if tactics:
            lines.extend(
                [
                    "**Tactics:** "
                    + ", ".join(tactics),
                    "",
                ]
            )

        if description:
            lines.extend(
                [
                    "### Description",
                    "",
                    description,
                    "",
                ]
            )

        if mitre_url:
            lines.extend(
                [
                    "**MITRE reference:** "
                    + mitre_url,
                    "",
                ]
            )

        lines.extend(
            [
                "---",
                "",
            ]
        )

    OUTPUT_FILE.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print(
        "MITRE knowledge base generated: OK"
    )

    print(
        "Source:",
        MITRE_SOURCE,
    )

    print(
        "Output:",
        OUTPUT_FILE,
    )

    print(
        "Active techniques:",
        len(techniques),
    )

    print(
        "Size:",
        OUTPUT_FILE.stat().st_size,
        "bytes",
    )


if __name__ == "__main__":
    build_knowledge_base()
