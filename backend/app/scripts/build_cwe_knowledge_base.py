import html
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional


def clean_text(value: Optional[str]) -> str:
    if not value:
        return ""

    value = html.unescape(value)

    value = re.sub(
        r"\s+",
        " ",
        value,
    )

    return value.strip()


def get_text(
    element: Optional[ET.Element],
) -> str:
    if element is None:
        return ""

    text = " ".join(
        part.strip()
        for part in element.itertext()
        if part and part.strip()
    )

    return clean_text(
        text
    )


def get_child_text(
    parent: ET.Element,
    namespace: dict,
    child_name: str,
) -> str:
    child = parent.find(
        "cwe:" + child_name,
        namespace,
    )

    return get_text(
        child
    )


def get_list_text(
    parent: ET.Element,
    namespace: dict,
    path: str,
) -> List[str]:
    values = []

    for element in parent.findall(
        path,
        namespace,
    ):
        value = get_text(
            element
        )

        if value:
            values.append(
                value
            )

    return values


def build_cwe_knowledge_base() -> None:
    backend_root = (
        Path(__file__)
        .resolve()
        .parents[2]
    )

    project_root = (
        backend_root.parent
    )

    source_path = (
        backend_root
        / "data"
        / "cwe"
        / "cwec_v4.20.xml"
    )

    output_directory = (
        project_root
        / "data"
        / "knowledge_base"
        / "cwe"
    )

    output_path = (
        output_directory
        / "cwe_weaknesses.md"
    )

    if not source_path.exists():
        raise FileNotFoundError(
            "CWE XML source not found: "
            + str(source_path)
        )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    tree = ET.parse(
        source_path
    )

    root = tree.getroot()

    namespace_uri = (
        root.tag
        .split("}")[0]
        .strip("{")
    )

    namespace = {
        "cwe": namespace_uri
    }

    weaknesses = root.findall(
        ".//cwe:Weakness",
        namespace,
    )

    sections = []

    header = """# CWE Knowledge Base

**Source:** MITRE Common Weakness Enumeration (CWE)

**Version:** 4.20

**Source format:** Official CWE XML catalog

This knowledge-base document was generated from the official local CWE XML catalog.

Each section represents one CWE weakness and is intended for semantic retrieval by the SOC RAG pipeline.

---
"""

    sections.append(
        header
    )

    processed_count = 0

    for weakness in weaknesses:
        cwe_id = (
            weakness.get(
                "ID",
                "",
            )
            .strip()
        )

        cwe_name = (
            weakness.get(
                "Name",
                "",
            )
            .strip()
        )

        abstraction = (
            weakness.get(
                "Abstraction",
                "",
            )
            .strip()
        )

        structure = (
            weakness.get(
                "Structure",
                "",
            )
            .strip()
        )

        status = (
            weakness.get(
                "Status",
                "",
            )
            .strip()
        )

        if not cwe_id:
            continue

        description = get_child_text(
            weakness,
            namespace,
            "Description",
        )

        extended_description = (
            get_child_text(
                weakness,
                namespace,
                "Extended_Description",
            )
        )

        likelihood = get_child_text(
            weakness,
            namespace,
            "Likelihood_Of_Exploit",
        )

        consequences = get_list_text(
            weakness,
            namespace,
            (
                "cwe:Common_Consequences/"
                "cwe:Consequence"
            ),
        )

        mitigations = get_list_text(
            weakness,
            namespace,
            (
                "cwe:Potential_Mitigations/"
                "cwe:Mitigation"
            ),
        )

        detection_methods = (
            get_list_text(
                weakness,
                namespace,
                (
                    "cwe:Detection_Methods/"
                    "cwe:Detection_Method"
                ),
            )
        )

        related_weaknesses = []

        for relationship in weakness.findall(
            (
                "cwe:Related_Weaknesses/"
                "cwe:Related_Weakness"
            ),
            namespace,
        ):
            related_cwe_id = (
                relationship.get(
                    "CWE_ID",
                    "",
                )
                .strip()
            )

            nature = (
                relationship.get(
                    "Nature",
                    "",
                )
                .strip()
            )

            if related_cwe_id:
                value = (
                    "CWE-"
                    + related_cwe_id
                )

                if nature:
                    value += (
                        " ("
                        + nature
                        + ")"
                    )

                related_weaknesses.append(
                    value
                )

        observed_examples = []

        for example in weakness.findall(
            (
                "cwe:Observed_Examples/"
                "cwe:Observed_Example"
            ),
            namespace,
        ):
            reference = get_child_text(
                example,
                namespace,
                "Reference",
            )

            description_example = (
                get_child_text(
                    example,
                    namespace,
                    "Description",
                )
            )

            if (
                reference
                or description_example
            ):
                value_parts = []

                if reference:
                    value_parts.append(
                        reference
                    )

                if description_example:
                    value_parts.append(
                        description_example
                    )

                observed_examples.append(
                    " - ".join(
                        value_parts
                    )
                )

        section_lines = [
            (
                "## CWE-"
                + cwe_id
                + " - "
                + cwe_name
            ),
            "",
            (
                "**CWE ID:** CWE-"
                + cwe_id
            ),
            "",
            (
                "**Name:** "
                + cwe_name
            ),
            "",
        ]

        if abstraction:
            section_lines.extend(
                [
                    (
                        "**Abstraction:** "
                        + abstraction
                    ),
                    "",
                ]
            )

        if structure:
            section_lines.extend(
                [
                    (
                        "**Structure:** "
                        + structure
                    ),
                    "",
                ]
            )

        if status:
            section_lines.extend(
                [
                    (
                        "**Status:** "
                        + status
                    ),
                    "",
                ]
            )

        if likelihood:
            section_lines.extend(
                [
                    (
                        "**Likelihood of Exploit:** "
                        + likelihood
                    ),
                    "",
                ]
            )

        if description:
            section_lines.extend(
                [
                    "### Description",
                    "",
                    description,
                    "",
                ]
            )

        if extended_description:
            section_lines.extend(
                [
                    "### Extended Description",
                    "",
                    extended_description,
                    "",
                ]
            )

        if consequences:
            section_lines.extend(
                [
                    "### Common Consequences",
                    "",
                ]
            )

            for consequence in consequences:
                section_lines.append(
                    "- " + consequence
                )

            section_lines.append(
                ""
            )

        if mitigations:
            section_lines.extend(
                [
                    "### Potential Mitigations",
                    "",
                ]
            )

            for mitigation in mitigations:
                section_lines.append(
                    "- " + mitigation
                )

            section_lines.append(
                ""
            )

        if detection_methods:
            section_lines.extend(
                [
                    "### Detection Methods",
                    "",
                ]
            )

            for detection_method in detection_methods:
                section_lines.append(
                    "- " + detection_method
                )

            section_lines.append(
                ""
            )

        if related_weaknesses:
            section_lines.extend(
                [
                    "### Related Weaknesses",
                    "",
                ]
            )

            for related in related_weaknesses:
                section_lines.append(
                    "- " + related
                )

            section_lines.append(
                ""
            )

        if observed_examples:
            section_lines.extend(
                [
                    "### Observed Examples",
                    "",
                ]
            )

            for example in observed_examples:
                section_lines.append(
                    "- " + example
                )

            section_lines.append(
                ""
            )

        section_lines.extend(
            [
                "---",
                "",
            ]
        )

        sections.append(
            "\n".join(
                section_lines
            )
        )

        processed_count += 1

    output_path.write_text(
        "\n".join(
            sections
        ),
        encoding="utf-8",
    )

    print(
        "CWE knowledge base generated: OK"
    )

    print(
        "Source:",
        source_path,
    )

    print(
        "Output:",
        output_path,
    )

    print(
        "Weaknesses found:",
        len(weaknesses),
    )

    print(
        "Weaknesses generated:",
        processed_count,
    )

    print(
        "Size:",
        output_path.stat().st_size,
        "bytes",
    )


if __name__ == "__main__":
    build_cwe_knowledge_base()

