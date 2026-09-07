import json
from pathlib import Path
from typing import Any, Dict, List, Optional


BASE_DIR = Path(__file__).resolve().parents[2]
SOURCE_DIR = BASE_DIR / "data" / "cve" / "selected"
OUTPUT_FILE = (
    BASE_DIR.parent
    / "data"
    / "knowledge_base"
    / "cve"
    / "cve_selected.md"
)


def first_english_description(
    descriptions: List[Dict[str, Any]],
) -> str:
    for item in descriptions:
        if item.get("lang") == "en":
            value = item.get("value")
            if value:
                return str(value).strip()

    for item in descriptions:
        value = item.get("value")
        if value:
            return str(value).strip()

    return ""


def extract_cwe_ids(
    cna: Dict[str, Any],
) -> List[str]:
    cwe_ids = []

    problem_types = cna.get(
        "problemTypes",
        [],
    )

    for problem_type in problem_types:
        descriptions = problem_type.get(
            "descriptions",
            [],
        )

        for description in descriptions:
            cwe_id = description.get(
                "cweId"
            )

            if (
                cwe_id
                and cwe_id not in cwe_ids
            ):
                cwe_ids.append(cwe_id)

    return cwe_ids


def extract_cvss_from_metrics(
    metrics: List[Dict[str, Any]],
) -> Dict[str, Optional[Any]]:
    result = {
        "version": None,
        "base_score": None,
        "base_severity": None,
        "vector": None,
    }

    for metric in metrics:
        for key in (
            "cvssV4_0",
            "cvssV3_1",
            "cvssV3_0",
            "cvssV2_0",
        ):
            cvss = metric.get(key)

            if not isinstance(
                cvss,
                dict,
            ):
                continue

            result["version"] = (
                cvss.get("version")
                or key
            )

            result["base_score"] = (
                cvss.get("baseScore")
            )

            result["base_severity"] = (
                cvss.get("baseSeverity")
            )

            result["vector"] = (
                cvss.get("vectorString")
            )

            return result

    return result


def extract_cvss(
    containers: Dict[str, Any],
) -> Dict[str, Optional[Any]]:
    cna = containers.get(
        "cna",
        {},
    )

    result = extract_cvss_from_metrics(
        cna.get(
            "metrics",
            [],
        )
    )

    if result["base_score"] is not None:
        return result

    for adp in containers.get(
        "adp",
        [],
    ):
        result = extract_cvss_from_metrics(
            adp.get(
                "metrics",
                [],
            )
        )

        if result["base_score"] is not None:
            return result

    return {
        "version": None,
        "base_score": None,
        "base_severity": None,
        "vector": None,
    }


def extract_affected_products(
    cna: Dict[str, Any],
) -> List[str]:
    products = []

    affected = cna.get(
        "affected",
        [],
    )

    for item in affected:
        vendor = (
            item.get("vendor")
            or ""
        ).strip()

        product = (
            item.get("product")
            or ""
        ).strip()

        if vendor and product:
            value = (
                f"{vendor} - {product}"
            )
        elif product:
            value = product
        elif vendor:
            value = vendor
        else:
            continue

        if value not in products:
            products.append(value)

    return products


def extract_references(
    cna: Dict[str, Any],
    limit: int = 10,
) -> List[str]:
    references = []

    for item in cna.get(
        "references",
        [],
    ):
        url = item.get("url")

        if not url:
            continue

        url = str(url).strip()

        if (
            url
            and url not in references
        ):
            references.append(url)

        if len(references) >= limit:
            break

    return references


def build_cve_section(
    data: Dict[str, Any],
) -> Optional[str]:
    metadata = data.get(
        "cveMetadata",
        {},
    )

    cve_id = metadata.get(
        "cveId"
    )

    state = metadata.get(
        "state"
    )

    if not cve_id:
        return None

    if state != "PUBLISHED":
        return None

    containers = data.get(
        "containers",
        {},
    )

    cna = containers.get(
        "cna",
        {},
    )

    title = (
        cna.get("title")
        or cve_id
    )

    description = (
        first_english_description(
            cna.get(
                "descriptions",
                [],
            )
        )
    )

    cwe_ids = extract_cwe_ids(
        cna
    )

    cvss = extract_cvss(
    containers
)

    products = (
        extract_affected_products(
            cna
        )
    )

    references = (
        extract_references(
            cna
        )
    )

    date_published = (
        metadata.get(
            "datePublished"
        )
        or ""
    )

    date_updated = (
        metadata.get(
            "dateUpdated"
        )
        or ""
    )

    assigner = (
        metadata.get(
            "assignerShortName"
        )
        or ""
    )

    lines = [
        f"## {cve_id} - {title}",
        "",
        f"**CVE ID:** {cve_id}",
        f"**State:** {state}",
    ]

    if assigner:
        lines.append(
            f"**Assigner:** {assigner}"
        )

    if date_published:
        lines.append(
            f"**Published:** {date_published}"
        )

    if date_updated:
        lines.append(
            f"**Updated:** {date_updated}"
        )

    if cwe_ids:
        lines.append(
            "**CWE:** "
            + ", ".join(cwe_ids)
        )

    if cvss["version"]:
        lines.append(
            "**CVSS Version:** "
            + str(
                cvss["version"]
            )
        )

    if cvss["base_score"] is not None:
        lines.append(
            "**CVSS Base Score:** "
            + str(
                cvss["base_score"]
            )
        )

    if cvss["base_severity"]:
        lines.append(
            "**CVSS Severity:** "
            + str(
                cvss["base_severity"]
            )
        )

    if cvss["vector"]:
        lines.append(
            "**CVSS Vector:** "
            + str(
                cvss["vector"]
            )
        )

    lines.append("")

    if description:
        lines.extend(
            [
                "### Description",
                description,
                "",
            ]
        )

    if products:
        lines.append(
            "### Affected Products"
        )

        for product in products:
            lines.append(
                f"- {product}"
            )

        lines.append("")

    if references:
        lines.append(
            "### References"
        )

        for reference in references:
            lines.append(
                f"- {reference}"
            )

        lines.append("")

    return "\n".join(
        lines
    ).strip()


def main() -> None:
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    files = sorted(
        SOURCE_DIR.glob(
            "CVE-*.json"
        )
    )

    sections = []

    for path in files:
        try:
            data = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )
        except Exception:
            print(
                f"Skipping invalid CVE file: {path.name}"
            )
            continue

        section = build_cve_section(
            data
        )

        if section:
            sections.append(section)

    header = "\n".join(
        [
            "# Selected CVE Knowledge Base",
            "",
            (
                "Source: CVE Program "
                "CVE List V5 JSON records."
            ),
            (
                "This file contains a curated "
                "selection of CVEs relevant to "
                "SOC analysis and RAG."
            ),
            "",
        ]
    )

    output = (
        header
        + "\n\n"
        + "\n\n".join(sections)
        + "\n"
    )

    OUTPUT_FILE.write_text(
        output,
        encoding="utf-8",
    )

    print(
        "CVE knowledge base generated: OK"
    )

    print(
        f"Source directory: {SOURCE_DIR}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print(
        f"CVE files found: {len(files)}"
    )

    print(
        f"CVE records generated: {len(sections)}"
    )

    print(
        f"Size: {OUTPUT_FILE.stat().st_size} bytes"
    )


if __name__ == "__main__":
    main()
