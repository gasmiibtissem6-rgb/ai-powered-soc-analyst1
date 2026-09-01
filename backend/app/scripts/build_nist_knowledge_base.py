import re
from pathlib import Path
from typing import List

from pypdf import PdfReader


BACKEND_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

PROJECT_ROOT = (
    BACKEND_ROOT.parent
)

NIST_SOURCE = (
    BACKEND_ROOT
    / "data"
    / "nist"
    / "NIST.CSWP.29.pdf"
)

OUTPUT_DIRECTORY = (
    PROJECT_ROOT
    / "data"
    / "knowledge_base"
    / "nist"
)

OUTPUT_FILE = (
    OUTPUT_DIRECTORY
    / "nist_csf_2_0.md"
)


NIST_FUNCTIONS = [
    "GOVERN",
    "IDENTIFY",
    "PROTECT",
    "DETECT",
    "RESPOND",
    "RECOVER",
]


def clean_text(
    text: str,
) -> str:
    """
    Clean text extracted from the official NIST CSF 2.0 PDF
    while preserving the original wording.
    """

    text = (
        text
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )

    # Remove repeated document header.
    text = re.sub(
        r"NIST CSWP 29\s+"
        r"The NIST Cybersecurity Framework "
        r"\(CSF\) 2\.0",
        "",
        text,
        flags=re.IGNORECASE,
    )

    # Remove repeated publication date.
    text = re.sub(
        r"February 26,\s*2024",
        "",
        text,
        flags=re.IGNORECASE,
    )

    # Normalize spaces.
    text = re.sub(
        r"[ \t]+",
        " ",
        text,
    )

    # Normalize excessive blank lines.
    text = re.sub(
        r"\n{3,}",
        "\n\n",
        text,
    )

    return text.strip()


def detect_functions(
    text: str,
) -> List[str]:
    detected = []

    upper_text = text.upper()

    for function_name in NIST_FUNCTIONS:
        if function_name in upper_text:
            detected.append(
                function_name
            )

    return detected


def detect_csf_codes(
    text: str,
) -> List[str]:
    """
    Detect NIST CSF identifiers such as:
        GV.OC-01
        ID.AM-01
        PR.AA-01
        DE.CM-01
        RS.MA-01
        RC.RP-01
    """

    matches = re.findall(
        r"\b(?:GV|ID|PR|DE|RS|RC)"
        r"\.[A-Z]{2}"
        r"(?:-\d{2})?\b",
        text,
    )

    return sorted(
        set(matches)
    )


def build_knowledge_base() -> None:
    if not NIST_SOURCE.exists():
        raise FileNotFoundError(
            "NIST CSF 2.0 PDF not found: "
            + str(NIST_SOURCE)
        )

    reader = PdfReader(
        str(NIST_SOURCE)
    )

    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    lines = [
        "# NIST Cybersecurity Framework (CSF) 2.0",
        "",
        "**Publication:** NIST CSWP 29",
        "",
        "**Publication date:** February 26, 2024",
        "",
        (
            "**Source:** Official National Institute "
            "of Standards and Technology publication"
        ),
        "",
        (
            "**DOI:** "
            "https://doi.org/10.6028/NIST.CSWP.29"
        ),
        "",
        (
            "This knowledge-base document was generated "
            "from the official local NIST CSF 2.0 PDF."
        ),
        "",
        (
            "The extracted wording is preserved for "
            "retrieval by the SOC RAG pipeline."
        ),
        "",
        "---",
        "",
    ]

    extracted_pages = 0

    for page_number, page in enumerate(
        reader.pages,
        start=1,
    ):
        raw_text = (
            page.extract_text()
            or ""
        )

        text = clean_text(
            raw_text
        )

        if not text:
            continue

        functions = detect_functions(
            text
        )

        csf_codes = detect_csf_codes(
            text
        )

        lines.extend(
            [
                (
                    "## NIST CSF 2.0 - Page "
                    + str(page_number)
                ),
                "",
                (
                    "**PDF Page:** "
                    + str(page_number)
                ),
                "",
            ]
        )

        if functions:
            lines.extend(
                [
                    (
                        "**Detected CSF Functions:** "
                        + ", ".join(functions)
                    ),
                    "",
                ]
            )

        if csf_codes:
            lines.extend(
                [
                    (
                        "**Detected CSF Identifiers:** "
                        + ", ".join(csf_codes)
                    ),
                    "",
                ]
            )

        lines.extend(
            [
                "### Content",
                "",
                text,
                "",
                "---",
                "",
            ]
        )

        extracted_pages += 1

    OUTPUT_FILE.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print(
        "NIST knowledge base generated: OK"
    )

    print(
        "Source:",
        NIST_SOURCE,
    )

    print(
        "Output:",
        OUTPUT_FILE,
    )

    print(
        "PDF pages:",
        len(reader.pages),
    )

    print(
        "Extracted pages:",
        extracted_pages,
    )

    print(
        "Size:",
        OUTPUT_FILE.stat().st_size,
        "bytes",
    )


if __name__ == "__main__":
    build_knowledge_base()
