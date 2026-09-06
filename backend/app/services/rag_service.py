import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from qdrant_client import QdrantClient

from app.core.config import settings

from llama_index.core import (
    Document,
    StorageContext,
    VectorStoreIndex,
)
from llama_index.core.node_parser import SentenceSplitter
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.vector_stores.qdrant import QdrantVectorStore


class RAGService:
    """
    Retrieval-Augmented Generation service for the SOC knowledge base.

    Architecture:
        Markdown knowledge base
            -> LlamaIndex Documents
            -> SentenceSplitter chunks
            -> HuggingFace embeddings
            -> Qdrant persistent vector database
            -> semantic retrieval

    Supported knowledge sources:
        - MITRE ATT&CK
        - CWE
        - CVE
        - NIST Cybersecurity Framework 2.0
        - SOC playbooks / internal Markdown documents

    Expensive resources are shared between RAGService instances so the
    embedding model and Qdrant index are not rebuilt for every SOC incident.
    """

    _client: Optional[QdrantClient] = None
    _embed_model: Optional[HuggingFaceEmbedding] = None
    _vector_store: Optional[QdrantVectorStore] = None
    _index: Optional[VectorStoreIndex] = None
    _fingerprint: Optional[str] = None

    def __init__(self) -> None:
        project_root = (
            Path(__file__)
            .resolve()
            .parents[3]
        )

        self.knowledge_base_path = (
            project_root
            / "data"
            / "knowledge_base"
        )

        self.metadata_path = (
            project_root
            / "data"
            / "qdrant_rag_metadata.json"
        )

        self.collection_name = "soc_knowledge"

        self.embedding_model_name = (
            "sentence-transformers/all-MiniLM-L6-v2"
        )

        self.chunk_size = 512
        self.chunk_overlap = 80

        # Increment this whenever indexing logic changes.
        self.index_version = "10"

        self._initialize()

    # =====================================================
    # KNOWLEDGE BASE
    # =====================================================

    def _load_documents(self) -> List[Document]:
        documents = []

        if not self.knowledge_base_path.exists():
            return documents

        for file_path in sorted(
            self.knowledge_base_path.rglob("*.md")
        ):
            try:
                content = file_path.read_text(
                    encoding="utf-8"
                )
            except Exception:
                continue

            if not content.strip():
                continue

            relative_path = file_path.relative_to(
                self.knowledge_base_path
            )

            relative_path_string = (
                relative_path.as_posix()
            )

            # =================================================
            # MITRE ATT&CK
            # =================================================

            if (
                relative_path_string
                == "mitre/mitre_enterprise_attack.md"
            ):
                pattern = re.compile(
                    r"(?m)^## "
                    r"(T\d{4}(?:\.\d{3})?)"
                    r" - "
                    r"(.+?)"
                    r"\n"
                )

                matches = list(
                    pattern.finditer(
                        content
                    )
                )

                for index, match in enumerate(
                    matches
                ):
                    technique_id = (
                        match.group(1)
                        .strip()
                    )

                    technique_name = (
                        match.group(2)
                        .strip()
                    )

                    section_start = (
                        match.start()
                    )

                    if (
                        index + 1
                        < len(matches)
                    ):
                        section_end = (
                            matches[
                                index + 1
                            ].start()
                        )
                    else:
                        section_end = len(
                            content
                        )

                    technique_content = (
                        content[
                            section_start:
                            section_end
                        ].strip()
                    )

                    if not technique_content:
                        continue

                    documents.append(
                        Document(
                            text=technique_content,
                            metadata={
                                "source": str(
                                    relative_path
                                ),
                                "display_source": (
                                    "MITRE ATT&CK "
                                    + technique_id
                                    + " - "
                                    + technique_name
                                ),
                                "file_name": (
                                    file_path.name
                                ),
                                "document_type": (
                                    "mitre_attack"
                                ),
                                "technique_id": (
                                    technique_id
                                ),
                                "technique_name": (
                                    technique_name
                                ),
                            },
                        )
                    )

                continue

            # =================================================
            # CWE - COMMON WEAKNESS ENUMERATION
            # =================================================

            if (
                relative_path_string
                == "cwe/cwe_weaknesses.md"
            ):
                pattern = re.compile(
                    r"(?m)^## CWE-"
                    r"(\d+)"
                    r" - "
                    r"(.+?)"
                    r"\n"
                )

                matches = list(
                    pattern.finditer(
                        content
                    )
                )

                for index, match in enumerate(
                    matches
                ):
                    cwe_number = (
                        match.group(1)
                        .strip()
                    )

                    cwe_id = (
                        "CWE-"
                        + cwe_number
                    )

                    cwe_name = (
                        match.group(2)
                        .strip()
                    )

                    section_start = (
                        match.start()
                    )

                    if (
                        index + 1
                        < len(matches)
                    ):
                        section_end = (
                            matches[
                                index + 1
                            ].start()
                        )
                    else:
                        section_end = len(
                            content
                        )

                    cwe_content = (
                        content[
                            section_start:
                            section_end
                        ].strip()
                    )

                    if not cwe_content:
                        continue

                    abstraction_match = re.search(
                        r"\*\*Abstraction:\*\*\s*(.+)",
                        cwe_content,
                    )

                    status_match = re.search(
                        r"\*\*Status:\*\*\s*(.+)",
                        cwe_content,
                    )

                    likelihood_match = re.search(
                        r"\*\*Likelihood of Exploit:\*\*"
                        r"\s*(.+)",
                        cwe_content,
                    )

                    abstraction = (
                        abstraction_match.group(1).strip()
                        if abstraction_match
                        else ""
                    )

                    status = (
                        status_match.group(1).strip()
                        if status_match
                        else ""
                    )

                    likelihood = (
                        likelihood_match.group(1).strip()
                        if likelihood_match
                        else ""
                    )

                    documents.append(
                        Document(
                            text=cwe_content,
                            metadata={
                                "source": str(
                                    relative_path
                                ),
                                "display_source": (
                                    cwe_id
                                    + " - "
                                    + cwe_name
                                ),
                                "file_name": (
                                    file_path.name
                                ),
                                "document_type": (
                                    "cwe"
                                ),
                                "cwe_id": (
                                    cwe_id
                                ),
                                "cwe_name": (
                                    cwe_name
                                ),
                                "cwe_abstraction": (
                                    abstraction
                                ),
                                "cwe_status": (
                                    status
                                ),
                                "cwe_likelihood": (
                                    likelihood
                                ),
                            },
                        )
                    )

                continue

            # =================================================
            # CVE - COMMON VULNERABILITIES AND EXPOSURES
            # =================================================

            if (
                relative_path_string
                == "cve/cve_selected.md"
            ):
                pattern = re.compile(
                    r"(?m)^## "
                    r"(CVE-\d{4}-\d+)"
                    r" - "
                    r"(.+?)"
                    r"\n"
                )

                matches = list(
                    pattern.finditer(
                        content
                    )
                )

                for index, match in enumerate(
                    matches
                ):
                    cve_id = (
                        match.group(1)
                        .strip()
                    )

                    cve_title = (
                        match.group(2)
                        .strip()
                    )

                    section_start = (
                        match.start()
                    )

                    if (
                        index + 1
                        < len(matches)
                    ):
                        section_end = (
                            matches[
                                index + 1
                            ].start()
                        )
                    else:
                        section_end = len(
                            content
                        )

                    cve_content = (
                        content[
                            section_start:
                            section_end
                        ].strip()
                    )

                    if not cve_content:
                        continue

                    cwe_match = re.search(
                        r"\*\*CWE:\*\*\s*(.+)",
                        cve_content,
                    )

                    cvss_score_match = re.search(
                        r"\*\*CVSS Base Score:\*\*"
                        r"\s*(.+)",
                        cve_content,
                    )

                    cvss_severity_match = re.search(
                        r"\*\*CVSS Severity:\*\*"
                        r"\s*(.+)",
                        cve_content,
                    )

                    published_match = re.search(
                        r"\*\*Published:\*\*"
                        r"\s*(.+)",
                        cve_content,
                    )

                    cwe_ids = (
                        cwe_match.group(1).strip()
                        if cwe_match
                        else ""
                    )

                    cvss_score = (
                        cvss_score_match.group(1).strip()
                        if cvss_score_match
                        else ""
                    )

                    cvss_severity = (
                        cvss_severity_match.group(1).strip()
                        if cvss_severity_match
                        else ""
                    )

                    published = (
                        published_match.group(1).strip()
                        if published_match
                        else ""
                    )

                    documents.append(
                        Document(
                            text=cve_content,
                            metadata={
                                "source": str(
                                    relative_path
                                ),
                                "display_source": (
                                    cve_id
                                    + " - "
                                    + cve_title
                                ),
                                "file_name": (
                                    file_path.name
                                ),
                                "document_type": (
                                    "cve"
                                ),
                                "cve_id": (
                                    cve_id
                                ),
                                "cve_title": (
                                    cve_title
                                ),
                                "cwe_ids": (
                                    cwe_ids
                                ),
                                "cvss_score": (
                                    cvss_score
                                ),
                                "cvss_severity": (
                                    cvss_severity
                                ),
                                "published": (
                                    published
                                ),
                            },
                        )
                    )

                continue

                        # =================================================
            # WAZUH DOCUMENTATION
            #
            # One LlamaIndex Document per Wazuh topic.
            # =================================================

            if (
                relative_path_string
                == "wazuh/wazuh_soc_reference.md"
            ):
                pattern = re.compile(
                    r"(?m)^## "
                    r"(WAZUH-[a-z0-9\-]+)"
                    r" - "
                    r"(.+?)"
                    r"\n"
                )

                matches = list(
                    pattern.finditer(
                        content
                    )
                )

                for index, match in enumerate(
                    matches
                ):
                    wazuh_topic_id = (
                        match.group(1)
                        .strip()
                    )

                    wazuh_topic = (
                        match.group(2)
                        .strip()
                    )

                    section_start = (
                        match.start()
                    )

                    if (
                        index + 1
                        < len(matches)
                    ):
                        section_end = (
                            matches[
                                index + 1
                            ].start()
                        )
                    else:
                        section_end = len(
                            content
                        )

                    wazuh_content = (
                        content[
                            section_start:
                            section_end
                        ].strip()
                    )

                    if not wazuh_content:
                        continue

                    source_match = re.search(
                        r"\*\*Official Source:\*\*"
                        r"\s*(.+)",
                        wazuh_content,
                    )

                    official_source = (
                        source_match.group(1).strip()
                        if source_match
                        else ""
                    )

                    documents.append(
                        Document(
                            text=wazuh_content,
                            metadata={
                                "source": str(
                                    relative_path
                                ),
                                "display_source": (
    wazuh_topic
    if wazuh_topic.lower().startswith("wazuh")
    else "Wazuh " + wazuh_topic
),
                                "file_name": (
                                    file_path.name
                                ),
                                "document_type": (
                                    "wazuh_documentation"
                                ),
                                "wazuh_topic_id": (
                                    wazuh_topic_id
                                ),
                                "wazuh_topic": (
                                    wazuh_topic
                                ),
                                "official_source": (
                                    official_source
                                ),
                            },
                        )
                    )

                continue

                        # =================================================
            # SURICATA DOCUMENTATION
            #
            # One LlamaIndex Document per Suricata topic.
            # =================================================

            if (
                relative_path_string
                == "suricata/suricata_soc_reference.md"
            ):
                pattern = re.compile(
                    r"(?m)^## "
                    r"(SURICATA-[a-z0-9\-]+)"
                    r" - "
                    r"(.+?)"
                    r"\n"
                )

                matches = list(
                    pattern.finditer(content)
                )

                for index, match in enumerate(matches):
                    suricata_topic_id = (
                        match.group(1).strip()
                    )

                    suricata_topic = (
                        match.group(2).strip()
                    )

                    section_start = match.start()

                    if index + 1 < len(matches):
                        section_end = matches[
                            index + 1
                        ].start()
                    else:
                        section_end = len(content)

                    suricata_content = content[
                        section_start:section_end
                    ].strip()

                    if not suricata_content:
                        continue

                    source_match = re.search(
                        r"\*\*Official Source:\*\*"
                        r"\s*(.+)",
                        suricata_content,
                    )

                    official_source = (
                        source_match.group(1).strip()
                        if source_match
                        else ""
                    )

                    documents.append(
                        Document(
                            text=suricata_content,
                            metadata={
                                "source": str(
                                    relative_path
                                ),
                                "display_source": (
                                    suricata_topic
                                    if suricata_topic
                                    .lower()
                                    .startswith("suricata")
                                    else (
                                        "Suricata "
                                        + suricata_topic
                                    )
                                ),
                                "file_name": (
                                    file_path.name
                                ),
                                "document_type": (
                                    "suricata_documentation"
                                ),
                                "suricata_topic_id": (
                                    suricata_topic_id
                                ),
                                "suricata_topic": (
                                    suricata_topic
                                ),
                                "official_source": (
                                    official_source
                                ),
                            },
                        )
                    )

                continue

                        # =================================================
            # INTERNAL SOC RUNBOOKS
            #
            # One LlamaIndex Document per generated SOC runbook.
            # =================================================

            if (
                relative_path.parts
                and relative_path.parts[0] == "runbooks"
                and file_path.name.endswith("_runbook.md")
            ):
                runbook_id_match = re.search(
                    r"\*\*Runbook ID:\*\*\s*(.+)",
                    content,
                )

                incident_type_match = re.search(
                    r"\*\*Incident Type:\*\*\s*(.+)",
                    content,
                )

                mitre_match = re.search(
                    r"\*\*MITRE ATT&CK:\*\*\s*(.+)",
                    content,
                )

                runbook_id = (
                    runbook_id_match.group(1).strip()
                    if runbook_id_match
                    else file_path.stem
                )

                incident_type = (
                    incident_type_match.group(1).strip()
                    if incident_type_match
                    else file_path.stem
                )

                mitre_mapping = (
                    mitre_match.group(1).strip()
                    if mitre_match
                    else ""
                )

                documents.append(
                    Document(
                        text=content.strip(),
                        metadata={
                            "source": str(relative_path),
                            "display_source": (
                                "SOC Runbook - "
                                + incident_type
                            ),
                            "file_name": file_path.name,
                            "document_type": "soc_runbook",
                            "runbook_id": runbook_id,
                            "incident_type": incident_type,
                            "mitre_mapping": mitre_mapping,
                            "source_type": "internal",
                        },
                    )
                )

                continue
            # =================================================
            # NIST CYBERSECURITY FRAMEWORK 2.0
            # =================================================

            if (
                relative_path_string
                == "nist/nist_csf_2_0.md"
            ):
                page_pattern = re.compile(
                    r"(?m)^## NIST CSF 2\.0 - Page "
                    r"(\d+)"
                    r"\n"
                )

                page_matches = list(
                    page_pattern.finditer(
                        content
                    )
                )

                function_map = {
                    "GV": "GOVERN",
                    "ID": "IDENTIFY",
                    "PR": "PROTECT",
                    "DE": "DETECT",
                    "RS": "RESPOND",
                    "RC": "RECOVER",
                }

                for (
                    page_index,
                    page_match,
                ) in enumerate(
                    page_matches
                ):
                    page_number = (
                        page_match
                        .group(1)
                        .strip()
                    )

                    page_start = (
                        page_match.start()
                    )

                    if (
                        page_index + 1
                        < len(page_matches)
                    ):
                        page_end = (
                            page_matches[
                                page_index + 1
                            ].start()
                        )
                    else:
                        page_end = len(
                            content
                        )

                    page_content = (
                        content[
                            page_start:
                            page_end
                        ].strip()
                    )

                    if not page_content:
                        continue

                    category_pattern = re.compile(
                        r"(?m)^•\s*"
                        r"(.+?)"
                        r"\s+\("
                        r"((?:GV|ID|PR|DE|RS|RC)"
                        r"\.[A-Z]{2})"
                        r"\):"
                    )

                    category_matches = list(
                        category_pattern.finditer(
                            page_content
                        )
                    )

                    if category_matches:
                        for (
                            category_index,
                            category_match,
                        ) in enumerate(
                            category_matches
                        ):
                            category_name = (
                                category_match
                                .group(1)
                                .strip()
                            )

                            category_id = (
                                category_match
                                .group(2)
                                .strip()
                            )

                            category_start = (
                                category_match.start()
                            )

                            if (
                                category_index + 1
                                < len(
                                    category_matches
                                )
                            ):
                                category_end = (
                                    category_matches[
                                        category_index + 1
                                    ].start()
                                )
                            else:
                                category_end = len(
                                    page_content
                                )

                            category_content = (
                                page_content[
                                    category_start:
                                    category_end
                                ].strip()
                            )

                            if not category_content:
                                continue

                            function_prefix = (
                                category_id
                                .split(".")[0]
                            )

                            nist_function = (
                                function_map.get(
                                    function_prefix,
                                    "",
                                )
                            )

                            subcategory_ids = sorted(
                                set(
                                    re.findall(
                                        (
                                            r"\b"
                                            + re.escape(
                                                category_id
                                            )
                                            + r"-\d{2}"
                                            + r"\b"
                                        ),
                                        category_content,
                                    )
                                )
                            )

                            all_identifiers = [
                                category_id
                            ]

                            all_identifiers.extend(
                                subcategory_ids
                            )

                            documents.append(
                                Document(
                                    text=(
                                        category_content
                                    ),
                                    metadata={
                                        "source": str(
                                            relative_path
                                        ),
                                        "display_source": (
                                            "NIST CSF 2.0 "
                                            + category_id
                                            + " - "
                                            + category_name
                                        ),
                                        "file_name": (
                                            file_path.name
                                        ),
                                        "document_type": (
                                            "nist_csf"
                                        ),
                                        "nist_publication": (
                                            "NIST CSWP 29"
                                        ),
                                        "nist_page": (
                                            page_number
                                        ),
                                        "nist_function": (
                                            nist_function
                                        ),
                                        "nist_category_id": (
                                            category_id
                                        ),
                                        "nist_category_name": (
                                            category_name
                                        ),
                                        "csf_identifiers": (
                                            ", ".join(
                                                all_identifiers
                                            )
                                        ),
                                    },
                                )
                            )

                        continue

                    functions_match = re.search(
                        r"\*\*Detected CSF Functions:\*\*"
                        r"\s*(.+)",
                        page_content,
                    )

                    nist_functions = ""

                    if functions_match:
                        nist_functions = (
                            functions_match
                            .group(1)
                            .strip()
                        )

                    identifiers_match = re.search(
                        r"\*\*Detected CSF Identifiers:\*\*"
                        r"\s*(.+)",
                        page_content,
                    )

                    csf_identifiers = ""

                    if identifiers_match:
                        csf_identifiers = (
                            identifiers_match
                            .group(1)
                            .strip()
                        )

                    documents.append(
                        Document(
                            text=page_content,
                            metadata={
                                "source": str(
                                    relative_path
                                ),
                                "display_source": (
                                    "NIST CSF 2.0 - Page "
                                    + page_number
                                ),
                                "file_name": (
                                    file_path.name
                                ),
                                "document_type": (
                                    "nist_csf"
                                ),
                                "nist_publication": (
                                    "NIST CSWP 29"
                                ),
                                "nist_page": (
                                    page_number
                                ),
                                "nist_function": (
                                    nist_functions
                                ),
                                "nist_category_id": "",
                                "nist_category_name": "",
                                "csf_identifiers": (
                                    csf_identifiers
                                ),
                            },
                        )
                    )

                continue

            # =================================================
            # STANDARD SOC KNOWLEDGE DOCUMENT
            # =================================================

            documents.append(
                Document(
                    text=content,
                    metadata={
                        "source": str(
                            relative_path
                        ),
                        "display_source": str(
                            relative_path
                        ),
                        "file_name": (
                            file_path.name
                        ),
                        "document_type": (
                            "soc_knowledge"
                        ),
                    },
                )
            )

        return documents

    # =====================================================
    # KNOWLEDGE BASE FINGERPRINT
    # =====================================================

    def _calculate_fingerprint(self) -> str:
        hasher = hashlib.sha256()

        hasher.update(
            self.index_version.encode(
                "utf-8"
            )
        )

        hasher.update(
            self.embedding_model_name.encode(
                "utf-8"
            )
        )

        hasher.update(
            str(
                self.chunk_size
            ).encode(
                "utf-8"
            )
        )

        hasher.update(
            str(
                self.chunk_overlap
            ).encode(
                "utf-8"
            )
        )

        if not self.knowledge_base_path.exists():
            return hasher.hexdigest()

        files = sorted(
            self.knowledge_base_path.rglob(
                "*.md"
            )
        )

        for file_path in files:
            try:
                relative_path = (
                    file_path.relative_to(
                        self.knowledge_base_path
                    )
                )

                content = (
                    file_path.read_bytes()
                )

                hasher.update(
                    str(
                        relative_path
                    ).encode(
                        "utf-8"
                    )
                )

                hasher.update(
                    content
                )

            except Exception:
                continue

        return hasher.hexdigest()

    def _load_saved_fingerprint(
        self,
    ) -> Optional[str]:

        if not self.metadata_path.exists():
            return None

        try:
            data = json.loads(
                self.metadata_path.read_text(
                    encoding="utf-8"
                )
            )

            return data.get(
                "knowledge_base_fingerprint"
            )

        except Exception:
            return None

    def _save_fingerprint(
        self,
        fingerprint: str,
    ) -> None:

        data = {
            "index_version": (
                self.index_version
            ),
            "collection_name": (
                self.collection_name
            ),
            "embedding_model": (
                self.embedding_model_name
            ),
            "chunk_size": (
                self.chunk_size
            ),
            "chunk_overlap": (
                self.chunk_overlap
            ),
            "knowledge_base_fingerprint": (
                fingerprint
            ),
        }

        self.metadata_path.write_text(
            json.dumps(
                data,
                indent=2,
            ),
            encoding="utf-8",
        )

    # =====================================================
    # QDRANT
    # =====================================================

    def _collection_exists(
        self,
        client: QdrantClient,
    ) -> bool:

        try:
            collections = (
                client
                .get_collections()
                .collections
            )

            return any(
                collection.name
                == self.collection_name
                for collection in collections
            )

        except Exception:
            return False

    def _collection_has_points(
        self,
        client: QdrantClient,
    ) -> bool:

        if not self._collection_exists(
            client
        ):
            return False

        try:
            collection_info = (
                client.get_collection(
                    self.collection_name
                )
            )

            return bool(
                collection_info.points_count
            )

        except Exception:
            return False

    # =====================================================
    # INITIALIZATION
    # =====================================================

    def _initialize(self) -> None:
        current_fingerprint = (
            self._calculate_fingerprint()
        )

        if (
            RAGService._client is not None
            and RAGService._index is not None
            and RAGService._fingerprint
            == current_fingerprint
        ):
            return

        saved_fingerprint = (
            self._load_saved_fingerprint()
        )

        knowledge_changed = (
            saved_fingerprint
            != current_fingerprint
        )

        client = QdrantClient(
            url=settings.QDRANT_URL
        )

        if knowledge_changed:
            RAGService._client = None
            RAGService._vector_store = None
            RAGService._index = None
            RAGService._fingerprint = None

            if self._collection_exists(
                client
            ):
                client.delete_collection(
                    collection_name=(
                        self.collection_name
                    )
                )

        if RAGService._embed_model is None:
            RAGService._embed_model = (
                HuggingFaceEmbedding(
                    model_name=(
                        self.embedding_model_name
                    ),
                    normalize=True,
                )
            )

        vector_store = QdrantVectorStore(
            collection_name=(
                self.collection_name
            ),
            client=client,
        )

        if (
            not knowledge_changed
            and self._collection_has_points(
                client
            )
        ):
            index = (
                VectorStoreIndex
                .from_vector_store(
                    vector_store=(
                        vector_store
                    ),
                    embed_model=(
                        RAGService
                        ._embed_model
                    ),
                )
            )

        else:
            documents = (
                self._load_documents()
            )

            if not documents:
                RAGService._client = client
                RAGService._vector_store = vector_store
                RAGService._index = None
                RAGService._fingerprint = (
                    current_fingerprint
                )
                return

            splitter = SentenceSplitter(
                chunk_size=(
                    self.chunk_size
                ),
                chunk_overlap=(
                    self.chunk_overlap
                ),
                include_metadata=True,
            )

            storage_context = (
                StorageContext
                .from_defaults(
                    vector_store=(
                        vector_store
                    )
                )
            )

            index = (
                VectorStoreIndex
                .from_documents(
                    documents=documents,
                    storage_context=(
                        storage_context
                    ),
                    transformations=[
                        splitter
                    ],
                    embed_model=(
                        RAGService
                        ._embed_model
                    ),
                    show_progress=False,
                )
            )

            self._save_fingerprint(
                current_fingerprint
            )

        RAGService._client = client
        RAGService._vector_store = vector_store
        RAGService._index = index
        RAGService._fingerprint = (
            current_fingerprint
        )

    # =====================================================
    # SEMANTIC SEARCH
    # =====================================================

    def search(
        self,
        query: str,
        limit: int = 3,
        min_score: float = 0.20,
        relative_threshold: float = 0.60,
    ) -> List[Dict]:

        if not query:
            return []

        if RAGService._index is None:
            return []

        candidate_limit = max(
            limit * 5,
            20,
        )

        retriever = (
            RAGService
            ._index
            .as_retriever(
                similarity_top_k=(
                    candidate_limit
                ),
            )
        )

        try:
            nodes = (
                retriever.retrieve(
                    query
                )
            )

        except Exception as exc:
            print(
                "RAG retrieval failed: "
                + str(exc)
            )
            return []

        if not nodes:
            return []

        scored_documents = []

        query_upper = (
            query.upper()
        )

        requested_cve_ids = set(
            re.findall(
                r"\bCVE-\d{4}-\d+\b",
                query_upper,
            )
        )

        requested_cwe_ids = set(
            re.findall(
                r"\bCWE-\d+\b",
                query_upper,
            )
        )

        requested_mitre_ids = set(
            re.findall(
                r"\bT\d{4}(?:\.\d{3})?\b",
                query_upper,
            )
        )

        for node_with_score in nodes:
            score = (
                node_with_score.score
            )

            if score is None:
                continue

            score = float(
                score
            )

            if score < min_score:
                continue

            node = (
                node_with_score.node
            )

            metadata = (
                node.metadata
                if isinstance(
                    node.metadata,
                    dict,
                )
                else {}
            )

            ranking_score = score

            cve_id = str(
                metadata.get(
                    "cve_id",
                    ""
                )
            ).upper()

            cwe_id = str(
                metadata.get(
                    "cwe_id",
                    ""
                )
            ).upper()

            technique_id = str(
                metadata.get(
                    "technique_id",
                    ""
                )
            ).upper()

            if (
                cve_id
                and cve_id
                in requested_cve_ids
            ):
                ranking_score += 1.0

            if (
                cwe_id
                and cwe_id
                in requested_cwe_ids
            ):
                ranking_score += 1.0

            if (
                technique_id
                and technique_id
                in requested_mitre_ids
            ):
                ranking_score += 1.0

            scored_documents.append(
                {
                    "source": (
                        metadata.get(
                            "display_source"
                        )
                        or metadata.get(
                            "source"
                        )
                        or metadata.get(
                            "file_name"
                        )
                        or "unknown"
                    ),
                    "content": (
                        node.get_content()
                    ),
                    "score": score,
                    "_ranking_score": (
                        ranking_score
                    ),
                    "metadata": metadata,
                }
            )

        if not scored_documents:
            return []

        scored_documents.sort(
            key=lambda item: item[
                "_ranking_score"
            ],
            reverse=True,
        )

        deduplicated_documents = []
        seen_documents = set()

        for document in scored_documents:
            metadata = document[
                "metadata"
            ]

            document_type = str(
                metadata.get(
                    "document_type",
                    ""
                )
            )

            if document_type == "cve":
                unique_key = (
                    "cve",
                    metadata.get(
                        "cve_id"
                    ),
                )

            elif document_type == "cwe":
                unique_key = (
                    "cwe",
                    metadata.get(
                        "cwe_id"
                    ),
                )

            elif (
                document_type
                == "mitre_attack"
            ):
                unique_key = (
                    "mitre_attack",
                    metadata.get(
                        "technique_id"
                    ),
                )

            elif (
                document_type
                == "nist_csf"
            ):
                unique_key = (
                    "nist_csf",
                    metadata.get(
                        "nist_category_id"
                    )
                    or metadata.get(
                        "nist_page"
                    ),
                )

            else:
                unique_key = (
                    document_type,
                    document.get(
                        "source"
                    ),
                )

            if unique_key in seen_documents:
                continue

            seen_documents.add(
                unique_key
            )

            deduplicated_documents.append(
                document
            )

        if not deduplicated_documents:
            return []

        best_semantic_score = max(
            document["score"]
            for document
            in deduplicated_documents
        )

        minimum_relative_score = (
            best_semantic_score
            * relative_threshold
        )

        relevant_documents = []

        for document in deduplicated_documents:
            metadata = document[
                "metadata"
            ]

            exact_identifier_match = (
                str(
                    metadata.get(
                        "cve_id",
                        ""
                    )
                ).upper()
                in requested_cve_ids
                or
                str(
                    metadata.get(
                        "cwe_id",
                        ""
                    )
                ).upper()
                in requested_cwe_ids
                or
                str(
                    metadata.get(
                        "technique_id",
                        ""
                    )
                ).upper()
                in requested_mitre_ids
            )

            if (
                document["score"]
                >= minimum_relative_score
                or exact_identifier_match
            ):
                document.pop(
                    "_ranking_score",
                    None,
                )

                relevant_documents.append(
                    document
                )

        return relevant_documents[
            :limit
        ]