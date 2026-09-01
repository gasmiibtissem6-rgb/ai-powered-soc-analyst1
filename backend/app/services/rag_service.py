import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Dict, List, Optional

from qdrant_client import QdrantClient

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

        self.qdrant_path = (
            project_root
            / "data"
            / "qdrant_storage"
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

        # Increment this value whenever indexing logic changes.
        # This automatically invalidates the previous Qdrant index.
        self.index_version = "4"

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
            #
            # One LlamaIndex Document per ATT&CK technique.
            #
            # Examples:
            #   T1110 - Brute Force
            #   T1053.005 - Scheduled Task/Job
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
                            text=(
                                technique_content
                            ),
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
            # NIST CYBERSECURITY FRAMEWORK 2.0
            #
            # Core pages:
            #   One LlamaIndex Document per CSF category.
            #
            # Examples:
            #   DE.CM - Continuous Monitoring
            #   RS.MA - Incident Management
            #   RC.RP - Incident Recovery Plan Execution
            #
            # General pages:
            #   One LlamaIndex Document per PDF page.
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

                    # =========================================
                    # Find NIST CSF category blocks
                    #
                    # Examples:
                    #
                    # • Continuous Monitoring (DE.CM):
                    # • Incident Management (RS.MA):
                    # • Incident Recovery Plan Execution
                    #   (RC.RP):
                    # =========================================

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

                    # =========================================
                    # NIST CORE CATEGORY DOCUMENTS
                    # =========================================

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

                            # Find all subcategory identifiers
                            # belonging to this category.
                            #
                            # Example for RS.MA:
                            # RS.MA-01
                            # RS.MA-02
                            # RS.MA-03
                            # ...

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

                    # =========================================
                    # GENERAL NIST PAGE
                    #
                    # Pages that do not contain CSF Core
                    # category blocks remain searchable.
                    #
                    # Examples:
                    #   - Abstract
                    #   - Overview
                    #   - Profiles
                    #   - Tiers
                    #   - Glossary
                    # =========================================

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
                            text=(
                                page_content
                            ),
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
                                "nist_category_id": (
                                    ""
                                ),
                                "nist_category_name": (
                                    ""
                                ),
                                "csf_identifiers": (
                                    csf_identifiers
                                ),
                            },
                        )
                    )

                continue

            # =================================================
            # STANDARD SOC KNOWLEDGE DOCUMENT
            #
            # Examples:
            #   brute_force_playbook.md
            #   phishing_playbook.md
            #   malware_playbook.md
            #   future runbooks/internal documents
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

        # Include indexing configuration so that changes to
        # indexing logic automatically invalidate Qdrant.
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

        # Reuse resources already loaded in this process.
        if (
            RAGService._client is not None
            and RAGService._index is not None
            and RAGService._fingerprint
            == current_fingerprint
        ):
            return

        self.qdrant_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        saved_fingerprint = (
            self._load_saved_fingerprint()
        )

        knowledge_changed = (
            saved_fingerprint
            != current_fingerprint
        )

        # Rebuild persistent Qdrant when:
        #   - knowledge base changes
        #   - indexing version changes
        #   - embedding configuration changes
        #   - chunk configuration changes
        if knowledge_changed:
            RAGService._client = None
            RAGService._vector_store = None
            RAGService._index = None
            RAGService._fingerprint = None

            if self.qdrant_path.exists():
                shutil.rmtree(
                    self.qdrant_path
                )

        # Load embedding model once per Python process.
        if RAGService._embed_model is None:
            RAGService._embed_model = (
                HuggingFaceEmbedding(
                    model_name=(
                        self.embedding_model_name
                    ),
                    normalize=True,
                )
            )

        client = QdrantClient(
            path=str(
                self.qdrant_path
            )
        )

        vector_store = QdrantVectorStore(
            collection_name=(
                self.collection_name
            ),
            client=client,
        )

        # =================================================
        # LOAD EXISTING QDRANT INDEX
        # =================================================

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

        # =================================================
        # BUILD NEW QDRANT INDEX
        # =================================================

        else:
            documents = (
                self._load_documents()
            )

            if not documents:
                RAGService._client = (
                    client
                )

                RAGService._vector_store = (
                    vector_store
                )

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

        RAGService._client = (
            client
        )

        RAGService._vector_store = (
            vector_store
        )

        RAGService._index = (
            index
        )

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

        retriever = (
            RAGService
            ._index
            .as_retriever(
                similarity_top_k=(
                    limit
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
                    "score": (
                        score
                    ),
                    "metadata": (
                        metadata
                    ),
                }
            )

        if not scored_documents:
            return []

        scored_documents.sort(
            key=lambda item: item[
                "score"
            ],
            reverse=True,
        )

        best_score = (
            scored_documents[0][
                "score"
            ]
        )

        minimum_relative_score = (
            best_score
            * relative_threshold
        )

        relevant_documents = [
            document
            for document
            in scored_documents
            if (
                document["score"]
                >= minimum_relative_score
            )
        ]

        return relevant_documents[
            :limit
        ]