from types import SimpleNamespace

import pytest

from app.services.rag_service import RAGService


@pytest.fixture
def rag_service(monkeypatch):
    monkeypatch.setattr(
        RAGService,
        "_initialize",
        lambda self: None,
    )

    service = RAGService()

    RAGService._index = None

    yield service

    RAGService._index = None
    RAGService._client = None
    RAGService._vector_store = None
    RAGService._fingerprint = None


def make_node(
    content,
    score,
    metadata,
):
    node = SimpleNamespace(
        metadata=metadata,
        get_content=lambda: content,
    )

    return SimpleNamespace(
        node=node,
        score=score,
    )


def set_retrieval_results(
    monkeypatch,
    results,
):
    retriever = SimpleNamespace(
        retrieve=lambda query: results,
    )

    index = SimpleNamespace(
        as_retriever=lambda **kwargs: retriever,
    )

    monkeypatch.setattr(
        RAGService,
        "_index",
        index,
    )


def test_search_returns_empty_for_empty_query(
    rag_service,
):
    assert rag_service.search("") == []


def test_search_returns_empty_without_index(
    rag_service,
):
    RAGService._index = None

    assert (
        rag_service.search(
            "MITRE T1110"
        )
        == []
    )


def test_search_filters_low_scores(
    rag_service,
    monkeypatch,
):
    set_retrieval_results(
        monkeypatch,
        [
            make_node(
                "Low relevance",
                0.10,
                {
                    "document_type": "soc_knowledge",
                    "display_source": "Low Source",
                },
            )
        ],
    )

    assert (
        rag_service.search(
            "incident response"
        )
        == []
    )


def test_search_prefers_exact_mitre_identifier(
    rag_service,
    monkeypatch,
):
    set_retrieval_results(
        monkeypatch,
        [
            make_node(
                "Other technique",
                0.80,
                {
                    "document_type": "mitre_attack",
                    "display_source": (
                        "MITRE ATT&CK T1041"
                    ),
                    "technique_id": "T1041",
                },
            ),
            make_node(
                "Brute Force",
                0.60,
                {
                    "document_type": "mitre_attack",
                    "display_source": (
                        "MITRE ATT&CK T1110"
                    ),
                    "technique_id": "T1110",
                },
            ),
        ],
    )

    results = rag_service.search(
        "MITRE ATT&CK T1110 brute force",
        limit=2,
    )

    assert len(results) == 2
    assert (
        results[0]["metadata"]["technique_id"]
        == "T1110"
    )


def test_search_prefers_exact_cve_identifier(
    rag_service,
    monkeypatch,
):
    set_retrieval_results(
        monkeypatch,
        [
            make_node(
                "Another vulnerability",
                0.85,
                {
                    "document_type": "cve",
                    "display_source": "CVE-2024-0001",
                    "cve_id": "CVE-2024-0001",
                },
            ),
            make_node(
                "Requested vulnerability",
                0.55,
                {
                    "document_type": "cve",
                    "display_source": "CVE-2023-34362",
                    "cve_id": "CVE-2023-34362",
                },
            ),
        ],
    )

    results = rag_service.search(
        "Analyze CVE-2023-34362",
        limit=2,
    )

    assert (
        results[0]["metadata"]["cve_id"]
        == "CVE-2023-34362"
    )


def test_search_prefers_exact_cwe_identifier(
    rag_service,
    monkeypatch,
):
    set_retrieval_results(
        monkeypatch,
        [
            make_node(
                "Other weakness",
                0.80,
                {
                    "document_type": "cwe",
                    "display_source": "CWE-79",
                    "cwe_id": "CWE-79",
                },
            ),
            make_node(
                "SQL Injection",
                0.60,
                {
                    "document_type": "cwe",
                    "display_source": "CWE-89",
                    "cwe_id": "CWE-89",
                },
            ),
        ],
    )

    results = rag_service.search(
        "Explain CWE-89",
        limit=2,
    )

    assert (
        results[0]["metadata"]["cwe_id"]
        == "CWE-89"
    )


def test_search_deduplicates_same_document(
    rag_service,
    monkeypatch,
):
    set_retrieval_results(
        monkeypatch,
        [
            make_node(
                "First chunk",
                0.90,
                {
                    "document_type": "mitre_attack",
                    "display_source": (
                        "MITRE ATT&CK T1110"
                    ),
                    "technique_id": "T1110",
                },
            ),
            make_node(
                "Second chunk",
                0.85,
                {
                    "document_type": "mitre_attack",
                    "display_source": (
                        "MITRE ATT&CK T1110"
                    ),
                    "technique_id": "T1110",
                },
            ),
        ],
    )

    results = rag_service.search(
        "brute force",
        limit=3,
    )

    assert len(results) == 1
    assert (
        results[0]["metadata"]["technique_id"]
        == "T1110"
    )


def test_search_applies_relative_threshold(
    rag_service,
    monkeypatch,
):
    set_retrieval_results(
        monkeypatch,
        [
            make_node(
                "Highly relevant",
                0.90,
                {
                    "document_type": "soc_knowledge",
                    "display_source": "Primary Source",
                },
            ),
            make_node(
                "Weakly relevant",
                0.40,
                {
                    "document_type": "soc_knowledge",
                    "display_source": "Secondary Source",
                },
            ),
        ],
    )

    results = rag_service.search(
        "SOC incident",
        limit=3,
    )

    assert len(results) == 1
    assert (
        results[0]["source"]
        == "Primary Source"
    )


def test_search_handles_retrieval_failure(
    rag_service,
    monkeypatch,
):
    def fail_retrieve(query):
        raise RuntimeError(
            "Qdrant unavailable"
        )

    retriever = SimpleNamespace(
        retrieve=fail_retrieve,
    )

    index = SimpleNamespace(
        as_retriever=lambda **kwargs: retriever,
    )

    monkeypatch.setattr(
        RAGService,
        "_index",
        index,
    )

    assert (
        rag_service.search(
            "incident response"
        )
        == []
    )