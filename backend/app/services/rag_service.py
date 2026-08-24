from pathlib import Path
from typing import List


class RAGService:

    def __init__(self):

        self.knowledge_base_path = (
            Path(__file__)
            .resolve()
            .parents[3]
            / "data"
            / "knowledge_base"
        )

    # =====================================================
    # LOAD DOCUMENTS
    # =====================================================

    def _load_documents(self) -> List[dict]:

        documents = []

        if not self.knowledge_base_path.exists():
            return documents

        for file_path in (
            self.knowledge_base_path.glob("*.md")
        ):

            try:
                content = file_path.read_text(
                    encoding="utf-8"
                )

                documents.append(
                    {
                        "source": file_path.name,
                        "content": content,
                    }
                )

            except Exception:
                continue

        return documents

    # =====================================================
    # SEARCH
    # =====================================================

    def search(
        self,
        query: str,
        limit: int = 3,
        min_score: int = 2,
        relative_threshold: float = 0.6,
    ) -> List[dict]:

        documents = self._load_documents()

        if not documents:
            return []

        # -------------------------------------------------
        # 1. Nettoyer les mots de la requête
        # -------------------------------------------------

        query_words = {
            word.lower().strip(
                ".,;:!?()[]{}\"'"
            )
            for word in query.split()
            if len(word) > 3
        }

        scored_documents = []

        # -------------------------------------------------
        # 2. Calcul du score
        # -------------------------------------------------

        for document in documents:

            content_lower = (
                document["content"].lower()
            )

            score = 0

            for word in query_words:

                if word in content_lower:
                    score += 1

            # Filtre minimum absolu
            if score >= min_score:

                scored_documents.append(
                    {
                        "source": document["source"],
                        "content": document["content"],
                        "score": score,
                    }
                )

        # -------------------------------------------------
        # 3. Aucun document pertinent
        # -------------------------------------------------

        if not scored_documents:
            return []

        # -------------------------------------------------
        # 4. Trier par score
        # -------------------------------------------------

        scored_documents.sort(
            key=lambda item: item["score"],
            reverse=True,
        )

        # -------------------------------------------------
        # 5. Calcul du seuil relatif
        # -------------------------------------------------

        best_score = scored_documents[0]["score"]

        minimum_relative_score = (
            best_score
            * relative_threshold
        )

        # -------------------------------------------------
        # 6. Garder uniquement les documents pertinents
        # -------------------------------------------------

        relevant_documents = [
            document
            for document in scored_documents
            if document["score"]
            >= minimum_relative_score
        ]

        # -------------------------------------------------
        # 7. Respecter la limite
        # -------------------------------------------------

        return relevant_documents[:limit]