from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.security import require_analyst
from app.models.user import User
from app.services.llm_service import LLMService
from app.services.rag_service import RAGService


router = APIRouter(
    prefix="/analyst",
    tags=["Analyst Assistant"],
)


class AnalystQuestionRequest(BaseModel):
    question: str = Field(
        ...,
        min_length=3,
        max_length=2000,
    )


class RAGSource(BaseModel):
    source: Optional[str] = None
    score: Optional[float] = None


class AnalystQuestionResponse(BaseModel):
    question: str
    answer: str
    sources: List[RAGSource]


@router.post(
    "/ask",
    response_model=AnalystQuestionResponse,
)
def ask_analyst_question(
    payload: AnalystQuestionRequest,
    current_user: User = Depends(
        require_analyst
    ),
):
    question = payload.question.strip()

    if not question:
        raise HTTPException(
            status_code=400,
            detail="Question cannot be empty",
        )

    try:
        rag_service = RAGService()

        rag_context = rag_service.search(
            question,
            limit=5,
        )

        llm_service = LLMService()

        answer = (
            llm_service.answer_analyst_question(
                question=question,
                rag_context=rag_context,
            )
        )

    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Analyst assistant failed: "
                f"{exc}"
            ),
        ) from exc

    sources = []

    for item in rag_context:
        sources.append(
            RAGSource(
                source=item.get("source"),
                score=item.get("score"),
            )
        )

    return AnalystQuestionResponse(
        question=question,
        answer=answer,
        sources=sources,
    )
