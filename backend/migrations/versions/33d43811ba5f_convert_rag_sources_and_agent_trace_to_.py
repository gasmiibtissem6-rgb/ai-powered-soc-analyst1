"""convert rag sources and agent trace to jsonb

Revision ID: 33d43811ba5f
Revises: 5c119ddb4bf0
Create Date: 2026-08-24

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "33d43811ba5f"
down_revision: Union[str, Sequence[str], None] = "5c119ddb4bf0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    op.alter_column(
        "ai_analyses",
        "rag_sources",
        existing_type=sa.Text(),
        type_=postgresql.JSONB(),
        existing_nullable=True,
        postgresql_using="rag_sources::jsonb",
    )

    op.alter_column(
        "ai_analyses",
        "agent_trace",
        existing_type=sa.Text(),
        type_=postgresql.JSONB(),
        existing_nullable=True,
        postgresql_using="agent_trace::jsonb",
    )


def downgrade() -> None:

    op.alter_column(
        "ai_analyses",
        "agent_trace",
        existing_type=postgresql.JSONB(),
        type_=sa.Text(),
        existing_nullable=True,
        postgresql_using="agent_trace::text",
    )

    op.alter_column(
        "ai_analyses",
        "rag_sources",
        existing_type=postgresql.JSONB(),
        type_=sa.Text(),
        existing_nullable=True,
        postgresql_using="rag_sources::text",
    )