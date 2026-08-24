"""extend ai analysis for soc workflow

Revision ID: 5c119ddb4bf0
Revises: 14a56b15c63a
Create Date: 2026-08-24 03:39:41.994046

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '5c119ddb4bf0'
down_revision: Union[str, Sequence[str], None] = '14a56b15c63a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'ai_analyses',
        sa.Column(
            'mitre_name',
            sa.String(length=150),
            nullable=True,
        )
    )

    op.add_column(
        'ai_analyses',
        sa.Column(
            'mitre_valid',
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        )
    )

    op.add_column(
        'ai_analyses',
        sa.Column(
            'rag_sources',
            sa.Text(),
            nullable=True,
        )
    )

    op.add_column(
        'ai_analyses',
        sa.Column(
            'human_approval_required',
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        )
    )

    op.add_column(
        'ai_analyses',
        sa.Column(
            'human_approved',
            sa.Boolean(),
            nullable=True,
        )
    )

    op.add_column(
        'ai_analyses',
        sa.Column(
            'human_review_status',
            sa.String(length=50),
            nullable=True,
        )
    )

    op.add_column(
        'ai_analyses',
        sa.Column(
            'human_comment',
            sa.Text(),
            nullable=True,
        )
    )

    op.add_column(
        'ai_analyses',
        sa.Column(
            'response_status',
            sa.String(length=50),
            nullable=True,
        )
    )

    op.add_column(
        'ai_analyses',
        sa.Column(
            'thread_id',
            sa.String(length=100),
            nullable=True,
        )
    )

    op.add_column(
        'ai_analyses',
        sa.Column(
            'agent_trace',
            sa.Text(),
            nullable=True,
        )
    )

    op.create_index(
        op.f('ix_ai_analyses_thread_id'),
        'ai_analyses',
        ['thread_id'],
        unique=False,
    )

def downgrade() -> None:
    op.drop_index(
        op.f('ix_ai_analyses_thread_id'),
        table_name='ai_analyses',
    )

    op.drop_column(
        'ai_analyses',
        'agent_trace',
    )

    op.drop_column(
        'ai_analyses',
        'thread_id',
    )

    op.drop_column(
        'ai_analyses',
        'response_status',
    )

    op.drop_column(
        'ai_analyses',
        'human_comment',
    )

    op.drop_column(
        'ai_analyses',
        'human_review_status',
    )

    op.drop_column(
        'ai_analyses',
        'human_approved',
    )

    op.drop_column(
        'ai_analyses',
        'human_approval_required',
    )

    op.drop_column(
        'ai_analyses',
        'rag_sources',
    )

    op.drop_column(
        'ai_analyses',
        'mitre_valid',
    )

    op.drop_column(
        'ai_analyses',
        'mitre_name',
    )