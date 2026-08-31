"""add multi-source correlation fields

Revision ID: 2d87f685e2ec
Revises: 60810b700695
Create Date: 2026-08-31 03:55:22.701775
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "2d87f685e2ec"
down_revision: Union[str, Sequence[str], None] = "60810b700695"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Add multi-source correlation fields.

    Important:
    LangGraph checkpoint tables are intentionally untouched.
    """

    # =====================================================
    # AI ANALYSES
    # =====================================================

    op.add_column(
        "ai_analyses",
        sa.Column(
            "correlation_id",
            sa.String(length=100),
            nullable=True,
        ),
    )

    op.add_column(
        "ai_analyses",
        sa.Column(
            "correlation_confidence",
            sa.String(length=50),
            nullable=True,
        ),
    )

    op.add_column(
        "ai_analyses",
        sa.Column(
            "correlated_incident_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    op.add_column(
        "ai_analyses",
        sa.Column(
            "correlated_sources",
            postgresql.JSONB(
                astext_type=sa.Text()
            ),
            nullable=True,
        ),
    )

    op.create_index(
        "ix_ai_analyses_correlation_id",
        "ai_analyses",
        [
            "correlation_id",
        ],
        unique=False,
    )

    # Remove temporary DB default.
    # SQLAlchemy model default remains responsible
    # for new ORM objects.
    op.alter_column(
        "ai_analyses",
        "correlated_incident_count",
        server_default=None,
    )

    # =====================================================
    # SOC REPORTS
    # =====================================================

    op.add_column(
        "soc_reports",
        sa.Column(
            "correlation_id",
            sa.String(length=100),
            nullable=True,
        ),
    )

    op.add_column(
        "soc_reports",
        sa.Column(
            "correlation_confidence",
            sa.String(length=50),
            nullable=True,
        ),
    )

    op.add_column(
        "soc_reports",
        sa.Column(
            "correlated_incident_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    op.add_column(
        "soc_reports",
        sa.Column(
            "correlated_sources",
            postgresql.JSONB(
                astext_type=sa.Text()
            ),
            nullable=True,
        ),
    )

    op.create_index(
        "ix_soc_reports_correlation_id",
        "soc_reports",
        [
            "correlation_id",
        ],
        unique=False,
    )

    op.alter_column(
        "soc_reports",
        "correlated_incident_count",
        server_default=None,
    )


def downgrade() -> None:
    """
    Remove only the multi-source correlation fields.

    LangGraph checkpoint tables are intentionally untouched.
    """

    # =====================================================
    # SOC REPORTS
    # =====================================================

    op.drop_index(
        "ix_soc_reports_correlation_id",
        table_name="soc_reports",
    )

    op.drop_column(
        "soc_reports",
        "correlated_sources",
    )

    op.drop_column(
        "soc_reports",
        "correlated_incident_count",
    )

    op.drop_column(
        "soc_reports",
        "correlation_confidence",
    )

    op.drop_column(
        "soc_reports",
        "correlation_id",
    )

    # =====================================================
    # AI ANALYSES
    # =====================================================

    op.drop_index(
        "ix_ai_analyses_correlation_id",
        table_name="ai_analyses",
    )

    op.drop_column(
        "ai_analyses",
        "correlated_sources",
    )

    op.drop_column(
        "ai_analyses",
        "correlated_incident_count",
    )

    op.drop_column(
        "ai_analyses",
        "correlation_confidence",
    )

    op.drop_column(
        "ai_analyses",
        "correlation_id",
    )