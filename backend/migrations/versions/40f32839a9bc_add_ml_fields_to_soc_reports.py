"""add ml fields to soc reports

Revision ID: 40f32839a9bc
Revises: 79656bc2f800
Create Date: 2026-08-29 17:39:36.768503
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "40f32839a9bc"
down_revision: Union[str, Sequence[str], None] = "79656bc2f800"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "soc_reports",
        sa.Column(
            "ml_status",
            sa.String(length=50),
            nullable=True,
        ),
    )

    op.add_column(
        "soc_reports",
        sa.Column(
            "ml_prediction",
            sa.String(length=50),
            nullable=True,
        ),
    )

    op.add_column(
        "soc_reports",
        sa.Column(
            "ml_probabilities",
            postgresql.JSONB(
                astext_type=sa.Text()
            ),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column(
        "soc_reports",
        "ml_probabilities",
    )

    op.drop_column(
        "soc_reports",
        "ml_prediction",
    )

    op.drop_column(
        "soc_reports",
        "ml_status",
    )