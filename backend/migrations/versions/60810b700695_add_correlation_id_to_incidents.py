"""add correlation id to incidents

Revision ID: 60810b700695
Revises: ca8087ef5bc0
Create Date: 2026-08-31 01:41:44.484554

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "60810b700695"
down_revision: Union[str, Sequence[str], None] = "ca8087ef5bc0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Add correlation support to SOC incidents.

    IMPORTANT:
    LangGraph checkpoint tables are intentionally
    not managed by this migration.
    """

    op.add_column(
        "incidents",
        sa.Column(
            "correlation_id",
            sa.String(length=100),
            nullable=True,
        ),
    )

    op.create_index(
        "ix_incidents_correlation_id",
        "incidents",
        ["correlation_id"],
        unique=False,
    )


def downgrade() -> None:
    """
    Remove correlation support from SOC incidents.
    """

    op.drop_index(
        "ix_incidents_correlation_id",
        table_name="incidents",
    )

    op.drop_column(
        "incidents",
        "correlation_id",
    )