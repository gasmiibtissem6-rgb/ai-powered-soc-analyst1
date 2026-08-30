"""add workflow status to incidents

Revision ID: ca8087ef5bc0
Revises: 40f32839a9bc
Create Date: 2026-08-30 20:53:42.769623
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "ca8087ef5bc0"
down_revision: Union[str, Sequence[str], None] = "40f32839a9bc"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add workflow tracking fields to incidents."""

    op.add_column(
        "incidents",
        sa.Column(
            "workflow_status",
            sa.String(length=50),
            nullable=False,
            server_default="pending",
        ),
    )

    op.add_column(
        "incidents",
        sa.Column(
            "workflow_error",
            sa.Text(),
            nullable=True,
        ),
    )

    # Existing rows now have "pending".
    # Remove the DB-level default afterward because
    # SQLAlchemy already provides the application default.
    op.alter_column(
        "incidents",
        "workflow_status",
        server_default=None,
    )


def downgrade() -> None:
    """Remove workflow tracking fields from incidents."""

    op.drop_column(
        "incidents",
        "workflow_error",
    )

    op.drop_column(
        "incidents",
        "workflow_status",
    )