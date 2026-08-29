"""add soar actions table

Revision ID: 8d9aaac84264
Revises: 1e3eca576387
Create Date: 2026-08-29 01:10:26.678457
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "8d9aaac84264"
down_revision: Union[str, Sequence[str], None] = "1e3eca576387"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "soar_actions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("action_type", sa.String(length=50), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("requires_approval", sa.Boolean(), nullable=False),
        sa.Column("approved", sa.Boolean(), nullable=True),
        sa.Column(
            "result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("executed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        op.f("ix_soar_actions_id"),
        "soar_actions",
        ["id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_soar_actions_incident_id"),
        "soar_actions",
        ["incident_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_soar_actions_incident_id"),
        table_name="soar_actions",
    )

    op.drop_index(
        op.f("ix_soar_actions_id"),
        table_name="soar_actions",
    )

    op.drop_table("soar_actions")