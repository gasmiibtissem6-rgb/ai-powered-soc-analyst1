"""add incident technical fields

Revision ID: 79656bc2f800
Revises: 8d9aaac84264
Create Date: 2026-08-29 02:38:06.234396
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "79656bc2f800"
down_revision: Union[str, Sequence[str], None] = "8d9aaac84264"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column(
            "hostname",
            sa.String(length=255),
            nullable=True,
        ),
    )

    op.add_column(
        "incidents",
        sa.Column(
            "source_ip",
            sa.String(length=45),
            nullable=True,
        ),
    )

    op.add_column(
        "incidents",
        sa.Column(
            "destination_ip",
            sa.String(length=45),
            nullable=True,
        ),
    )

    op.add_column(
        "incidents",
        sa.Column(
            "username",
            sa.String(length=255),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column(
        "incidents",
        "username",
    )

    op.drop_column(
        "incidents",
        "destination_ip",
    )

    op.drop_column(
        "incidents",
        "source_ip",
    )

    op.drop_column(
        "incidents",
        "hostname",
    )