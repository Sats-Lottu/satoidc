"""rename lnurl challenge consumed flag

Revision ID: dad11091fd15
Revises: 32a836ab058b
Create Date: 2026-05-13 14:34:26.404602

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'dad11091fd15'
down_revision: Union[str, Sequence[str], None] = '32a836ab058b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_index(
        "ix_lnurl_auth_challenges_verified",
        table_name="lnurl_auth_challenges",
    )
    op.alter_column(
        "lnurl_auth_challenges",
        "verified",
        new_column_name="consumed",
        existing_type=sa.Boolean(),
        existing_nullable=False,
    )
    op.create_index(
        "ix_lnurl_auth_challenges_consumed",
        "lnurl_auth_challenges",
        ["consumed"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(
        "ix_lnurl_auth_challenges_consumed",
        table_name="lnurl_auth_challenges",
    )
    op.alter_column(
        "lnurl_auth_challenges",
        "consumed",
        new_column_name="verified",
        existing_type=sa.Boolean(),
        existing_nullable=False,
    )
    op.create_index(
        "ix_lnurl_auth_challenges_verified",
        "lnurl_auth_challenges",
        ["verified"],
        unique=False,
    )
