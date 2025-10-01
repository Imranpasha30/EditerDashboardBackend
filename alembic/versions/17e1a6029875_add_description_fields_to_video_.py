"""add_description_fields_to_video_submissions

Revision ID: 17e1a6029875
Revises: 2580dd9569e7
Create Date: 2025-10-01 10:42:35.598022

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '17e1a6029875'
down_revision: Union[str, Sequence[str], None] = '2580dd9569e7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
