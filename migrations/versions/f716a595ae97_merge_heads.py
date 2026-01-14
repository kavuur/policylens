"""merge heads

Revision ID: f716a595ae97
Revises: add_excerpts_table, add_view_only_admin
Create Date: 2025-11-25 14:42:29.241693

"""
from alembic import op  # noqa: F401  (required for Alembic runtime)
import sqlalchemy as sa  # noqa: F401


# revision identifiers, used by Alembic.
revision = 'f716a595ae97'
down_revision = ('add_excerpts_table', 'add_view_only_admin')
branch_labels = None
depends_on = None


def upgrade():
	"""No-op merge revision."""
	pass


def downgrade():
	"""No-op merge revision."""
	pass
