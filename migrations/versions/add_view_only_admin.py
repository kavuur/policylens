"""Add is_view_only_admin to user

Revision ID: add_view_only_admin
Revises:
Create Date: 2023-11-25 10:45:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision = 'add_view_only_admin'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
	"""Add the is_view_only_admin column."""
	bind = op.get_bind()
	inspector = inspect(bind)
	columns = {col['name'] for col in inspector.get_columns('user')}
	if 'is_view_only_admin' in columns:
		return

	op.add_column('user', sa.Column('is_view_only_admin', sa.Boolean(), nullable=True, server_default='0'))
	op.execute('UPDATE "user" SET is_view_only_admin = 0 WHERE is_view_only_admin IS NULL')
	op.alter_column('user', 'is_view_only_admin', existing_type=sa.Boolean(), nullable=False, server_default=None)


def downgrade():
	"""Remove the is_view_only_admin column."""
	bind = op.get_bind()
	inspector = inspect(bind)
	columns = {col['name'] for col in inspector.get_columns('user')}
	if 'is_view_only_admin' not in columns:
		return

	op.drop_column('user', 'is_view_only_admin')
