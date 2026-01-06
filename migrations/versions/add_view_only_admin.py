"""Add is_view_only_admin to user

Revision ID: add_view_only_admin
Revises: 
Create Date: 2023-11-25 10:45:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_view_only_admin'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Add the is_view_only_admin column to the user table
    op.add_column('user', sa.Column('is_view_only_admin', sa.Boolean(), nullable=True, server_default='0'))
    # Update existing rows to set is_view_only_admin to False
    op.execute('UPDATE user SET is_view_only_admin = 0 WHERE is_view_only_admin IS NULL')
    # Alter the column to be non-nullable
    op.alter_column('user', 'is_view_only_admin', existing_type=sa.Boolean(), nullable=False)


def downgrade():
    # Remove the column if we need to rollback
    op.drop_column('user', 'is_view_only_admin')
