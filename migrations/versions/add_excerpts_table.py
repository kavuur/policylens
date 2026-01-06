"""Add Excerpt model

Revision ID: add_excerpts_table
Revises: 
Create Date: 2025-09-09 11:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_excerpts_table'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Create excerpts table
    op.create_table('excerpts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('media_id', sa.Integer(), nullable=False),
        sa.Column('codebook_id', sa.Integer(), nullable=True),
        sa.Column('code', sa.String(length=100), nullable=True),
        sa.Column('subcode', sa.String(length=100), nullable=True),
        sa.Column('excerpt', sa.Text(), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['codebook_id'], ['codebook.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['media_id'], ['media.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['project_id'], ['project.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_excerpts_created_at'), 'excerpts', ['created_at'], unique=False)

def downgrade():
    op.drop_index(op.f('ix_excerpts_created_at'), table_name='excerpts')
    op.drop_table('excerpts')
