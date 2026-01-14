"""add privacy flags and analysis runs

Revision ID: 20260114_privacy_and_analysis
Revises: f716a595ae97
Create Date: 2026-01-14 10:15:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.exc import NoSuchTableError
from pathlib import Path


# revision identifiers, used by Alembic.
revision = '20260114_privacy_and_analysis'
down_revision = 'f716a595ae97'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    def has_table(table_name: str) -> bool:
        return inspector.has_table(table_name)

    def has_column(table_name: str, column_name: str) -> bool:
        try:
            return column_name in {col['name'] for col in inspector.get_columns(table_name)}
        except NoSuchTableError:
            return False

    def has_index(table_name: str, index_name: str) -> bool:
        if not has_table(table_name):
            return False
        return index_name in {idx['name'] for idx in inspector.get_indexes(table_name)}

    # Visibility columns
    if not has_column('project', 'visibility'):
        op.add_column('project', sa.Column('visibility', sa.String(length=20), nullable=False, server_default='private'))
    if not has_column('codebook', 'visibility'):
        op.add_column('codebook', sa.Column('visibility', sa.String(length=20), nullable=False, server_default='private'))
    if not has_column('excerpts', 'visibility'):
        op.add_column('excerpts', sa.Column('visibility', sa.String(length=20), nullable=False, server_default='private'))

    # Analysis run table
    if not has_table('analysis_run'):
        op.create_table(
            'analysis_run',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('project_id', sa.Integer(), nullable=False),
            sa.Column('codebook_id', sa.Integer(), nullable=True),
            sa.Column('user_id', sa.Integer(), nullable=True),
            sa.Column('name', sa.String(length=200), nullable=False),
            sa.Column('notes', sa.Text(), nullable=True),
            sa.Column('media_snapshot', sa.JSON(), nullable=True),
            sa.Column('visibility', sa.String(length=20), nullable=False, server_default='private'),
            sa.Column('created_at', sa.DateTime(), nullable=True, server_default=sa.text('now()')),
            sa.Column('updated_at', sa.DateTime(), nullable=True, server_default=sa.text('now()')),
            sa.ForeignKeyConstraint(['codebook_id'], ['codebook.id'], ondelete='SET NULL'),
            sa.ForeignKeyConstraint(['project_id'], ['project.id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='SET NULL'),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_analysis_run_project_id'), 'analysis_run', ['project_id'], unique=False)
        op.create_index(op.f('ix_analysis_run_codebook_id'), 'analysis_run', ['codebook_id'], unique=False)
        op.create_index(op.f('ix_analysis_run_user_id'), 'analysis_run', ['user_id'], unique=False)
    else:
        if not has_index('analysis_run', op.f('ix_analysis_run_project_id')):
            op.create_index(op.f('ix_analysis_run_project_id'), 'analysis_run', ['project_id'], unique=False)
        if not has_index('analysis_run', op.f('ix_analysis_run_codebook_id')):
            op.create_index(op.f('ix_analysis_run_codebook_id'), 'analysis_run', ['codebook_id'], unique=False)
        if not has_index('analysis_run', op.f('ix_analysis_run_user_id')):
            op.create_index(op.f('ix_analysis_run_user_id'), 'analysis_run', ['user_id'], unique=False)

    # Excerpts -> analysis relationship
    added_analysis_column = False
    if not has_column('excerpts', 'analysis_id'):
        op.add_column('excerpts', sa.Column('analysis_id', sa.Integer(), nullable=True))
        added_analysis_column = True

    fk_names = []
    if has_table('excerpts'):
        fk_names = [fk['name'] for fk in inspector.get_foreign_keys('excerpts')]

    if 'fk_excerpts_analysis_run' not in fk_names and (added_analysis_column or has_column('excerpts', 'analysis_id')):
        op.create_foreign_key(
            'fk_excerpts_analysis_run',
            'excerpts',
            'analysis_run',
            ['analysis_id'],
            ['id'],
            ondelete='SET NULL'
        )

    # Clean up server defaults so future inserts rely on ORM defaults
    if has_column('project', 'visibility'):
        with op.batch_alter_table('project') as batch_op:
            batch_op.alter_column('visibility', server_default=None)
    if has_column('codebook', 'visibility'):
        with op.batch_alter_table('codebook') as batch_op:
            batch_op.alter_column('visibility', server_default=None)
    if has_column('excerpts', 'visibility'):
        with op.batch_alter_table('excerpts') as batch_op:
            batch_op.alter_column('visibility', server_default=None)
    if has_column('analysis_run', 'visibility'):
        with op.batch_alter_table('analysis_run') as batch_op:
            batch_op.alter_column('visibility', server_default=None)


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    def has_table(table_name: str) -> bool:
        return inspector.has_table(table_name)

    def has_column(table_name: str, column_name: str) -> bool:
        try:
            return column_name in {col['name'] for col in inspector.get_columns(table_name)}
        except NoSuchTableError:
            return False

    def has_index(table_name: str, index_name: str) -> bool:
        if not has_table(table_name):
            return False
        return index_name in {idx['name'] for idx in inspector.get_indexes(table_name)}

    if has_table('excerpts'):
        fk_names = [fk['name'] for fk in inspector.get_foreign_keys('excerpts')]
        if 'fk_excerpts_analysis_run' in fk_names:
            op.drop_constraint('fk_excerpts_analysis_run', 'excerpts', type_='foreignkey')
        if has_column('excerpts', 'analysis_id'):
            op.drop_column('excerpts', 'analysis_id')
        if has_column('excerpts', 'visibility'):
            op.drop_column('excerpts', 'visibility')

    if has_table('analysis_run'):
        if has_index('analysis_run', op.f('ix_analysis_run_user_id')):
            op.drop_index(op.f('ix_analysis_run_user_id'), table_name='analysis_run')
        if has_index('analysis_run', op.f('ix_analysis_run_codebook_id')):
            op.drop_index(op.f('ix_analysis_run_codebook_id'), table_name='analysis_run')
        if has_index('analysis_run', op.f('ix_analysis_run_project_id')):
            op.drop_index(op.f('ix_analysis_run_project_id'), table_name='analysis_run')
        op.drop_table('analysis_run')

    if has_column('codebook', 'visibility'):
        op.drop_column('codebook', 'visibility')
    if has_column('project', 'visibility'):
        op.drop_column('project', 'visibility')

# allow running independently
if __name__ == "__main__":
    import sys
    from alembic import command
    from alembic.config import Config

    version_dir = Path(__file__).resolve().parent
    project_root = version_dir.parents[1]
    sys.path.insert(0, str(project_root))

    from app import app  # pylint: disable=import-error

    config_path = project_root / "alembic.ini"
    if not config_path.exists():
        config_path = project_root / "migrations" / "alembic.ini"

    alembic_cfg = Config(str(config_path))

    with app.app_context():
        command.upgrade(alembic_cfg, "head")

