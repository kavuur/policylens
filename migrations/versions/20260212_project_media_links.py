"""add project media association table

Revision ID: 20260212_project_media_links
Revises: 20260114_privacy_and_analysis
Create Date: 2026-02-12 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.exc import NoSuchTableError


# revision identifiers, used by Alembic.
revision = '20260212_project_media_links'
down_revision = '20260114_privacy_and_analysis'
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

    def fk_names(table_name: str) -> list:
        if not has_table(table_name):
            return []
        return [fk['name'] for fk in inspector.get_foreign_keys(table_name)]

    if not has_table('project_media'):
        op.create_table(
            'project_media',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('project_id', sa.Integer(), nullable=False),
            sa.Column('media_id', sa.Integer(), nullable=False),
            sa.Column('added_by', sa.Integer(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True, server_default=sa.text('now()')),
            sa.ForeignKeyConstraint(['added_by'], ['user.id'], ondelete='SET NULL'),
            sa.ForeignKeyConstraint(['media_id'], ['media.id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['project_id'], ['project.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('project_id', 'media_id', name='uq_project_media_project_id_media_id')
        )
        op.create_index('ix_project_media_project_id', 'project_media', ['project_id'], unique=False)
        op.create_index('ix_project_media_media_id', 'project_media', ['media_id'], unique=False)
    else:
        if not has_index('project_media', 'ix_project_media_project_id'):
            op.create_index('ix_project_media_project_id', 'project_media', ['project_id'], unique=False)
        if not has_index('project_media', 'ix_project_media_media_id'):
            op.create_index('ix_project_media_media_id', 'project_media', ['media_id'], unique=False)

    if has_table('media') and has_column('media', 'project_id'):
        metadata = sa.MetaData()
        media_table = sa.Table(
            'media',
            metadata,
            sa.Column('id', sa.Integer),
            sa.Column('project_id', sa.Integer),
            sa.Column('user_id', sa.Integer)
        )
        project_media_table = sa.Table(
            'project_media',
            metadata,
            sa.Column('project_id', sa.Integer),
            sa.Column('media_id', sa.Integer),
            sa.Column('added_by', sa.Integer)
        )

        rows = list(
            bind.execute(
                sa.select(
                    media_table.c.id,
                    media_table.c.project_id,
                    media_table.c.user_id
                ).where(media_table.c.project_id.isnot(None))
            )
        )
        inserted_pairs = set()
        for media_id, project_id, user_id in rows:
            if project_id is None:
                continue
            key = (project_id, media_id)
            if key in inserted_pairs:
                continue
            bind.execute(
                project_media_table.insert().values(
                    project_id=project_id,
                    media_id=media_id,
                    added_by=user_id
                )
            )
            inserted_pairs.add(key)

        result = bind.execute(sa.text("SELECT project_id, COUNT(*) FROM project_media GROUP BY project_id"))
        for project_id, count in result.fetchall():
            bind.execute(
                sa.text("UPDATE project SET media_count = :count WHERE id = :project_id"),
                {"count": count, "project_id": project_id}
            )
        bind.execute(sa.text("UPDATE project SET media_count = COALESCE(media_count, 0)"))

        media_fks = inspector.get_foreign_keys('media') if has_table('media') else []
        fk_to_drop = [fk['name'] for fk in media_fks if fk.get('referred_table') == 'project']
        if has_index('media', 'ix_media_project_id'):
            op.drop_index('ix_media_project_id', table_name='media')
        with op.batch_alter_table('media') as batch_op:
            for fk_name in fk_to_drop:
                batch_op.drop_constraint(fk_name, type_='foreignkey')
            batch_op.drop_column('project_id')


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

    if has_table('media') and not has_column('media', 'project_id'):
        with op.batch_alter_table('media') as batch_op:
            batch_op.add_column(sa.Column('project_id', sa.Integer(), nullable=True))
        if not has_index('media', 'ix_media_project_id'):
            op.create_index('ix_media_project_id', 'media', ['project_id'], unique=False)
        fk_names = [fk['name'] for fk in inspector.get_foreign_keys('media') if fk.get('referred_table') == 'project']
        if not fk_names:
            with op.batch_alter_table('media') as batch_op:
                batch_op.create_foreign_key('media_project_id_fkey', 'project', ['project_id'], ['id'], ondelete='CASCADE')

    if has_table('project_media') and has_column('media', 'project_id'):
        metadata = sa.MetaData()
        project_media_table = sa.Table(
            'project_media',
            metadata,
            sa.Column('project_id', sa.Integer),
            sa.Column('media_id', sa.Integer)
        )
        rows = list(
            bind.execute(
                sa.select(
                    project_media_table.c.media_id,
                    sa.func.min(project_media_table.c.project_id)
                ).group_by(project_media_table.c.media_id)
            )
        )
        for media_id, project_id in rows:
            bind.execute(
                sa.text("UPDATE media SET project_id = :project_id WHERE id = :media_id"),
                {"project_id": project_id, "media_id": media_id}
            )
        result = bind.execute(sa.text("SELECT project_id, COUNT(*) FROM project_media GROUP BY project_id"))
        for project_id, count in result.fetchall():
            bind.execute(
                sa.text("UPDATE project SET media_count = :count WHERE id = :project_id"),
                {"count": count, "project_id": project_id}
            )

    if has_table('project_media'):
        if has_index('project_media', 'ix_project_media_media_id'):
            op.drop_index('ix_project_media_media_id', table_name='project_media')
        if has_index('project_media', 'ix_project_media_project_id'):
            op.drop_index('ix_project_media_project_id', table_name='project_media')
        op.drop_table('project_media')
