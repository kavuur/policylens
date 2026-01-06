from app import app, db
from sqlalchemy import inspect, text

def upgrade():
    with app.app_context():
        inspector = inspect(db.engine)
        cols = [c['name'] for c in inspector.get_columns('codebook')]

        if 'project_id' not in cols:
            print('Adding project_id column to codebook table...')
            db.session.execute(text('ALTER TABLE codebook ADD COLUMN project_id INTEGER REFERENCES project(id)'))
            # Ensure index exists
            try:
                db.session.execute(text('CREATE INDEX IF NOT EXISTS ix_codebook_project_id ON codebook (project_id)'))
            except Exception:
                # Some older SQLAlchemy/Postgres combos may not support IF NOT EXISTS
                try:
                    db.session.execute(text('CREATE INDEX ix_codebook_project_id ON codebook (project_id)'))
                except Exception:
                    pass
            db.session.commit()
            print('Added project_id column to codebook table.')
        else:
            print('project_id column already exists in codebook table.')

        # Print current structure via inspector
        cols_details = inspector.get_columns('codebook')
        print('\nCurrent codebook table structure:')
        for col in cols_details:
            print(f"Column: {col['name']}, Type: {col.get('type')}, Nullable: {col.get('nullable')}")

if __name__ == '__main__':
    upgrade()
