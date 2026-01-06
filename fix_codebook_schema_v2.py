from app import app, db
from sqlalchemy import inspect, text

def upgrade():
    with app.app_context():
        with db.engine.connect() as conn:
            # Start a transaction
            with conn.begin():
                inspector = inspect(db.engine)
                cols = [c['name'] for c in inspector.get_columns('codebook')]

                has_project_id = 'project_id' in cols

                if not has_project_id:
                    print("Adding project_id column to codebook table...")
                    conn.execute(text("ALTER TABLE codebook ADD COLUMN project_id INTEGER REFERENCES project(id)"))
                    print("Added project_id column to codebook table.")
                else:
                    print("project_id column already exists in codebook table.")

                # Verify the changes
                inspector = inspect(db.engine)
                cols_details = inspector.get_columns('codebook')
                print("\nCurrent codebook table structure:")
                for col in cols_details:
                    print(f"Column: {col['name']}, Type: {col.get('type')}, Nullable: {col.get('nullable')}")

if __name__ == '__main__':
    upgrade()
