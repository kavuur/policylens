from app import app, db
from sqlalchemy import text

def upgrade():
    with app.app_context():
        with db.engine.connect() as conn:
            # Start a transaction
            with conn.begin():
                # Check if project_id column exists
                result = conn.execute(
                    text("PRAGMA table_info(codebook)")
                ).fetchall()
                
                # Check if project_id column exists
                has_project_id = any(col[1] == 'project_id' for col in result)
                
                if not has_project_id:
                    print("Adding project_id column to codebook table...")
                    # Add the project_id column
                    conn.execute(text('''
                        ALTER TABLE codebook 
                        ADD COLUMN project_id INTEGER 
                        REFERENCES project(id)
                    '''))
                    print("Added project_id column to codebook table.")
                else:
                    print("project_id column already exists in codebook table.")
                
                # Verify the changes
                result = conn.execute(
                    text("PRAGMA table_info(codebook)")
                ).fetchall()
                print("\nCurrent codebook table structure:")
                for col in result:
                    print(f"Column: {col[1]}, Type: {col[2]}, Nullable: {not col[3]}")

if __name__ == '__main__':
    upgrade()
