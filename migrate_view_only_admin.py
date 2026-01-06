"""
Migration script to add is_view_only_admin column to User table
"""
from app import app, db
from models.models import User

def migrate():
    with app.app_context():
        try:
            # Check if column already exists
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('user')]
            
            if 'is_view_only_admin' in columns:
                print("Column 'is_view_only_admin' already exists. Skipping migration.")
                return
            
            # Add the new column
            with db.engine.connect() as conn:
                conn.execute(db.text(
                    "ALTER TABLE user ADD COLUMN is_view_only_admin BOOLEAN DEFAULT 0"
                ))
                conn.commit()
            
            print("Successfully added 'is_view_only_admin' column to User table.")
            print("All existing users have is_view_only_admin set to False (0).")
            
        except Exception as e:
            print(f"Error during migration: {e}")
            raise

if __name__ == '__main__':
    migrate()
