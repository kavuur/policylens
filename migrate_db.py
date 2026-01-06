from app import app, db
from models import *
from sqlalchemy import text

def migrate_database():
    with app.app_context():
        # Add file_size column to Media table if it doesn't exist
        try:
            # Check if column already exists
            result = db.session.execute(text("PRAGMA table_info(media)"))
            columns = [row[1] for row in result]
            
            if 'file_size' not in columns:
                db.session.execute(text('ALTER TABLE media ADD COLUMN file_size BIGINT'))
                db.session.commit()
                print("[SUCCESS] Added file_size column to Media table")
            else:
                print("[INFO] file_size column already exists in Media table")
                
        except Exception as e:
            db.session.rollback()
            print(f"[ERROR] During migration: {e}")

if __name__ == '__main__':
    migrate_database()
