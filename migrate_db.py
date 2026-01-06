from app import app, db
from models import *
from sqlalchemy import inspect, text

def migrate_database():
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            cols = [c['name'] for c in inspector.get_columns('media')]

            if 'file_size' not in cols:
                db.session.execute(text("ALTER TABLE media ADD COLUMN file_size BIGINT"))
                db.session.commit()
                print("[SUCCESS] Added file_size column to Media table")
            else:
                print("[INFO] file_size column already exists in Media table")

        except Exception as e:
            db.session.rollback()
            print(f"[ERROR] During migration: {e}")

if __name__ == '__main__':
    migrate_database()
