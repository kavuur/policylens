from app import app, db
from sqlalchemy import text

def migrate_media_fields():
    with app.app_context():
        try:
            # Check if type and visibility columns exist
            result = db.session.execute(text("PRAGMA table_info(media)"))
            columns = [row[1] for row in result]
            
            if 'type' not in columns:
                db.session.execute(text('ALTER TABLE media ADD COLUMN type VARCHAR(50) DEFAULT "other" NOT NULL'))
                print("Added 'type' column to media table")
            
            if 'visibility' not in columns:
                db.session.execute(text('ALTER TABLE media ADD COLUMN visibility VARCHAR(20) DEFAULT "private" NOT NULL'))
                print("Added 'visibility' column to media table")
            
            # Update existing records with default values
            if 'type' not in columns or 'visibility' not in columns:
                db.session.execute(text('UPDATE media SET type="other" WHERE type IS NULL'))
                db.session.execute(text('UPDATE media SET visibility="private" WHERE visibility IS NULL'))
                print("Updated existing records with default values")
            
            db.session.commit()
            print("[SUCCESS] Database migration completed successfully")
                
        except Exception as e:
            db.session.rollback()
            print(f"[ERROR] During database migration: {e}")

if __name__ == '__main__':
    migrate_media_fields()
