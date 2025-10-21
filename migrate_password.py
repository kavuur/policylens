from app import app, db
from models import User
from sqlalchemy import text

def migrate_passwords():
    with app.app_context():
        try:
            # Check if password_hash column exists
            result = db.session.execute(text("PRAGMA table_info(user)"))
            columns = [row[1] for row in result]
            
            if 'password_hash' not in columns:
                # Add the new column
                db.session.execute(text('ALTER TABLE user ADD COLUMN password_hash VARCHAR(128)'))
                
                # Migrate existing passwords (if any)
                users = User.query.all()
                for user in users:
                    if hasattr(user, 'password'):
                        user.set_password(user.password)
                
                db.session.commit()
                print("[SUCCESS] Updated user table with password hashing")
            else:
                print("[INFO] password_hash column already exists")
                
        except Exception as e:
            db.session.rollback()
            print(f"[ERROR] During password migration: {e}")

if __name__ == '__main__':
    migrate_passwords()
