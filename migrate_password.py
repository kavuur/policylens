from app import app, db
from models import User
from sqlalchemy import inspect, text

def migrate_passwords():
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            cols = [c['name'] for c in inspector.get_columns('user')]

            if 'password_hash' not in cols:
                # Add the new column
                db.session.execute(text('ALTER TABLE "user" ADD COLUMN password_hash VARCHAR(128)'))

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
