from app import app, db
from sqlalchemy import text

def add_is_admin_column():
    with app.app_context():
        with db.engine.connect() as conn:
            try:
                conn.execute(text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
                conn.commit()
                print("Successfully added is_admin column.")
            except Exception as e:
                print(f"Error adding column (might already exist): {e}")

if __name__ == "__main__":
    add_is_admin_column()
