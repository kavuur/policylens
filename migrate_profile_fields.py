from app import app, db
from models import User

def upgrade():
    with app.app_context():
        # Add new columns if they don't exist
        with db.engine.connect() as conn:
            # SQLite doesn't support IF NOT EXISTS for ADD COLUMN, so we'll use a try-except
            columns_to_add = [
                'name VARCHAR(100)',
                'age_group VARCHAR(20)',
                'sex VARCHAR(20)',
                'industry VARCHAR(100)',
                'organization VARCHAR(200)'
            ]
            
            for column in columns_to_add:
                try:
                    column_name = column.split()[0]
                    conn.execute(db.text(f'ALTER TABLE user ADD COLUMN {column}'))
                    print(f"Added column: {column_name}")
                except Exception as e:
                    if "duplicate column" in str(e).lower():
                        print(f"Column {column_name} already exists")
                    else:
                        print(f"Error adding column {column_name}: {e}")
            
            conn.commit()
            print("Database schema update completed!")

if __name__ == '__main__':
    upgrade()
