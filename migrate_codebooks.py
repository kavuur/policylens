from app import app, db
from models import Codebook

def upgrade():
    with app.app_context():
        # This will create all tables that don't exist yet
        db.create_all()
        print("Database schema updated successfully!")

if __name__ == '__main__':
    upgrade()
