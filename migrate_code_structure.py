from app import app, db
from models import Code, SubCode, SubSubCode

def upgrade():
    """Create the new code structure tables."""
    # Create the tables
    db.create_all()
    
    # Add any initial data if needed
    # ...
    
    print("Successfully created code structure tables")

if __name__ == '__main__':
    with app.app_context():
        upgrade()
