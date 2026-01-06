from app import app, db

def update_relationships():
    """Update database relationships."""
    # This will create any missing tables and update the schema
    with app.app_context():
        db.create_all()
        print("Database relationships updated successfully")

if __name__ == '__main__':
    update_relationships()
