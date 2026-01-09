from app import app, db
from models.models import User

def init_db():
    with app.app_context():

        # # # clear existing data and create fresh tables
        # db.drop_all()

        # # Create all database tables
        # db.create_all()
        
        # Create admin user if it doesn't exist
        if not User.query.filter_by(username='admin_user').first():
            admin = User(
                username='admin_user',
                email='admin@policylens.ai',
                is_active=True,
                is_admin=True
            )
            admin.set_password('admin123')  # In production, use a strong password
            db.session.add(admin)
            db.session.commit()
            print("Database initialized with admin user")
        else:
            print("Database already initialized")

if __name__ == '__main__':
    init_db()
