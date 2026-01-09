from app import app, db
from models.models import User

def init_db():
    with app.app_context():

        # # # clear existing data and create fresh tables
        # db.drop_all()

        # # Create all database tables
        # db.create_all()
        
        # Create 2 admin users, view only admin user and normal user
        if not User.query.filter_by(username='admin1').first():
            admin_user = User(
                username='admin1',
                name='Administrator',
                email='admin1@example.com',
                is_active=True, 
                is_admin=True)
            admin_user.set_password('admin123')  # Replace with a secure password
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created with username 'admin1' and password 'admin123'")
        else:
            print("Admin user already exists.")

        # view only admin user
        if not User.query.filter_by(username='admin2').first():
            admin_user = User(
                username='admin2',
                name='View Only Administrator',
                email='admin2@example.com',
                is_active=True, 
                is_admin=True,
                is_view_only_admin=True)
            admin_user.set_password('admin123')  # Replace with a secure password
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created with username 'admin2' and password 'admin123'")
        else:
            print("Admin user already exists.")

        #normal user
        if not User.query.filter_by(username='user1').first():
            normal_user = User(
                username='user1',
                name='Normal User One',
                email='user1@example.com',
                is_active=True, 
                is_admin=False)
            normal_user.set_password('user123')  # Replace with a secure password
            db.session.add(normal_user)
            db.session.commit()
            print("Normal user created with username 'user1' and password 'user123'")
        else:
            print("Normal user already exists.")
        

        

if __name__ == '__main__':
    init_db()
