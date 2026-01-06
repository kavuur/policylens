from app import app, db
from models.models import User

users_to_create = [
    {'username': 'admin005', 'email': 'admin005@policylens.com', 'password': 'password05'},
    {'username': 'admin003', 'email': 'admin003@policylens.com', 'password': 'password03'},
    {'username': 'admin004', 'email': 'admin004@policylens.com', 'password': 'password05'}
]

with app.app_context():
    for u_data in users_to_create:
        user = User.query.filter_by(username=u_data['username']).first()
        if not user:
            # Check if email exists to avoid unique constraint error
            email_user = User.query.filter_by(email=u_data['email']).first()
            if email_user:
                print(f"User with email {u_data['email']} already exists (username: {email_user.username}). Skipping creation of {u_data['username']}.")
                continue
                
            user = User(username=u_data['username'], email=u_data['email'])
            user.set_password(u_data['password'])
            user.is_view_only_admin = True
            user.is_admin = False
            db.session.add(user)
            print(f"Creating user {u_data['username']}")
        else:
            print(f"User {u_data['username']} already exists. Updating permissions and password.")
            user.is_view_only_admin = True
            user.is_admin = False
            user.set_password(u_data['password'])
        
    db.session.commit()
    print("Users created/updated successfully.")
