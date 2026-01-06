import sys
from app import app, db, User

def create_admin(email, username=None, password=None):
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user:
            print(f"User with email {email} found. Promoting to admin.")
            user.is_admin = True
            db.session.commit()
            print(f"User {user.username} is now an admin.")
        else:
            if not username or not password:
                print("User not found. To create a new admin, provide username and password.")
                return
            
            print(f"Creating new admin user {username} ({email}).")
            user = User(username=username, email=email, is_admin=True)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            print(f"Admin user {username} created.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python create_admin.py <email> [username] [password]")
        sys.exit(1)
    
    email = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else None
    password = sys.argv[3] if len(sys.argv) > 3 else None
    
    create_admin(email, username, password)
