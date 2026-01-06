from app import app, db
from models.models import User

with app.app_context():
    user = User.query.filter_by(username='admin_2').first()
    if user:
        user.set_password('password002')
        db.session.commit()
        print("Password for admin_2 reset successfully.")
    else:
        print("User admin_2 not found.")
