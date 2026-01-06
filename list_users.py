from app import app, db
from models.models import User

with app.app_context():
    users = User.query.all()
    for u in users:
        print(f"ID: {u.id}, Username: {u.username}, Email: {u.email}, Admin: {u.is_admin}, ViewOnly: {u.is_view_only_admin}")
