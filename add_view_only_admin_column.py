import importlib
from sqlalchemy import inspect, text

# Dynamically import the app module (app.py) to access the Flask app and db
app_module = importlib.import_module('app')
app = app_module.app
db = app_module.db

with app.app_context():
    inspector = inspect(db.engine)
    cols = [c['name'] for c in inspector.get_columns('user')]
    if 'is_view_only_admin' not in cols:
        db.session.execute(text('ALTER TABLE "user" ADD COLUMN is_view_only_admin BOOLEAN NOT NULL DEFAULT FALSE'))
        db.session.commit()
        print('Column added successfully')
    else:
        print('Column already exists')
