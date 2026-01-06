import importlib

# Dynamically import the app module (app.py) to access the Flask app and db
app_module = importlib.import_module('app')
app = app_module.app
db = app_module.db

with app.app_context():
    # Check if column already exists
    result = db.session.execute("PRAGMA table_info('user')").fetchall()
    columns = [row[1] for row in result]
    if 'is_view_only_admin' not in columns:
        db.session.execute("ALTER TABLE user ADD COLUMN is_view_only_admin BOOLEAN NOT NULL DEFAULT 0")
        db.session.commit()
        print('Column added successfully')
    else:
        print('Column already exists')
