import importlib
from sqlalchemy import text

app_module = importlib.import_module('app')
app = app_module.app
db = app_module.db

with app.app_context():
    try:
        result = db.session.execute(text('SELECT id, username, email, is_admin, is_view_only_admin FROM "user"'))
        rows = result.fetchall()
        for row in rows:
            print(row)
    except Exception as e:
        print(f"Error querying users: {e}")
