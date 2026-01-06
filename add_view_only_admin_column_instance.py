import importlib
from sqlalchemy import inspect, text

# Use the application's SQLAlchemy DB (expects DATABASE_URL / DATABASE_URI to point to Postgres)
app_module = importlib.import_module('app')
app = app_module.app
db = app_module.db

def add_column():
    with app.app_context():
        inspector = inspect(db.engine)
        cols = [c['name'] for c in inspector.get_columns('user')]
        if 'is_view_only_admin' not in cols:
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN is_view_only_admin BOOLEAN NOT NULL DEFAULT FALSE'))
            db.session.commit()
            print('Column added successfully to database')
        else:
            print('Column already exists in database')

if __name__ == '__main__':
    add_column()
