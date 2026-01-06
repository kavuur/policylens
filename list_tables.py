import sys
import importlib
from sqlalchemy import inspect

app_module = importlib.import_module('app')
app = app_module.app
db = app_module.db

with app.app_context():
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    print("Tables found:", tables)
