import sqlite3
import os

dbs = ['policylens.db', 'instance/policylens.db']

for db_path in dbs:
    if os.path.exists(db_path):
        print(f"--- Checking {db_path} ---")
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, is_admin, is_view_only_admin FROM user")
            rows = cursor.fetchall()
            for row in rows:
                print(row)
            conn.close()
        except Exception as e:
            print(f"Error reading {db_path}: {e}")
    else:
        print(f"--- {db_path} does not exist ---")
