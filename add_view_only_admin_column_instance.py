import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'policylens.db')

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
# Check if column exists
cur.execute("PRAGMA table_info('user')")
columns = [row[1] for row in cur.fetchall()]
if 'is_view_only_admin' not in columns:
    try:
        cur.execute("ALTER TABLE user ADD COLUMN is_view_only_admin BOOLEAN NOT NULL DEFAULT 0")
        conn.commit()
        print('Column added successfully to instance/policylens.db')
    except Exception as e:
        print(f"Error adding column: {e}")
else:
    print('Column already exists in instance/policylens.db')
conn.close()
