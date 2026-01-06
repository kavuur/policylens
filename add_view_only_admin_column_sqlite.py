import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'policylens.db')

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
# Check if column exists
cur.execute("PRAGMA table_info('user')")
columns = [row[1] for row in cur.fetchall()]
if 'is_view_only_admin' not in columns:
    cur.execute("ALTER TABLE user ADD COLUMN is_view_only_admin BOOLEAN NOT NULL DEFAULT 0")
    conn.commit()
    print('Column added')
else:
    print('Column already exists')
conn.close()
