import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'policylens.db')

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print("Tables found:", [t[0] for t in tables])
    conn.close()
except Exception as e:
    print(f"Error: {e}")
