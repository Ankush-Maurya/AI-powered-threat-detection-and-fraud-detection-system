import sqlite3

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT,
password TEXT
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS login_attempts (
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT,
time TEXT,
status TEXT
)
''')

conn.commit()
conn.close()

print("Database ready")