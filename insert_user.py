import sqlite3

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute(
    "INSERT INTO users (username,password) VALUES (?,?)",
    ("admin", "1234")
)

conn.commit()

cursor.execute("SELECT * FROM users")
print(cursor.fetchall())

conn.close()

print("User inserted successfully")