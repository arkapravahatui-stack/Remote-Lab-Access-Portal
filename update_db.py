import sqlite3

db_path = r'C:\Users\hp\Desktop\lab-portal\lab_portal.db'

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE users ADD COLUMN bandwidth_used INTEGER DEFAULT 0")
    cursor.execute("ALTER TABLE users ADD COLUMN bandwidth_limit INTEGER DEFAULT 10485760")
    conn.commit()
    print("Quota columns added successfully.")
except sqlite3.OperationalError:
    print("Columns already exist!")

conn.close()