import sqlite3

DB_PATH = 'storestash.db'  # Replace with your actual database file path

def add_name_column():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check if 'name' column already exists
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'name' in columns:
        print("'name' column already exists.")
        conn.close()
        return

    # Add the 'name' column (TEXT, nullable)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN name TEXT")
        conn.commit()
        print("'name' column added successfully.")
    except sqlite3.OperationalError as e:
        print(f"Error adding column: {e}")

    conn.close()

if __name__ == '__main__':
    add_name_column()