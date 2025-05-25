import sqlite3

DB_PATH = 'your_database.db'  # Replace with your actual database file path

def remove_theme_column():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check if 'theme' column exists
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'theme' not in columns:
        print("'theme' column does not exist.")
        conn.close()
        return

    # SQLite does not support DROP COLUMN directly. We'll need to recreate the table.
    cursor.execute("ALTER TABLE users RENAME TO users_old")

    # Create new table without 'theme' column (adjust this schema to match your original)
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            privilege TEXT NOT NULL
        )
    """)

    # Copy data without 'theme' column
    cursor.execute("""
        INSERT INTO users (id, username, password, privilege)
        SELECT id, username, password, privilege FROM users_old
    """)

    # Drop the old table
    cursor.execute("DROP TABLE users_old")

    conn.commit()
    conn.close()
    print("'theme' column removed successfully.")

if __name__ == '__main__':
    remove_theme_column()