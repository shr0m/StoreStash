import sqlite3

def init_db():
    conn = sqlite3.connect('storestash.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS stock (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1
        );
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            otp TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            privilege TEXT NOT NULL CHECK(privilege IN ('admin', 'store team', 'view')),
            requires_password_change INTEGER DEFAULT 1,
            theme TEXT NOT NULL DEFAULT 'light'
        );
    ''')

    conn.commit()
    conn.close()