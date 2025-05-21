import sqlite3

def init_db():
    conn = sqlite3.connect('storestash.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS stock (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1
        )
    ''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()