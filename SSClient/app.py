from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import json

app = Flask(__name__)
DB_FILE = '../SSServer/storestash.db'

def get_stock_items():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM stock')
    items = cursor.fetchall()
    conn.close()
    return items

@app.route('/')
def dashboard():
    stock_items = get_stock_items()
    return render_template('dashboard.html', stock_items=stock_items)

@app.route('/add_stock_type', methods=['POST'])
def add_stock_type():
    new_type = request.form['new_type']
    initial_quantity = int(request.form['initial_quantity'])

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO stock (type, quantity) VALUES (?, ?)', (new_type, initial_quantity))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/update_stock_batch', methods=['POST'])
def update_stock_batch():
    data = json.loads(request.form['update_data'])

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    for item in data:
        if item['quantity'] == 0:
            cursor.execute('DELETE FROM stock WHERE id = ?', (item['id'],))
        else:
            cursor.execute('UPDATE stock SET quantity = ? WHERE id = ?', (item['quantity'], item['id']))

    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)