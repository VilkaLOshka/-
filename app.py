from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
from hashlib import sha256

app = Flask(__name__)
app.secret_key = '121212356klo1'


def create_database():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            card_number TEXT NOT NULL,
            card_holder TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            cvv TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()


def register_user(username, password):
    password_hash = sha256(password.encode()).hexdigest()
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        ''', (username, password_hash))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def login_user(username, password):
    password_hash = sha256(password.encode()).hexdigest()
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, username FROM users WHERE username = ? AND password_hash = ?
    ''', (username, password_hash))
    user = cursor.fetchone()
    conn.close()
    return user


def save_card_data(user_id, card_number, card_holder, expiry_date, cvv):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO cards (user_id, card_number, card_holder, expiry_date, cvv)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, card_number, card_holder, expiry_date, cvv))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Ошибка при сохранении данных карты: {e}")
        return False
    finally:
        conn.close()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = login_user(username, password)
        if user:
            session['username'] = user[1]
            flash('Вход выполнен успешно!', 'success')
            return redirect(url_for('profile', username=user[1]))
        else:
            flash('Неверное имя пользователя или пароль!', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Пароли не совпадают!', 'error')
            return redirect(url_for('register'))

        if register_user(username, password):
            flash('Регистрация успешна! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Пользователь с таким именем уже существует!', 'error')

    return render_template('register.html')


@app.route('/profile/<username>')
def profile(username):
    if 'username' not in session or session['username'] != username:
        flash('Доступ запрещен!', 'error')
        return redirect(url_for('login'))
    return render_template('profile.html', username=username)


@app.route('/save_card', methods=['POST'])
def save_card():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Доступ запрещен!'})

    data = request.get_json()
    card_number = data.get('card_number')
    card_holder = data.get('card_holder')
    expiry_date = data.get('expiry_date')
    cvv = data.get('cvv')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (session['username'],))
    user_id = cursor.fetchone()[0]
    conn.close()

    if save_card_data(user_id, card_number, card_holder, expiry_date, cvv):
        return jsonify({'success': True, 'message': 'Данные успешно сохранены!'})
    else:
        return jsonify({'success': False, 'message': 'Ошибка при сохранении данных карты.'})


@app.route('/dengidavai')
def dengidavai():
    if 'username' not in session:
        flash('Доступ запрещен!', 'error')
        return redirect(url_for('login'))
    return render_template('dengidavai.html', username=session['username'])


@app.route('/index2')
def index2():
    if 'username' not in session:
        flash('Доступ запрещен!', 'error')
        return redirect(url_for('login'))
    return render_template('index2.html', username=session['username'])


if __name__ == '__main__':
    create_database()
    app.run(debug=True)
