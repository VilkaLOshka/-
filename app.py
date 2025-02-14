from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
from hashlib import sha256

app = Flask(__name__)
app.secret_key = 'abobavenom52'  # Секретный ключ для работы с flash-сообщениями


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


@app.route('/')
def home():
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


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = login_user(username, password)
        if user:
            flash('Вход выполнен успешно!', 'success')
            return redirect(url_for('profile', username=user[1]))
        else:
            flash('Неверное имя пользователя или пароль!', 'error')

    return render_template('login.html')


@app.route('/profile/<username>')
def profile(username):
    return render_template('profile.html', username=username)


if __name__ == '__main__':
    create_database()
    app.run(debug=True)
