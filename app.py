import os
from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from forms import NoteForm, EditForm, LoginForm, RegisterForm
from models import db, init_db, User, Note, create_user, verify_user
from markupsafe import escape
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from waitress import serve

# Загрузка переменных окружения
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback_key')

# Конфигурация базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Режим отладки
app.config['DEBUG'] = False if os.getenv('FLASK_ENV') == 'production' else True

# Безопасность cookie
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Инициализация CSRF-защиты
csrf = CSRFProtect(app)

# Инициализация базы данных
init_db(app)

# Установка заголовков безопасности
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Server'] = 'SecureApp'
    response.headers.pop('X-Powered-By', None)
    response.headers.pop('X-AspNet-Version', None)
    return response

@app.route('/')
def home():
    return redirect(url_for('index'))

@app.route('/index', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = NoteForm()
    if form.validate_on_submit():
        title = escape(form.title.data)
        content = escape(form.content.data)
        if "http://" in title or "https://" in title or "http://" in content or "https://" in content:
            flash("Ссылки запрещены!", "danger")
        else:
            note = Note(title=title, content=content, user_id=session['user_id'])
            db.session.add(note)
            db.session.commit()
            flash("Заметка добавлена", "success")
        return redirect(url_for('index'))

    notes = Note.query.filter_by(user_id=session['user_id']).order_by(Note.created_at.desc()).all()
    return render_template('index.html', form=form, notes=notes)

@app.route('/edit/<int:note_id>', methods=['GET', 'POST'])
def edit(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    note = Note.query.get(note_id)
    if not note or note.user_id != session['user_id']:
        flash("Нет доступа к этой заметке", "danger")
        return redirect(url_for('index'))

    form = EditForm(obj=note)
    if form.validate_on_submit():
        title = escape(form.title.data)
        content = escape(form.content.data)
        if "http://" in title or "https://" in title or "http://" in content or "https://" in content:
            flash("Ссылки запрещены!", "danger")
        else:
            note.title = title
            note.content = content
            db.session.commit()
            flash("Заметка обновлена", "success")
        return redirect(url_for('index'))

    return render_template('edit.html', form=form)

@app.route('/delete/<int:note_id>', methods=['POST'])
def delete(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    note = Note.query.get(note_id)
    if note and note.user_id == session['user_id']:
        db.session.delete(note)
        db.session.commit()
        flash("Заметка удалена", "success")
    else:
        flash("Нет доступа к удалению", "danger")
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = verify_user(form.username.data, form.password.data)
        if user:
            session['user_id'] = user.id
            flash("Успешный вход", "success")
            return redirect(url_for('index'))
        else:
            flash("Неверные данные", "danger")
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            create_user(form.username.data, form.password.data)
            flash("Регистрация успешна. Теперь войдите.", "success")
            return redirect(url_for('login'))
        except Exception:
            flash("Имя пользователя уже занято", "danger")
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash("Вы вышли", "info")
    return redirect(url_for('login'))

# Запуск через Waitress
if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=8000)
