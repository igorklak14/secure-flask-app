from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User
from app import db

auth_bp = Blueprint('auth', __name__)

# ---------------- REGISTER ----------------
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('sec.scan'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Користувач з таким іменем вже існує.', 'warning')
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Реєстрація успішна! Тепер ви можете увійти.', 'success')
            return redirect(url_for('auth.login'))

    return render_template('register.html')


# ---------------- LOGIN ----------------
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('sec.scan'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f'Вітаю, {username}! Вхід успішний ✅', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('sec.scan'))
        else:
            flash("Невірне ім'я користувача або пароль.", 'danger')

    return render_template('login.html')


# ---------------- LOGOUT ----------------
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ви вийшли з системи.', 'info')
    return redirect(url_for('auth.login'))


# ---------------- TIMESHIFT: зробити користувача адміном ----------------
@auth_bp.route("/make-admin/<username>")
@login_required
def make_admin(username):
    # Якщо вже є хоч один адмін — дозволяти тільки адмінам
    admins = User.query.filter_by(role="admin").count()
    if admins > 0 and not current_user.is_admin():
        abort(403)

    # Якщо адмінів немає, дозволяємо ЗРОБИТИ СЕБЕ адміном
    if admins == 0 and current_user.username != username:
        abort(403)

    u = User.query.filter_by(username=username).first_or_404()
    u.role = "admin"
    db.session.commit()
    flash(f"Користувач {username} тепер admin ✅", "success")
    return redirect(url_for("main.dashboard"))
