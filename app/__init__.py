# app/__init__.py
import os
import secrets
from pathlib import Path

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    BASE_DIR = Path(__file__).resolve().parent.parent
    TEMPLATES_DIR = BASE_DIR / "templates"
    STATIC_DIR = BASE_DIR / "static"
    INSTANCE_DIR = BASE_DIR / "instance"

    # створюємо директорії, якщо немає
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    STATIC_DIR.mkdir(parents=True, exist_ok=True)

    app = Flask(
        __name__,
        template_folder=str(TEMPLATES_DIR),
        static_folder=str(STATIC_DIR),
        instance_path=str(INSTANCE_DIR),
    )

    # ---- DB CONFIG ----
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{INSTANCE_DIR / 'app.db'}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ---- 4.3(c) Secrets management: SECRET_KEY ----
    # 1) спершу з .env
    secret_from_env = os.getenv("SECRET_KEY")

    # 2) якщо нема — пробуємо прочитати з secrets/secret_key.txt
    if not secret_from_env:
        key_file = BASE_DIR / "secrets" / "secret_key.txt"
        if key_file.exists():
            secret_from_env = key_file.read_text(encoding="utf-8").strip()

    # 3) останній fallback — згенерувати випадковий ключ
    if not secret_from_env:
        secret_from_env = secrets.token_hex(32)

    app.config["SECRET_KEY"] = secret_from_env
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")

    # ---- INIT EXTENSIONS ----
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return db.session.get(User, int(user_id))

    # ---- BLUEPRINTS ----
    from .auth import auth_bp
    from .main import main_bp
    from .security import sec_bp
    from .admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(sec_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")

    return app
