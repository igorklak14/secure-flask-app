# app/models.py
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(16), default="user", nullable=False)  # "admin" | "user"

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        return (self.role or "user") == "admin"

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"

class ScanResult(db.Model):
    __tablename__ = "scan_result"

    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.String(255), nullable=False)     # ім'я/тег образу
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    total = db.Column(db.Integer, default=0, nullable=False)
    critical = db.Column(db.Integer, default=0, nullable=False)
    high = db.Column(db.Integer, default=0, nullable=False)
    medium = db.Column(db.Integer, default=0, nullable=False)
    low = db.Column(db.Integer, default=0, nullable=False)

    # можна замінити на JSON тип для Postgres; для SQLite зручно тримати як текст
    report_json = db.Column(db.Text, nullable=False)

class SBOM(db.Model):
    __tablename__ = "sbom"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_result.id"), nullable=False)
    tool = db.Column(db.String(32))      # "syft"
    format = db.Column(db.String(32))    # "cyclonedx-json"
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    sbom_json = db.Column(db.Text, nullable=False)

    scan = db.relationship("ScanResult", backref=db.backref("sboms", lazy=True))
