from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required
from app.authz import roles_required
from app import db
from app.models import User

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.route("/users", methods=["GET"])
@login_required
@roles_required("admin")
def users_list():
    q = (request.args.get("q") or "").strip()
    query = User.query
    if q:
        query = query.filter(User.username.ilike(f"%{q}%"))
    users = query.order_by(User.username.asc()).all()
    return render_template("admin_users.html", users=users, q=q)

@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@roles_required("admin")
def set_role(user_id: int):
    user = User.query.get_or_404(user_id)
    role = (request.form.get("role") or "user").strip().lower()
    if role not in ("user", "admin"):
        flash("Неприпустима роль.", "danger")
        return redirect(url_for("admin.users_list"))

    # не дозволяємо зняти роль з останнього адміна
    if user.role == "admin" and role != "admin":
        admin_count = User.query.filter(User.role == "admin").count()
        if admin_count <= 1:
            flash("Неможливо забрати роль з останнього адміністратора.", "warning")
            return redirect(url_for("admin.users_list"))

    user.role = role
    db.session.commit()
    flash(f"Роль для {user.username} змінено на {role}.", "success")
    return redirect(url_for("admin.users_list"))
