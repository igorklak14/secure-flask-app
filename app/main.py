# app/main.py
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from sqlalchemy import func
from app import db
from app.models import ScanResult

main_bp = Blueprint("main", __name__)

@main_bp.route("/")
@main_bp.route("/dashboard")
@login_required
def dashboard():
    # агрегати по БД
    total_scans = db.session.query(func.count(ScanResult.id)).scalar() or 0
    distinct_images = db.session.query(func.count(func.distinct(ScanResult.image))).scalar() or 0

    crit, high, med, low, total = db.session.query(
        func.coalesce(func.sum(ScanResult.critical), 0),
        func.coalesce(func.sum(ScanResult.high), 0),
        func.coalesce(func.sum(ScanResult.medium), 0),
        func.coalesce(func.sum(ScanResult.low), 0),
        func.coalesce(func.sum(ScanResult.total), 0),
    ).one()

    last_scan = ScanResult.query.order_by(ScanResult.created_at.desc()).first()
    recent = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(5).all()

    return render_template(
        "dashboard.html",
        username=current_user.username,
        total_scans=total_scans,
        distinct_images=distinct_images,
        agg={"critical": crit, "high": high, "medium": med, "low": low, "total": total},
        last_scan=last_scan,
        recent=recent,
    )
