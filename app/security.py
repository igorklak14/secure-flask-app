# app/security.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, make_response
from flask_login import login_required
from sqlalchemy import and_
import json

from app import db
from app.models import ScanResult, SBOM

from app.trivy_integration import (
    # Image scan
    scan_image_to_json, summarize_counts, extract_vulns_table,
    # Config / filesystem scan
    scan_config_to_json, scan_fs_to_json,
    extract_misconfigs_table, extract_secrets_table, summarize_fs_vulns,
    # Dockerfile-only scan
    scan_dockerfile_to_json, extract_dockerfile_findings, summarize_dockerfile_severities,
    # SBOM + Grype
    syft_generate_sbom, syft_available,
    grype_scan_sbom_raw, grype_available, summarize_grype,
    # Kubescape
    kubescape_scan_path, summarize_kubescape, kubescape_available,
)

sec_bp = Blueprint("sec", __name__)


# ---------------------------
# Helpers
# ---------------------------
def _cve_set(trivy_json: dict) -> set[str]:
    s = set()
    for r in trivy_json.get("Results", []):
        for v in (r.get("Vulnerabilities") or []):
            vid = v.get("VulnerabilityID")
            if vid:
                s.add(vid)
    return s


# ---------------------------
# Image scan
# ---------------------------
@sec_bp.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    if request.method == "POST":
        image = (request.form.get("image") or "").strip() or "secure-flask-app:latest"
        ignore_unfixed = bool(request.form.get("ignore_unfixed"))
        only_os = bool(request.form.get("only_os"))

        try:
            parsed, raw = scan_image_to_json(
                image,
                ignore_unfixed=ignore_unfixed,
                only_os=only_os,
            )
            sums = summarize_counts(parsed)

            row = ScanResult(
                image=image,
                total=sums.get("total", 0),
                critical=sums.get("critical", 0),
                high=sums.get("high", 0),
                medium=sums.get("medium", 0),
                low=sums.get("low", 0),
                report_json=raw,
            )
            db.session.add(row)
            db.session.commit()

            flash(f"Сканування '{image}' виконано успішно!", "success")
            return redirect(url_for("sec.scan_result", scan_id=row.id))
        except Exception as e:
            db.session.rollback()
            flash(f"Помилка сканування: {e}", "danger")
            return redirect(url_for("sec.scan"))

    scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(10).all()
    return render_template("scan_form.html", scans=scans)


@sec_bp.route("/scan/<int:scan_id>")
@login_required
def scan_result(scan_id: int):
    sr = ScanResult.query.get_or_404(scan_id)
    parsed = json.loads(sr.report_json)
    table = extract_vulns_table(parsed)
    sums = summarize_counts(parsed)

    prev_sr = (
        ScanResult.query
        .filter(and_(ScanResult.image == sr.image, ScanResult.created_at < sr.created_at))
        .order_by(ScanResult.created_at.desc())
        .first()
    )
    prev_id = prev_sr.id if prev_sr else None

    return render_template(
        "scan_result.html",
        scan=sr,
        summary=sums,
        rows=table,
        prev_id=prev_id,
        export=False,
    )


@sec_bp.route("/scan/<int:scan_id>/diff")
@login_required
def scan_diff(scan_id: int):
    cur = ScanResult.query.get_or_404(scan_id)
    prev = (
        ScanResult.query
        .filter(and_(ScanResult.image == cur.image, ScanResult.created_at < cur.created_at))
        .order_by(ScanResult.created_at.desc())
        .first()
    )
    if not prev:
        flash("Немає попереднього скану цього образу для порівняння.", "info")
        return redirect(url_for("sec.scan_result", scan_id=scan_id))

    cur_parsed = json.loads(cur.report_json)
    prev_parsed = json.loads(prev.report_json)

    cur_set = _cve_set(cur_parsed)
    prev_set = _cve_set(prev_parsed)

    added = sorted(list(cur_set - prev_set))
    removed = sorted(list(prev_set - cur_set))
    unchanged = sorted(list(cur_set & prev_set))

    def _meta_map(parsed):
        m = {}
        for r in parsed.get("Results", []):
            for v in (r.get("Vulnerabilities") or []):
                vid = v.get("VulnerabilityID")
                if vid and vid not in m:
                    m[vid] = {
                        "severity": (v.get("Severity") or "").upper(),
                        "title": (v.get("Title") or v.get("Description") or "")[:140],
                        "url": v.get("PrimaryURL") or (v.get("References") or [None])[0],
                        "pkg": v.get("PkgName") or v.get("PkgID") or "",
                    }
        return m

    cur_meta = _meta_map(cur_parsed)
    prev_meta = _meta_map(prev_parsed)

    return render_template(
        "scan_diff.html",
        image=cur.image,
        current=cur,
        previous=prev,
        added=[(c, cur_meta.get(c, {})) for c in added],
        removed=[(c, prev_meta.get(c, {})) for c in removed],
        unchanged_count=len(unchanged),
    )


@sec_bp.route("/scan/<int:scan_id>/download.json")
@login_required
def scan_download_json(scan_id: int):
    sr = ScanResult.query.get_or_404(scan_id)
    resp = make_response(sr.report_json)
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename=scan_{scan_id}.json'
    return resp


@sec_bp.route("/scan/<int:scan_id>/download.html")
@login_required
def scan_download_html(scan_id: int):
    sr = ScanResult.query.get_or_404(scan_id)
    parsed = json.loads(sr.report_json)
    table = extract_vulns_table(parsed)
    sums = summarize_counts(parsed)

    html = render_template(
        "scan_result.html",
        scan=sr,
        summary=sums,
        rows=table,
        prev_id=None,
        export=True
    )
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename=scan_{scan_id}.html'
    return resp


# ---------------------------
# SBOM (Syft) + Grype
# ---------------------------
@sec_bp.route("/scan/<int:scan_id>/sbom/create", methods=["POST"])
@login_required
def sbom_create(scan_id: int):
    sr = ScanResult.query.get_or_404(scan_id)
    try:
        if not syft_available():
            raise RuntimeError("Syft не знайдено у PATH.")
        _parsed, raw = syft_generate_sbom(sr.image, fmt="cyclonedx-json")
        rec = SBOM(scan_id=sr.id, tool="syft", format="cyclonedx-json", sbom_json=raw)
        db.session.add(rec)
        db.session.commit()
        flash("SBOM згенеровано (Syft CycloneDX).", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Помилка SBOM: {e}", "danger")
    return redirect(url_for("sec.scan_result", scan_id=scan_id))


@sec_bp.route("/sbom/<int:sbom_id>/download.json")
@login_required
def sbom_download(sbom_id: int):
    sb = SBOM.query.get_or_404(sbom_id)
    resp = make_response(sb.sbom_json)
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename=sbom_{sb.id}.json'
    return resp


@sec_bp.route("/sbom/<int:sbom_id>/grype")
@login_required
def sbom_grype(sbom_id: int):
    sb = SBOM.query.get_or_404(sbom_id)
    try:
        if not grype_available():
            raise RuntimeError("Grype не знайдено у PATH.")
        g_parsed, g_raw = grype_scan_sbom_raw(sb.sbom_json)
        summ = summarize_grype(g_parsed)
        return render_template("sbom_grype.html", sbom=sb, summary=summ, raw=g_raw)
    except Exception as e:
        flash(f"Помилка Grype: {e}", "danger")
        return redirect(url_for("sec.scan_result", scan_id=sb.scan_id))


# ---------------------------
# Kubescape (K8s YAML/Helм/Manifest)
# ---------------------------
@sec_bp.route("/scan/k8s", methods=["GET", "POST"])
@login_required
def scan_k8s():
    ctx = {"ran": False, "error": None, "path": ".", "summary": None, "raw": None}
    if request.method == "POST":
        path = (request.form.get("path") or ".").strip() or "."
        ctx["path"] = path
        try:
            if not kubescape_available():
                raise RuntimeError("Kubescape не знайдено у PATH.")
            parsed, raw = kubescape_scan_path(path)
            ctx["summary"] = summarize_kubescape(parsed)
            ctx["raw"] = raw
            ctx["ran"] = True
        except Exception as e:
            ctx["error"] = str(e)
            ctx["ran"] = True
    return render_template("scan_k8s.html", **ctx)


# ---------------------------
# Config & Code scan (Trivy config/filesystem)
# ---------------------------
@sec_bp.route("/scan/config", methods=["GET", "POST"], endpoint="scan_config_page")
@login_required
def scan_config_page():
    """
    Сканує:
      - Dockerfile / конфіги (trivy config)
      - секрети в коді (trivy filesystem --security-checks secrets)
      - вразливості в залежностях (trivy filesystem)
    """
    ctx = {
        "misconfigs": [],
        "secrets": [],
        "deps_summary": None,
        "ran": False,
        "error": None,
        "path": ".",
        "json_url": None,
        "html_url": None,
        "export": False,
    }

    if request.method == "POST":
        path = (request.form.get("path") or ".").strip()
        do_conf = bool(request.form.get("do_conf"))
        do_secrets = bool(request.form.get("do_secrets"))
        do_deps = bool(request.form.get("do_deps"))

        ctx["path"] = path

        try:
            if do_conf:
                conf_parsed, _ = scan_config_to_json(path)
                ctx["misconfigs"] = extract_misconfigs_table(conf_parsed)

            if do_secrets or do_deps:
                fs_parsed, _ = scan_fs_to_json(path, include_secrets=do_secrets)
                if do_secrets:
                    ctx["secrets"] = extract_secrets_table(fs_parsed)
                if do_deps:
                    ctx["deps_summary"] = summarize_fs_vulns(fs_parsed)

            ctx["ran"] = True

            # Лінки експорту з такими ж параметрами
            q = dict(path=path, conf=int(do_conf), secrets=int(do_secrets), deps=int(do_deps))
            ctx["json_url"] = url_for("sec.scan_config_export_json", **q)
            ctx["html_url"] = url_for("sec.scan_config_export_html", **q)

        except Exception as e:
            ctx["error"] = str(e)
            ctx["ran"] = True

    return render_template("scan_config.html", **ctx)


@sec_bp.route("/scan/config/export.json")
@login_required
def scan_config_export_json():
    path = request.args.get("path", ".")
    do_conf = request.args.get("conf") == "1"
    do_secrets = request.args.get("secrets") == "1"
    do_deps = request.args.get("deps") == "1"

    out = {"path": path, "misconfigs": [], "secrets": [], "deps_summary": None}

    if do_conf:
        conf_parsed, _ = scan_config_to_json(path)
        out["misconfigs"] = extract_misconfigs_table(conf_parsed)

    if do_secrets or do_deps:
        fs_parsed, _ = scan_fs_to_json(path, include_secrets=do_secrets)
        if do_secrets:
            out["secrets"] = extract_secrets_table(fs_parsed)
        if do_deps:
            out["deps_summary"] = summarize_fs_vulns(fs_parsed)

    resp = make_response(json.dumps(out, ensure_ascii=False, indent=2))
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=config_scan.json"
    return resp


@sec_bp.route("/scan/config/export.html")
@login_required
def scan_config_export_html():
    path = request.args.get("path", ".")
    do_conf = request.args.get("conf") == "1"
    do_secrets = request.args.get("secrets") == "1"
    do_deps = request.args.get("deps") == "1"

    ctx = {
        "ran": True,
        "error": None,
        "misconfigs": [],
        "secrets": [],
        "deps_summary": None,
        "path": path,
        "export": True,   # ховаємо навігацію у шаблоні
        "json_url": None,
        "html_url": None,
    }

    try:
        if do_conf:
            conf_parsed, _ = scan_config_to_json(path)
            ctx["misconfigs"] = extract_misconfigs_table(conf_parsed)
        if do_secrets or do_deps:
            fs_parsed, _ = scan_fs_to_json(path, include_secrets=do_secrets)
            if do_secrets:
                ctx["secrets"] = extract_secrets_table(fs_parsed)
            if do_deps:
                ctx["deps_summary"] = summarize_fs_vulns(fs_parsed)
    except Exception as e:
        ctx["error"] = str(e)

    html = render_template("scan_config.html", **ctx)
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=config_scan.html"
    return resp


# ---------------------------
# Dockerfile-only scan
# ---------------------------
@sec_bp.route("/scan/dockerfile", methods=["GET", "POST"], endpoint="scan_dockerfile")
@login_required
def scan_dockerfile():
    ctx = {
        "ran": False,
        "error": None,
        "path": "Dockerfile",
        "rows": [],
        "summary": None,
    }

    if request.method == "POST":
        path = (request.form.get("path") or "").strip() or "Dockerfile"
        ctx["path"] = path
        try:
            parsed, _ = scan_dockerfile_to_json(path)
            rows = extract_dockerfile_findings(parsed)
            ctx["rows"] = rows
            ctx["summary"] = summarize_dockerfile_severities(rows)
            ctx["ran"] = True
        except Exception as e:
            ctx["error"] = str(e)
            ctx["ran"] = True

    return render_template("dockerfile_scan.html", **ctx)

@sec_bp.route("/scan/export.csv")
@login_required
def export_scans_csv():
    from io import StringIO
    import csv

    buf = StringIO()
    w = csv.writer(buf)
    w.writerow(["id","image","created_at","total","critical","high","medium","low"])
    for s in ScanResult.query.order_by(ScanResult.created_at.desc()).all():
        w.writerow([s.id, s.image, s.created_at.isoformat(), s.total, s.critical, s.high, s.medium, s.low])

    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=scans.csv"
    return resp
