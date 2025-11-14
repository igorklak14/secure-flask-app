# app/trivy_integration.py
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Tuple, Dict, Any, List


# ---------------- Common ----------------
def trivy_available() -> bool:
    return shutil.which("trivy") is not None


def _run(cmd: List[str]) -> str:
    """Запускає CLI і повертає stdout або кидає RuntimeError зі stderr."""
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Trivy error")
    return proc.stdout


# ---------------- Image scan ----------------
def scan_image_to_json(
    image: str,
    ignore_unfixed: bool = True,
    only_os: bool = False,
) -> Tuple[Dict[str, Any], str]:
    """Запускає `trivy image` і повертає (parsed_json, raw_json_str)."""
    if not trivy_available():
        raise RuntimeError("Trivy не знайдено у PATH.")

    cmd: List[str] = ["trivy", "image", "--format", "json", "--timeout", "2m"]
    if ignore_unfixed:
        cmd.append("--ignore-unfixed")
    if only_os:
        cmd += ["--vuln-type", "os"]   # за замовчуванням: os,library
    cmd.append(image)

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Помилка виконання Trivy")
    raw = proc.stdout
    parsed = json.loads(raw)
    return parsed, raw


def summarize_counts(trivy_json: Dict[str, Any]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for r in trivy_json.get("Results", []):
        for v in (r.get("Vulnerabilities") or []):
            sev = (v.get("Severity") or "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1

    return {
        "total": sum(counts.values()),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "unknown": counts["UNKNOWN"],
    }


def extract_vulns_table(trivy_json: Dict[str, Any]):
    """Рядки для таблиці з результатів `trivy image`."""
    rows = []
    for r in trivy_json.get("Results", []):
        target = r.get("Target", "")
        for v in (r.get("Vulnerabilities") or []):
            rows.append({
                "target": target,
                "pkg_name": v.get("PkgName", "") or v.get("PkgID", ""),
                "cve_id": v.get("VulnerabilityID", ""),
                "severity": v.get("Severity", ""),
                "installed_version": v.get("InstalledVersion", ""),
                "fixed_version": v.get("FixedVersion") or "-",
                "title": (v.get("Title") or "")[:140],
                "description": (v.get("Description") or "")[:200],
                "cve_link": v.get("PrimaryURL") or (v.get("References") or [None])[0],
            })
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    rows.sort(key=lambda x: sev_order.get(x["severity"].upper(), 0), reverse=True)
    return rows


# ---------------- Config / FS scan ----------------
def scan_config_to_json(path: str = ".") -> Tuple[Dict[str, Any], str]:
    """`trivy config <path>` — пошук misconfig у Dockerfile/маніфестах."""
    if not trivy_available():
        raise RuntimeError("Trivy не знайдено у PATH.")
    raw = _run(["trivy", "config", "--format", "json", path])
    return json.loads(raw), raw


def scan_fs_to_json(path: str = ".", include_secrets: bool = True) -> Tuple[Dict[str, Any], str]:
    """`trivy fs` — вразливості у залежностях; опційно — секрети в коді."""
    if not trivy_available():
        raise RuntimeError("Trivy не знайдено у PATH.")
    scanners = "vuln,secret" if include_secrets else "vuln"
    raw = _run(["trivy", "fs", "--scanners", scanners, "--format", "json", path])
    return json.loads(raw), raw


def extract_misconfigs_table(conf_json: dict) -> List[dict]:
    """Рядки для таблиці з `trivy config`/`trivy fs` (misconfig)."""
    rows: List[dict] = []

    def _push(target, check, cause_meta):
        rows.append({
            "file": target or "",
            "rule_id": check.get("ID") or check.get("RuleID") or "",
            "title": check.get("Title") or check.get("ID") or "",
            "severity": (check.get("Severity") or "").upper(),
            "desc": (check.get("Description") or "")[:240],
            "help": check.get("PrimaryURL") or (check.get("References") or [None])[0],
            "start_line": (cause_meta or {}).get("StartLine") or "",
            "end_line": (cause_meta or {}).get("EndLine") or "",
        })

    for r in conf_json.get("Results", []):
        target = r.get("Target")
        # Новий формат
        for m in r.get("Misconfigurations", []) or []:
            _push(target, m, m.get("CauseMetadata"))
        # Старий формат
        for m in r.get("MisconfResults", []) or []:
            cause_meta = m.get("CauseMetadata")
            for chk in m.get("Checks", []) or []:
                _push(target, chk, cause_meta)

    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    rows.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)
    return rows


def extract_secrets_table(fs_json: Dict[str, Any]) -> List[dict]:
    """Знайдені секрети з `trivy fs --scanners secret`."""
    rows: List[dict] = []
    for r in fs_json.get("Results", []) or []:
        target = r.get("Target", "")
        for s in r.get("Secrets") or []:
            rows.append({
                "target": target,
                "rule_id": s.get("RuleID"),
                "title": s.get("Title") or "",
                "severity": (s.get("Severity") or ""),
                "match": (s.get("Match") or "")[:120],
            })
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    rows.sort(key=lambda x: sev_order.get((x["severity"] or "").upper(), 0), reverse=True)
    return rows


def summarize_fs_vulns(fs_json: Dict[str, Any]) -> Dict[str, int]:
    """Підсумки по вразливостях із `trivy fs` (залежності)."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for r in fs_json.get("Results", []) or []:
        for v in (r.get("Vulnerabilities") or []):
            sev = (v.get("Severity") or "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
    return {
        "total": sum(counts.values()),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "unknown": counts["UNKNOWN"],
    }


# ---------------- Dockerfile-only scan ----------------
def _trivy_supports_input_flag() -> bool:
    """
    Перевіряємо, чи підтримує поточна версія Trivy прапорець `--input` для `trivy config`.
    Якщо так — використаємо його; якщо ні — дамо шлях позиційно (старий синтаксис).
    """
    try:
        res = subprocess.run(
            ["trivy", "config", "--help"],
            capture_output=True, text=True, check=False
        )
        help_text = (res.stdout or "") + (res.stderr or "")
        return "--input" in help_text
    except Exception:
        return False


def scan_dockerfile_to_json(dockerfile_path: str = "Dockerfile") -> Tuple[Dict[str, Any], str]:
    """
    Сканує конкретний Dockerfile через `trivy config`.
    Працює як з новими (з `--input`), так і зі старими версіями Trivy (позиційний шлях).
    """
    if not trivy_available():
        raise RuntimeError("Trivy не знайдено у PATH.")

    supports_input = _trivy_supports_input_flag()

    cmd: List[str] = ["trivy", "config", "--format", "json", "--timeout", "2m", "--quiet"]
    if supports_input:
        cmd += ["--input", dockerfile_path]
    else:
        # старі релізи Trivy: шлях передається позиційно
        cmd += [dockerfile_path]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    # деякі релізи повертають 1 при знайдених проблемах; це не "збій" для нас
    if proc.returncode not in (0, 1):
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "Помилка виконання Trivy (config)")

    raw = proc.stdout
    parsed = json.loads(raw or "{}")
    return parsed, raw


def extract_dockerfile_findings(conf_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Рядки для таблиці з `trivy config` (Dockerfile)."""
    rows: List[Dict[str, Any]] = []
    for r in conf_json.get("Results", []):
        target = r.get("Target", "")
        for m in (r.get("Misconfigurations") or []):
            meta = m.get("CauseMetadata") or {}
            loc = (meta.get("Location") or {})
            rows.append({
                "file": target or "Dockerfile",
                "id": m.get("ID", ""),
                "title": m.get("Title", "") or m.get("Description", "")[:140],
                "severity": (m.get("Severity") or "UNKNOWN").upper(),
                "message": m.get("Message") or "",
                "url": m.get("PrimaryURL") or (m.get("References") or [None])[0],
                "start_line": loc.get("StartLine"),
                "end_line": loc.get("EndLine"),
            })

    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    rows.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)
    return rows


def summarize_dockerfile_severities(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for r in rows:
        s = r.get("severity", "UNKNOWN").upper()
        counts[s] = counts.get(s, 0) + 1
    counts["total"] = sum(counts.values())
    return counts


# ---------------- SBOM / Syft / Grype ----------------
def syft_available() -> bool:
    return shutil.which("syft") is not None


def grype_available() -> bool:
    return shutil.which("grype") is not None


def syft_generate_sbom(image_or_dir: str, fmt: str = "cyclonedx-json") -> Tuple[dict, str]:
    """Генерує SBOM через Syft. fmt: cyclonedx-json | spdx-json | syft-json."""
    if not syft_available():
        raise RuntimeError("Syft не знайдено у PATH.")
    cmd = ["syft", image_or_dir, "-o", fmt]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Syft помилка")
    raw = proc.stdout
    return json.loads(raw), raw


def grype_scan_sbom_raw(sbom_raw: str) -> Tuple[dict, str]:
    """Сканує SBOM (CycloneDX/SPDX) через Grype, передаючи тимчасовий файл."""
    if not grype_available():
        raise RuntimeError("Grype не знайдено у PATH.")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "sbom.json"
        p.write_text(sbom_raw, encoding="utf-8")
        cmd = ["grype", f"sbom:{str(p)}", "-o", "json"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "Grype помилка")
        raw = proc.stdout
        return json.loads(raw), raw


def summarize_grype(json_doc: dict) -> dict:
    """Підсумок по severities з Grype JSON."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
    for m in json_doc.get("matches", []):
        sev = (m.get("vulnerability", {}).get("severity") or "Unknown").title()
        counts[sev] = counts.get(sev, 0) + 1
    total = sum(counts.values())
    return {"total": total, **counts}


# ---------------- Kubescape ----------------
def kubescape_available() -> bool:
    return shutil.which("kubescape") is not None


def kubescape_scan_path(path: str) -> Tuple[dict, str]:
    """
    kubescape scan <path> --format json --fail-threshold -1
    (fail-threshold -1 щоб не фейлити exit-code при знайдених порушеннях)
    """
    if not kubescape_available():
        raise RuntimeError("Kubescape не знайдено у PATH.")
    cmd = ["kubescape", "scan", path, "--format", "json", "--fail-threshold", "-1"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 4):  # 4 == found misconfig (не помилка для нас)
        raise RuntimeError(proc.stderr.strip() or "Kubescape помилка")
    raw = proc.stdout
    return json.loads(raw), raw


def summarize_kubescape(json_doc: dict) -> dict:
    """Грубий підсумок: кількість failed / passed контролів (структура варіюється між версіями)."""
    failed = 0
    passed = 0
    for r in json_doc.get("results", []):
        status = (r.get("statusInfo", {}).get("status") or "").lower()
        if status == "failed":
            failed += 1
        elif status == "passed":
            passed += 1
    return {"failed": failed, "passed": passed, "total": failed + passed}
