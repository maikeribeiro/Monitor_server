from __future__ import annotations

import json
import mimetypes
import os
import pathlib
import platform
import socket
import time
import csv
import io
import subprocess
import zipfile
import shutil
from datetime import datetime
from typing import Iterable, List, Tuple

from flask import (
    Flask,
    abort,
    jsonify,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - handled at runtime
    psutil = None

APP_ROOT = pathlib.Path(__file__).resolve().parent
BASE_BROWSE_PATH = pathlib.Path(os.environ.get("BROWSE_ROOT", "/home")).resolve()
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "100"))
BUILD_ID = os.environ.get("BUILD_ID") or datetime.now().strftime("%Y%m%d-%H%M")
SERVICE_NAME = os.environ.get("SERVICE_NAME", "SistemaME")
SERVICE_MATCH = os.environ.get("SERVICE_MATCH", "/home/sistemame/SistemaME/venv/bin/gunicorn")
SERVICE_USER = os.environ.get("SERVICE_USER", "sistemame")
SERVICE_START_CMD = os.environ.get(
    "SERVICE_START_CMD",
    "/home/sistemame/SistemaME/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 "
    "--log-level info --error-logfile /home/sistemame/bdsistemame/gunicorn-error.log "
    "--access-logfile /home/sistemame/bdsistemame/gunicorn-access.log app:app",
)
SERVICE_WORKDIR = os.environ.get("SERVICE_WORKDIR", "/home/sistemame/SistemaME")
GIT_PULL_DIR = os.environ.get("GIT_PULL_DIR", "/home/sistemame/SistemaME")
GIT_PULL_SCRIPT = os.environ.get("GIT_PULL_SCRIPT", "/home/sistemame/atualizar.sh")
BACKUP_SOURCE = pathlib.Path(
    os.environ.get("BACKUP_SOURCE", "/home/sistemame/bdsistemame")
).resolve()
BACKUP_DEST = pathlib.Path(
    os.environ.get("BACKUP_DEST", "/home/sistemame/OneDrive/bkp_bdsistemame")
).resolve()
BACKUP_SCHEDULE = os.environ.get("BACKUP_SCHEDULE", "07:00,19:00")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

AUTH_STORE = pathlib.Path(
    os.environ.get("AUTH_STORE", str(APP_ROOT / ".credentials.json"))
).resolve()


def _auth_payload() -> dict | None:
    if not AUTH_STORE.exists():
        return None
    try:
        return json.loads(AUTH_STORE.read_text(encoding="utf-8"))
    except Exception:
        return None


@app.context_processor
def inject_build_id() -> dict:
    return {"build_id": BUILD_ID}


def _has_credentials() -> bool:
    payload = _auth_payload()
    return bool(payload and payload.get("username") and payload.get("password_hash"))


def _save_credentials(username: str, password: str) -> None:
    payload = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "created_at": datetime.now().isoformat(),
    }
    AUTH_STORE.parent.mkdir(parents=True, exist_ok=True)
    AUTH_STORE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        os.chmod(AUTH_STORE, 0o600)
    except Exception:
        pass


@app.before_request
def require_login() -> None:
    if request.endpoint in {"static", "login", "setup", "logout"}:
        return
    if request.endpoint == "healthz":
        return
    if not _has_credentials():
        return redirect(url_for("setup", next=request.full_path))
    if not session.get("authenticated"):
        return redirect(url_for("login", next=request.full_path))


def _safe_join(base: pathlib.Path, *paths: str) -> pathlib.Path:
    joined = base.joinpath(*paths).resolve()
    if not str(joined).startswith(str(base)):
        raise ValueError("Invalid path")
    return joined


def _list_dir(path: pathlib.Path) -> List[dict]:
    entries = []
    for entry in path.iterdir():
        try:
            stat = entry.stat()
        except OSError:
            continue
        entries.append(
            {
                "name": entry.name,
                "is_dir": entry.is_dir(),
                "size": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime),
            }
        )
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    return entries


def _fmt_bytes(value: int | float | None) -> str:
    if value is None:
        return "-"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    unit = 0
    while size >= 1024 and unit < len(units) - 1:
        size /= 1024
        unit += 1
    if unit == 0:
        return f"{int(size)} {units[unit]}"
    return f"{size:.1f} {units[unit]}"


def _backup_dir_name(moment: datetime) -> str:
    return moment.strftime("%Y%m%d-%H%M%S")


def _dir_size(path: pathlib.Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for filename in files:
            try:
                total += (pathlib.Path(root) / filename).stat().st_size
            except OSError:
                continue
    return total


def _list_backups() -> List[dict]:
    if not BACKUP_DEST.exists():
        return []
    backups = []
    for entry in BACKUP_DEST.iterdir():
        if not entry.is_dir():
            continue
        try:
            stat = entry.stat()
        except OSError:
            continue
        backups.append(
            {
                "name": entry.name,
                "path": entry,
                "mtime": datetime.fromtimestamp(stat.st_mtime),
            }
        )
    backups.sort(key=lambda item: item["mtime"], reverse=True)
    for backup in backups:
        backup["size"] = _dir_size(backup["path"])
        backup["size_h"] = _fmt_bytes(backup["size"])
    return backups


def _backup_files(base_dir: pathlib.Path) -> List[dict]:
    files = []
    for root, _, filenames in os.walk(base_dir):
        for filename in filenames:
            path = pathlib.Path(root) / filename
            try:
                stat = path.stat()
            except OSError:
                continue
            files.append(
                {
                    "name": filename,
                    "path": path,
                    "rel": path.relative_to(base_dir),
                    "size": stat.st_size,
                    "size_h": _fmt_bytes(stat.st_size),
                    "mtime": datetime.fromtimestamp(stat.st_mtime),
                }
            )
    files.sort(key=lambda item: str(item["rel"]).lower())
    return files


def _relative_to_base(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(BASE_BROWSE_PATH))
    except Exception:
        return ""


def _create_backup() -> Tuple[bool, str]:
    if not BACKUP_SOURCE.exists() or not BACKUP_SOURCE.is_dir():
        return False, "Origem do backup não encontrada."
    try:
        BACKUP_DEST.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False, "Não foi possível criar a pasta de destino."

    backup_dir = BACKUP_DEST / _backup_dir_name(datetime.now())
    try:
        shutil.copytree(BACKUP_SOURCE, backup_dir, copy_function=shutil.copy2)
    except Exception as exc:
        return False, f"Erro ao gerar backup: {exc}"

    return True, f"Backup criado: {backup_dir.name}"


def _service_processes() -> List[dict]:
    if not psutil:
        return []
    procs = []
    for proc in psutil.process_iter(attrs=["pid", "name", "cmdline", "username"]):
        info = proc.info
        cmdline = " ".join(info.get("cmdline") or [])
        if SERVICE_MATCH and SERVICE_MATCH not in cmdline:
            continue
        procs.append(
            {
                "pid": info.get("pid"),
                "name": info.get("name"),
                "cmdline": cmdline,
                "user": info.get("username"),
            }
        )
    return procs


def _list_services() -> List[dict]:
    try:
        res = subprocess.run(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=running",
                "--no-legend",
                "--no-pager",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
    except Exception:
        return []
    if res.returncode != 0:
        return []
    services = []
    for line in (res.stdout or "").splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        unit, load, active, sub, description = parts
        services.append(
            {
                "unit": unit,
                "load": load,
                "active": active,
                "sub": sub,
                "description": description,
            }
        )
    return services


def _run_as_service_user(cmd: List[str], cwd: str | None = None) -> Tuple[int, str]:
    # Uses sudo -u to execute as SERVICE_USER; requires sudoers rule.
    full_cmd = ["sudo", "-u", SERVICE_USER] + cmd
    try:
        res = subprocess.run(
            full_cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
        )
        return res.returncode, (res.stdout or "").strip()
    except Exception as exc:
        return 1, str(exc)


@app.route("/")
def index():
    return redirect(url_for("browse"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if _has_credentials():
        return redirect(url_for("login"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        if not username or not password:
            flash("Informe usuário e senha.")
        elif password != confirm:
            flash("A confirmação da senha não confere.")
        else:
            _save_credentials(username, password)
            flash("Credenciais salvas. Faça o login.")
            return redirect(url_for("login"))
    return render_template("auth.html", mode="setup", title="Configurar acesso")


@app.route("/login", methods=["GET", "POST"])
def login():
    if not _has_credentials():
        return redirect(url_for("setup"))
    next_url = request.args.get("next") or url_for("status")
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        payload = _auth_payload() or {}
        if (
            username == payload.get("username")
            and payload.get("password_hash")
            and check_password_hash(payload["password_hash"], password)
        ):
            session["authenticated"] = True
            session["username"] = username
            return redirect(next_url)
        flash("Usuário ou senha inválidos.")
    return render_template("auth.html", mode="login", title="Entrar", next_url=next_url)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/status")
def status():
    info = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "time": datetime.now(),
        "uptime_seconds": None,
        "cpu_percent": None,
        "mem": None,
        "disk": None,
    }

    if psutil:
        info["uptime_seconds"] = int(time.time() - psutil.boot_time())
        info["cpu_percent"] = psutil.cpu_percent(interval=0.3)
        vm = psutil.virtual_memory()
        info["mem"] = {
            "total": vm.total,
            "used": vm.used,
            "percent": vm.percent,
            "total_h": _fmt_bytes(vm.total),
            "used_h": _fmt_bytes(vm.used),
        }
        du = psutil.disk_usage(str(BASE_BROWSE_PATH))
        info["disk"] = {
            "total": du.total,
            "used": du.used,
            "percent": du.percent,
            "total_h": _fmt_bytes(du.total),
            "used_h": _fmt_bytes(du.used),
        }

    return render_template("status.html", info=info, psutil_available=bool(psutil))


@app.route("/api/status")
def api_status():
    info = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "time": datetime.now().isoformat(),
        "uptime_seconds": None,
        "cpu_percent": None,
        "mem": None,
        "disk": None,
    }
    if psutil:
        info["uptime_seconds"] = int(time.time() - psutil.boot_time())
        info["cpu_percent"] = psutil.cpu_percent(interval=0.1)
        vm = psutil.virtual_memory()
        info["mem"] = {
            "total": vm.total,
            "used": vm.used,
            "percent": vm.percent,
            "total_h": _fmt_bytes(vm.total),
            "used_h": _fmt_bytes(vm.used),
        }
        du = psutil.disk_usage(str(BASE_BROWSE_PATH))
        info["disk"] = {
            "total": du.total,
            "used": du.used,
            "percent": du.percent,
            "total_h": _fmt_bytes(du.total),
            "used_h": _fmt_bytes(du.used),
        }
    return jsonify(info)


@app.route("/api/service")
def api_service():
    procs = _service_processes()
    return jsonify(
        {
            "name": SERVICE_NAME,
            "match": SERVICE_MATCH,
            "running": len(procs) > 0,
            "count": len(procs),
            "pids": [p["pid"] for p in procs],
            "user": (procs[0]["user"] if procs else None),
        }
    )


@app.route("/browse")
def browse():
    rel_path = request.args.get("path", "")
    try:
        current = _safe_join(BASE_BROWSE_PATH, rel_path)
    except ValueError:
        abort(400)

    if not current.exists():
        abort(404)

    if current.is_file():
        return redirect(url_for("download", path=rel_path))

    parent = None
    if current != BASE_BROWSE_PATH:
        parent = str(current.parent.relative_to(BASE_BROWSE_PATH))

    entries = _list_dir(current)
    return render_template(
        "browse.html",
        base_path=str(BASE_BROWSE_PATH),
        rel_path=rel_path,
        parent=parent,
        entries=entries,
    )


@app.route("/backup")
def backup():
    backups = _list_backups()
    return render_template(
        "backup.html",
        backups=backups,
        backup_source=str(BACKUP_SOURCE),
        backup_dest=str(BACKUP_DEST),
        backup_schedule=BACKUP_SCHEDULE,
    )


@app.route("/backup/run", methods=["POST"])
def backup_run():
    ok, message = _create_backup()
    flash(message)
    return redirect(url_for("backup"))


@app.route("/backup/view")
def backup_view():
    name = pathlib.Path(request.args.get("name", "")).name
    if not name:
        abort(400)
    target = BACKUP_DEST / name
    if not target.exists() or not target.is_dir():
        abort(404)
    files = _backup_files(target)
    for item in files:
        item["browse_path"] = _relative_to_base(item["path"])
    return render_template(
        "backup_files.html",
        backup_name=name,
        backup_path=str(target),
        files=files,
    )


@app.route("/backup/download")
def backup_download():
    name = pathlib.Path(request.args.get("name", "")).name
    if not name:
        abort(400)
    target = BACKUP_DEST / name
    if not target.exists() or not target.is_dir():
        abort(404)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, filenames in os.walk(target):
            for filename in filenames:
                path = pathlib.Path(root) / filename
                arcname = str(path.relative_to(target))
                zf.write(path, arcname=arcname)
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{name}.zip",
        mimetype="application/zip",
    )


@app.route("/download")
def download():
    rel_path = request.args.get("path", "")
    try:
        target = _safe_join(BASE_BROWSE_PATH, rel_path)
    except ValueError:
        abort(400)
    if not target.exists() or not target.is_file():
        abort(404)
    return send_file(target, as_attachment=True)


def _guess_mime(path: pathlib.Path) -> str:
    mime, _ = mimetypes.guess_type(str(path))
    if mime:
        return mime
    if path.suffix.lower() in {".log", ".txt", ".csv"}:
        return "text/plain"
    if path.suffix.lower() == ".svg":
        return "image/svg+xml"
    return "application/octet-stream"


@app.route("/view")
def view():
    rel_path = request.args.get("path", "")
    try:
        target = _safe_join(BASE_BROWSE_PATH, rel_path)
    except ValueError:
        abort(400)
    if not target.exists() or not target.is_file():
        abort(404)
    return send_file(
        target,
        mimetype=_guess_mime(target),
        as_attachment=False,
        download_name=target.name,
    )


@app.route("/upload", methods=["POST"])
def upload():
    rel_path = request.form.get("path", "")
    try:
        target_dir = _safe_join(BASE_BROWSE_PATH, rel_path)
    except ValueError:
        abort(400)

    if not target_dir.exists() or not target_dir.is_dir():
        abort(404)

    files = request.files.getlist("files")
    if not files:
        single = request.files.get("file")
        if single:
            files = [single]
    if not files:
        abort(400)

    saved = False
    for file in files:
        if not file or not file.filename:
            continue
        filename = pathlib.Path(file.filename).name
        dest = target_dir / filename
        file.save(dest)
        saved = True

    if not saved:
        abort(400)

    return redirect(url_for("browse", path=rel_path))


@app.route("/delete", methods=["POST"])
def delete():
    rel_path = request.form.get("path", "")
    if not rel_path:
        abort(400)
    try:
        target = _safe_join(BASE_BROWSE_PATH, rel_path)
    except ValueError:
        abort(400)

    if not target.exists():
        abort(404)

    parent = str(target.parent.relative_to(BASE_BROWSE_PATH))
    if target.is_file():
        target.unlink()
        flash("Arquivo removido.")
    elif target.is_dir():
        try:
            target.rmdir()
            flash("Pasta removida.")
        except OSError:
            flash("A pasta não está vazia.")
    else:
        abort(400)

    return redirect(url_for("browse", path=parent))


@app.route("/download-multi", methods=["POST"])
def download_multi():
    rel_path = request.form.get("path", "")
    names = request.form.getlist("files")
    try:
        target_dir = _safe_join(BASE_BROWSE_PATH, rel_path)
    except ValueError:
        abort(400)
    if not target_dir.exists() or not target_dir.is_dir():
        abort(404)
    if not names:
        abort(400)

    normalized: List[pathlib.Path] = []
    for name in names:
        filename = pathlib.Path(name).name
        if not filename:
            continue
        candidate = target_dir / filename
        if candidate.exists() and candidate.is_file():
            normalized.append(candidate)

    if not normalized:
        abort(404)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in normalized:
            zf.write(path, arcname=path.name)
    buffer.seek(0)

    zip_name = "arquivos.zip"
    if rel_path:
        zip_name = f"{pathlib.Path(rel_path).name or 'arquivos'}.zip"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=zip_name,
        mimetype="application/zip",
    )


@app.route("/api/exists")
def api_exists():
    rel_path = request.args.get("path", "")
    name = request.args.get("name", "")
    try:
        target_dir = _safe_join(BASE_BROWSE_PATH, rel_path)
    except ValueError:
        abort(400)
    if not target_dir.exists() or not target_dir.is_dir():
        abort(404)
    filename = pathlib.Path(name).name
    dest = target_dir / filename
    return jsonify({"exists": dest.exists(), "is_file": dest.is_file()})


def _is_csv(path: pathlib.Path) -> bool:
    return path.suffix.lower() == ".csv"


def _load_csv(path: pathlib.Path) -> Tuple[List[str], List[List[str]]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        sample = f.read(2048)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample)
        except Exception:
            dialect = csv.excel
        reader = csv.reader(f, dialect)
        rows = list(reader)
    if not rows:
        return [], []
    header = rows[0]
    data = rows[1:]
    return header, data


def _save_csv(path: pathlib.Path, header: List[str], data: List[List[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if header:
            writer.writerow(header)
        writer.writerows(data)


@app.route("/csv", methods=["GET", "POST"])
def csv_edit():
    rel_path = request.values.get("path", "")
    try:
        target = _safe_join(BASE_BROWSE_PATH, rel_path)
    except ValueError:
        abort(400)
    if not target.exists() or not target.is_file() or not _is_csv(target):
        abort(404)

    if request.method == "POST":
        rows_raw = request.form.get("rows", "")
        header_raw = request.form.get("header", "")
        header = [c.strip() for c in header_raw.split(",")] if header_raw else []
        data: List[List[str]] = []
        for line in rows_raw.splitlines():
            data.append([c.strip() for c in line.split(",")])
        _save_csv(target, header, data)
        return redirect(url_for("csv_edit", path=rel_path))

    header, data = _load_csv(target)
    return render_template(
        "csv_edit.html",
        rel_path=rel_path,
        header=header,
        data=data,
    )


@app.route("/service/stop", methods=["POST"])
def service_stop():
    if not psutil:
        abort(503)
    procs = _service_processes()
    if not procs:
        return jsonify({"stopped": True, "message": "Service not running", "count": 0})
    alive = []
    for p in procs:
        try:
            proc = psutil.Process(p["pid"])
            proc.terminate()
            alive.append(proc)
        except Exception:
            continue
    if alive:
        _, still_alive = psutil.wait_procs(alive, timeout=3)
        for proc in still_alive:
            try:
                proc.kill()
            except Exception:
                pass
    return jsonify({"stopped": True, "count": len(procs), "message": "Stopped"})


@app.route("/service/start", methods=["POST"])
def service_start():
    # Start via sudo as service user; only if not already running.
    if _service_processes():
        return jsonify({"started": False, "message": "Service already running"})
    code, out = _run_as_service_user(["bash", "-lc", SERVICE_START_CMD], cwd=SERVICE_WORKDIR)
    return jsonify({"started": code == 0, "output": out, "code": code})


@app.route("/service/restart", methods=["POST"])
def service_restart():
    # Stop then start
    _ = service_stop()
    code, out = _run_as_service_user(["bash", "-lc", SERVICE_START_CMD], cwd=SERVICE_WORKDIR)
    return jsonify({"restarted": code == 0, "output": out, "code": code})


@app.route("/deploy/pull", methods=["POST"])
def deploy_pull():
    # Run atualizar.sh as service user
    code, out = _run_as_service_user(["bash", "-lc", GIT_PULL_SCRIPT], cwd=GIT_PULL_DIR)
    return jsonify({"ok": code == 0, "output": out, "code": code})


@app.route("/processes")
def processes():
    if not psutil:
        abort(503)
    procs = []
    for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_info"]):
        info = proc.info
        procs.append(
            {
                "pid": info.get("pid"),
                "name": info.get("name"),
                "cpu": info.get("cpu_percent"),
                "mem": info.get("memory_info").rss if info.get("memory_info") else 0,
            }
        )
    procs.sort(key=lambda p: (p["cpu"] or 0, p["mem"] or 0), reverse=True)
    return render_template("processes.html", procs=procs[:50])


@app.route("/services")
def services():
    items = _list_services()
    return render_template("services.html", services=items)


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
