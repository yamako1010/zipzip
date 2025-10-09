import hashlib
import os
import re
import secrets
from io import BytesIO
from typing import List

from flask import Flask, jsonify, make_response, render_template, request, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf
from werkzeug.utils import secure_filename
import pyzipper


app = Flask(__name__)

force_https = os.environ.get("FORCE_HTTPS", "1").lower() not in {"0", "false", "no"}

# Limit uploads to ~512 MB per request to guard against accidental huge uploads.
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY") or secrets.token_urlsafe(32)
app.config["SESSION_COOKIE_SECURE"] = force_https
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config.setdefault("WTF_CSRF_TIME_LIMIT", None)


csrf = CSRFProtect(app)


Talisman(
    app,
    force_https=force_https,
    strict_transport_security=force_https,
    strict_transport_security_max_age=31536000,
    content_security_policy=None,
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.environ.get("RATE_LIMIT_STORAGE_URI", "memory://"),
)

ZIP_RATE_LIMIT = os.environ.get("ZIP_RATE_LIMIT", "30 per minute")


def _fingerprint(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:12]}"


def _summarize_files(file_storages) -> List[str]:
    hashed_names = []
    for storage in file_storages:
        filename = storage.filename or ""
        if not filename:
            continue
        hashed_names.append(_fingerprint(filename))
    return hashed_names


@app.route("/")
def index():
    csrf_token = generate_csrf()
    response = make_response(render_template("index.html", csrf_token=csrf_token))
    response.headers.setdefault("Cache-Control", "no-store")
    return response


def _build_encrypted_zip(file_storages, password: str) -> BytesIO:
    """
    Build an in-memory AES-256 encrypted ZIP archive from the uploaded files.
    """
    zip_buffer = BytesIO()
    with pyzipper.AESZipFile(
        zip_buffer,
        mode="w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zip_file:
        zip_file.setpassword(password.encode("utf-8"))
        zip_file.setencryption(pyzipper.WZ_AES, nbits=256)

        for storage in file_storages:
            filename = secure_filename(storage.filename or "")
            if not filename:
                continue

            storage.stream.seek(0)
            data = storage.read()
            zip_file.writestr(filename, data)

    zip_buffer.seek(0)
    return zip_buffer


def _limit_decorator():
    if ZIP_RATE_LIMIT:
        return limiter.limit(ZIP_RATE_LIMIT)

    def _identity(func):
        return func

    return _identity


@app.route("/zip", methods=["POST"])
@_limit_decorator()
def create_zip():
    files = request.files.getlist("files")
    password = request.form.get("password", "").strip()
    raw_zip_name = request.form.get("zipname", "").strip()

    if not files or all(not f.filename for f in files):
        return jsonify({"success": False, "message": "少なくとも1つのファイルを選択してください。"}), 400

    if not password:
        return jsonify({"success": False, "message": "パスワードを入力してください。"}), 400

    base_candidate = os.path.basename(raw_zip_name)
    base_candidate = base_candidate.strip().replace("\x00", "") if base_candidate else ""
    if base_candidate.lower().endswith(".zip"):
        base_candidate = base_candidate[:-4]
    safe_base = re.sub(r'[<>:"\\|?*]', "_", base_candidate).strip().strip(".")
    if not safe_base:
        safe_base = "MonoZip_Output"
    download_name = f"{safe_base[:120]}.zip"

    sanitized_files = _summarize_files(files)
    file_count = len([f for f in files if f.filename])

    try:
        zip_stream = _build_encrypted_zip(files, password)
        app.logger.info(
            "zip_created",
            extra={
                "file_fingerprints": sanitized_files,
                "password_fingerprint": _fingerprint(password),
                "file_count": file_count,
                "client_ip": request.remote_addr,
            },
        )
    except Exception as exc:  # pragma: no cover - defensive logging
        app.logger.exception(
            "zip_failed (%s)",
            exc.__class__.__name__,
            extra={
                "file_fingerprints": sanitized_files,
                "file_count": file_count,
                "client_ip": request.remote_addr,
            },
        )
        return (
            jsonify(
                {
                    "success": False,
                    "message": "ZIPファイルの生成に失敗しました。もう一度お試しください。",
                }
            ),
            500,
        )

    return send_file(
        zip_stream,
        mimetype="application/zip",
        as_attachment=True,
        download_name=download_name,
        max_age=0,
    )


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    return (
        jsonify(
            {
                "success": False,
                "message": "セッションが期限切れです。ページを再読み込みして再試行してください。",
            }
        ),
        400,
    )


@app.errorhandler(429)
def handle_rate_limit(error):
    return (
        jsonify(
            {
                "success": False,
                "message": "リクエストが多すぎます。しばらく時間をおいてから再試行してください。",
            }
        ),
        429,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
