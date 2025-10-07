import os
import re
from io import BytesIO

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename
import pyzipper


app = Flask(__name__)

# Limit uploads to ~512 MB per request to guard against accidental huge uploads.
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024


@app.route("/")
def index():
    return render_template("index.html")


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


@app.route("/zip", methods=["POST"])
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

    try:
        zip_stream = _build_encrypted_zip(files, password)
    except Exception as exc:  # pragma: no cover - defensive logging
        app.logger.exception("ZIP creation failed: %s", exc)
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
