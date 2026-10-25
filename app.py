
from __future__ import annotations

import base64
import binascii
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=12 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get(
        "COOKIE_SECURE", "0"
    ).strip().lower() in {"1", "true", "yes", "on"},
)

app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Set DATABASE_PATH to a persistent disk location in production.
_raw_db_path = os.environ.get(
    "DATABASE_PATH", str(BASE_DIR / "campus_voice.db")
).strip()

if _raw_db_path == ":memory:":
    DATABASE_PATH = _raw_db_path
else:
    _db_path = Path(_raw_db_path).expanduser()
    if not _db_path.is_absolute():
        _db_path = BASE_DIR / _db_path
    DATABASE_PATH = str(_db_path.resolve())
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)

ALLOWED_AUDIO_EXTENSIONS = {
    ".mp3", ".wav", ".ogg", ".oga", ".m4a",
    ".aac", ".webm", ".mp4", ".3gp",
}
MAX_AUDIO_BYTES = 10 * 1024 * 1024

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "meru123").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "merupoly123@")


# ============================================================
# DATABASE HELPERS
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def json_error(message: str, status: int = 400):
    return jsonify({
        "success": False,
        "error": message,
        "message": message,
    }), status


def request_data() -> dict[str, Any]:
    if request.is_json:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}
    return request.form.to_dict()


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            if request.path.startswith("/api/"):
                return json_error(
                    "Please log in as an administrator.", 401
                )
            return redirect(url_for("admin_login"))
        return function(*args, **kwargs)
    return wrapper


def get_audio_upload():
    for field in ("audio", "voice", "audio_file", "voice_note"):
        uploaded = request.files.get(field)
        if uploaded and uploaded.filename:
            return uploaded
    return None


def decode_audio_data(value: str) -> tuple[str, str] | None:
    if not value or not isinstance(value, str):
        return None

    match = re.fullmatch(
        r"data:([^;,]+);base64,(.+)",
        value.strip(),
        flags=re.DOTALL,
    )
    if not match:
        return None

    mime_type = match.group(1).strip().lower()
    encoded = re.sub(r"\s+", "", match.group(2))

    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None

    if not decoded or len(decoded) > MAX_AUDIO_BYTES:
        return None

    return base64.b64encode(decoded).decode("ascii"), mime_type


def normalise_status(value: str | None) -> str:
    allowed = {
        "new": "New",
        "pending": "Pending",
        "reviewed": "Reviewed",
        "in progress": "In Progress",
        "in_progress": "In Progress",
        "resolved": "Resolved",
        "closed": "Closed",
    }
    return allowed.get((value or "New").strip().lower(), "New")


def submission_public_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["type"] = item.get("message_type", "Text")
    item["review_note"] = item.get("review_note") or ""
    item["has_audio"] = bool(item.get("audio_base64"))
    item.pop("audio_base64", None)
    return item


def response_public_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    published = bool(item.get("published", 0))
    item["published"] = published
    item["is_published"] = published
    return item


# ============================================================
# DATABASE INITIALISATION AND MIGRATIONS
# ============================================================

def init_db() -> None:
    connection = get_db()
    try:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_type TEXT NOT NULL DEFAULT 'Text',
                category TEXT NOT NULL DEFAULT 'General',
                body TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                audio_base64 TEXT,
                audio_mime TEXT,
                audio_filename TEXT,
                status TEXT NOT NULL DEFAULT 'New',
                review_note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL DEFAULT 'Campus Voice Feedback',
                category TEXT NOT NULL DEFAULT 'General',
                body TEXT NOT NULL,
                published INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                admin_id INTEGER,
                FOREIGN KEY (admin_id)
                    REFERENCES admins(id) ON DELETE SET NULL
            );
        """)

        migrations = {
            "admins": {
                "password_hash": "TEXT NOT NULL DEFAULT ''",
                "created_at": "TEXT NOT NULL DEFAULT ''",
            },
            "submissions": {
                "message_type": "TEXT NOT NULL DEFAULT 'Text'",
                "category": "TEXT NOT NULL DEFAULT 'General'",
                "body": "TEXT NOT NULL DEFAULT ''",
                "details": "TEXT NOT NULL DEFAULT ''",
                "audio_base64": "TEXT",
                "audio_mime": "TEXT",
                "audio_filename": "TEXT",
                "status": "TEXT NOT NULL DEFAULT 'New'",
                "review_note": "TEXT NOT NULL DEFAULT ''",
                "created_at": "TEXT NOT NULL DEFAULT ''",
                "updated_at": "TEXT NOT NULL DEFAULT ''",
            },
            "responses": {
                "title": "TEXT NOT NULL DEFAULT 'Campus Voice Feedback'",
                "category": "TEXT NOT NULL DEFAULT 'General'",
                "body": "TEXT NOT NULL DEFAULT ''",
                "published": "INTEGER NOT NULL DEFAULT 1",
                "created_at": "TEXT NOT NULL DEFAULT ''",
                "updated_at": "TEXT NOT NULL DEFAULT ''",
                "admin_id": "INTEGER",
            },
        }

        for table, columns in migrations.items():
            existing = {
                row["name"]
                for row in connection.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }
            for column, definition in columns.items():
                if column not in existing:
                    connection.execute(
                        f"ALTER TABLE {table} ADD COLUMN "
                        f"{column} {definition}"
                    )

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_submissions_created_at
            ON submissions(created_at)
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_submissions_status
            ON submissions(status)
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_responses_published
            ON responses(published)
        """)
        connection.commit()
    finally:
        connection.close()


def ensure_default_admin() -> None:
    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        app.logger.error("ADMIN_USERNAME or ADMIN_PASSWORD is missing.")
        return

    connection = get_db()
    try:
        existing = connection.execute(
            "SELECT id FROM admins WHERE username = ?",
            (ADMIN_USERNAME,),
        ).fetchone()

        password_hash = generate_password_hash(ADMIN_PASSWORD)

        if existing:
            connection.execute(
                "UPDATE admins SET password_hash = ? WHERE id = ?",
                (password_hash, existing["id"]),
            )
        else:
            connection.execute(
                """
                INSERT INTO admins (username, password_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (ADMIN_USERNAME, password_hash, utc_now()),
            )
        connection.commit()
    finally:
        connection.close()


init_db()
ensure_default_admin()


# ============================================================
# PUBLIC PAGES AND DIAGNOSTICS
# ============================================================

@app.route("/")
@app.route("/home")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    connection = None
    try:
        connection = get_db()
        connection.execute("SELECT 1").fetchone()
        return jsonify({
            "status": "ok",
            "service": "Campus Voice",
            "database": "connected",
        })
    except sqlite3.Error:
        app.logger.exception("Database health check failed")
        return jsonify({
            "status": "error",
            "service": "Campus Voice",
            "database": "unavailable",
        }), 503
    finally:
        if connection:
            connection.close()


# Admin-only diagnostic: confirms which database the app is using.
@app.route("/api/admin/diagnostics", methods=["GET"])
@admin_required
def admin_diagnostics():
    connection = get_db()
    try:
        submissions = connection.execute(
            "SELECT COUNT(*) AS total FROM submissions"
        ).fetchone()["total"]
        responses = connection.execute(
            "SELECT COUNT(*) AS total FROM responses"
        ).fetchone()["total"]
        admins = connection.execute(
            "SELECT COUNT(*) AS total FROM admins"
        ).fetchone()["total"]

        return jsonify({
            "success": True,
            "database_configured": True,
            "database_path": DATABASE_PATH,
            "submissions_count": submissions,
            "responses_count": responses,
            "admins_count": admins,
        })
    finally:
        connection.close()


# ============================================================
# PUBLIC SUBMISSIONS
# ============================================================

@app.route("/api/submissions", methods=["POST"])
@app.route("/api/feedback", methods=["POST"])
def create_submission():
    data = request_data()

    raw_type = str(
        data.get("type")
        or data.get("message_type")
        or data.get("messageType")
        or ""
    ).strip().lower()

    category = str(data.get("category") or "General").strip()[:100]
    body = str(
        data.get("body") or data.get("message")
        or data.get("text") or ""
    ).strip()
    details = str(
        data.get("details") or data.get("description") or ""
    ).strip()

    if len(body) > 20000 or len(details) > 20000:
        return json_error("Your message is too long.")

    uploaded_audio = get_audio_upload()
    audio_base64 = None
    audio_mime = None
    audio_filename = None

    if uploaded_audio:
        filename = secure_filename(uploaded_audio.filename or "")
        extension = Path(filename).suffix.lower()

        if not extension or extension not in ALLOWED_AUDIO_EXTENSIONS:
            return json_error("Unsupported audio file type.")

        audio_bytes = uploaded_audio.read(MAX_AUDIO_BYTES + 1)
        if len(audio_bytes) > MAX_AUDIO_BYTES:
            return json_error("The voice note must not exceed 10 MB.")

        if audio_bytes:
            audio_base64 = base64.b64encode(
                audio_bytes
            ).decode("ascii")
            audio_mime = (
                uploaded_audio.mimetype or "application/octet-stream"
            )
            audio_filename = filename or "voice-note"

    else:
        audio_value = (
            data.get("audio") or data.get("voice")
            or data.get("audio_data") or data.get("audio_base64") or ""
        )
        decoded = decode_audio_data(str(audio_value))
        if decoded:
            audio_base64, audio_mime = decoded
            audio_filename = "voice-note"
        elif isinstance(audio_value, str) and audio_value.startswith("data:"):
            return json_error("The supplied voice note is invalid or too large.")

    is_voice = (
        "voice" in raw_type or "audio" in raw_type or bool(audio_base64)
    )
    message_type = "Voice note" if is_voice else "Text"

    if message_type == "Text" and not body and not details:
        return json_error("Please enter a message before submitting.")

    if message_type == "Voice note" and not audio_base64 and not body and not details:
        return json_error("Please record or upload a voice note.")

    timestamp = utc_now()
    connection = get_db()
    try:
        cursor = connection.execute(
            """
            INSERT INTO submissions (
                message_type, category, body, details,
                audio_base64, audio_mime, audio_filename,
                status, review_note, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'New', '', ?, ?)
            """,
            (
                message_type, category or "General", body, details,
                audio_base64, audio_mime, audio_filename,
                timestamp, timestamp,
            ),
        )
        submission_id = cursor.lastrowid
        connection.commit()

        # Verify the row is readable before returning success.
        saved = connection.execute(
            "SELECT id FROM submissions WHERE id = ?",
            (submission_id,),
        ).fetchone()
        if saved is None:
            raise sqlite3.DatabaseError("Inserted submission was not found.")

    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("Could not save submission")
        return json_error(
            "Your message could not be saved. Please try again.", 500
        )
    finally:
        connection.close()

    return jsonify({
        "success": True,
        "message": "Your message has been submitted successfully.",
        "submission_id": submission_id,
        "id": submission_id,
        "type": message_type,
        "status": "New",
    }), 201


# ============================================================
# PUBLIC ADMIN REPLIES
# ============================================================

@app.route("/api/responses", methods=["GET"])
@app.route("/api/feedback/responses", methods=["GET"])
def get_public_responses():
    connection = get_db()
    try:
        rows = connection.execute(
            """
            SELECT id, title, category, body, published,
                   created_at, updated_at
            FROM responses
            WHERE published = 1
            ORDER BY created_at DESC, id DESC
            """
        ).fetchall()
        responses = [response_public_dict(row) for row in rows]
    finally:
        connection.close()

    return jsonify({
        "success": True,
        "responses": responses,
        "feedback": responses,
        "data": responses,
    })


# ============================================================
# ADMIN LOGIN AND LOGOUT
# ============================================================

@app.route("/admin", methods=["GET", "POST"])
@app.route("/admin/login", methods=["GET", "POST"])
@app.route("/admin_login", methods=["GET", "POST"])
@app.route("/admin_login.html", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        if session.get("admin_id"):
            return redirect(url_for("admin_dashboard"))
        return render_template("admin_login.html")

    data = request_data()
    username = str(
        data.get("username") or data.get("admin_username") or ""
    ).strip()
    password = str(
        data.get("password") or data.get("admin_password") or ""
    )

    if not username or not password:
        message = "Enter both username and password."
        if request.is_json:
            return json_error(message)
        return render_template("admin_login.html", error=message), 400

    connection = get_db()
    try:
        admin = connection.execute(
            "SELECT * FROM admins WHERE username = ?", (username,)
        ).fetchone()
    finally:
        connection.close()

    if not admin or not check_password_hash(admin["password_hash"], password):
        message = "Invalid administrator username or password."
        if request.is_json:
            return json_error(message, 401)
        return render_template("admin_login.html", error=message), 401

    session.clear()
    session["admin_id"] = admin["id"]
    session["admin_username"] = admin["username"]

    if request.is_json:
        return jsonify({
            "success": True,
            "message": "Login successful.",
            "redirect": url_for("admin_dashboard"),
        })
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/logout", methods=["GET", "POST"])
@app.route("/admin_logout", methods=["GET", "POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin/dashboard")
@app.route("/admin_dashboard")
@app.route("/admin_dashboard.html")
@admin_required
def admin_dashboard():
    connection = get_db()
    try:
        total_submissions = connection.execute(
            "SELECT COUNT(*) AS total FROM submissions"
        ).fetchone()["total"]

        new_submissions = connection.execute(
            """
            SELECT COUNT(*) AS total FROM submissions
            WHERE LOWER(status) IN ('new', 'pending')
            """
        ).fetchone()["total"]

        total_responses = connection.execute(
            "SELECT COUNT(*) AS total FROM responses"
        ).fetchone()["total"]

        published_responses = connection.execute(
            "SELECT COUNT(*) AS total FROM responses WHERE published = 1"
        ).fetchone()["total"]

        recent_submissions = [
            dict(row) for row in connection.execute(
                """
                SELECT id, message_type, category, body, details,
                       audio_mime, audio_filename, status, review_note,
                       created_at, updated_at,
                       CASE WHEN audio_base64 IS NOT NULL
                            AND audio_base64 != ''
                            THEN 1 ELSE 0 END AS has_audio
                FROM submissions
                ORDER BY created_at DESC, id DESC
                LIMIT 10
                """
            ).fetchall()
        ]
    finally:
        connection.close()

    return render_template(
        "admin_dashboard.html",
        admin_username=session.get("admin_username", "Administrator"),
        total_submissions=total_submissions,
        new_submissions=new_submissions,
        total_responses=total_responses,
        published_responses=published_responses,
        recent_submissions=recent_submissions,
    )


# ============================================================
# ADMIN SUBMISSION MANAGEMENT
# ============================================================

@app.route("/api/admin/submissions", methods=["GET"])
@admin_required
def admin_get_submissions():
    status_filter = request.args.get("status", "").strip()
    category_filter = request.args.get("category", "").strip()
    search_term = request.args.get("search", "").strip()

    query = """
        SELECT id, message_type, category, body, details,
               audio_base64, audio_mime, audio_filename,
               status, review_note, created_at, updated_at
        FROM submissions WHERE 1 = 1
    """
    parameters: list[Any] = []

    if status_filter:
        query += " AND LOWER(status) = LOWER(?)"
        parameters.append(status_filter)

    if category_filter:
        query += " AND category = ?"
        parameters.append(category_filter)

    if search_term:
        query += """
            AND (body LIKE ? OR details LIKE ? OR category LIKE ?
                 OR CAST(id AS TEXT) LIKE ?)
        """
        pattern = f"%{search_term}%"
        parameters.extend([pattern] * 4)

    query += " ORDER BY created_at DESC, id DESC"

    connection = get_db()
    try:
        rows = connection.execute(query, parameters).fetchall()
        submissions = [submission_public_dict(row) for row in rows]
    finally:
        connection.close()

    return jsonify({
        "success": True,
        "submissions": submissions,
        "messages": submissions,
        "data": submissions,
        "count": len(submissions),
    })


@app.route("/api/admin/submissions/<int:submission_id>", methods=["GET"])
@admin_required
def admin_get_submission(submission_id: int):
    connection = get_db()
    try:
        row = connection.execute(
            """
            SELECT id, message_type, category, body, details,
                   audio_base64, audio_mime, audio_filename,
                   status, review_note, created_at, updated_at
            FROM submissions WHERE id = ?
            """,
            (submission_id,),
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        return json_error("Submission not found.", 404)

    item = submission_public_dict(row)
    return jsonify({"success": True, "submission": item, "data": item})


@app.route(
    "/api/admin/submissions/<int:submission_id>/audio",
    methods=["GET"],
)
@admin_required
def admin_get_submission_audio(submission_id: int):
    connection = get_db()
    try:
        row = connection.execute(
            """
            SELECT audio_base64, audio_mime, audio_filename
            FROM submissions WHERE id = ?
            """,
            (submission_id,),
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        return json_error("Submission not found.", 404)
    if not row["audio_base64"]:
        return json_error("This submission does not contain a voice note.", 404)

    mime_type = row["audio_mime"] or "audio/webm"
    data_url = f"data:{mime_type};base64,{row['audio_base64']}"

    return jsonify({
        "success": True,
        "audio": data_url,
        "audio_url": data_url,
        "mime_type": mime_type,
        "filename": row["audio_filename"] or "voice-note",
    })


@app.route(
    "/api/admin/submissions/<int:submission_id>",
    methods=["PATCH", "PUT"],
)
@app.route(
    "/api/admin/submissions/<int:submission_id>/review",
    methods=["PATCH", "POST"],
)
@app.route(
    "/api/admin/submissions/<int:submission_id>/status",
    methods=["PATCH", "POST"],
)
@admin_required
def admin_update_submission(submission_id: int):
    data = request_data()
    status_value = data.get("status")
    review_note = data.get("review_note", data.get("reviewNote"))

    connection = get_db()
    try:
        existing = connection.execute(
            "SELECT * FROM submissions WHERE id = ?", (submission_id,)
        ).fetchone()

        if existing is None:
            return json_error("Submission not found.", 404)

        new_status = (
            normalise_status(str(status_value))
            if status_value is not None else existing["status"]
        )
        new_review_note = (
            str(review_note).strip()[:5000]
            if review_note is not None else existing["review_note"]
        )

        connection.execute(
            """
            UPDATE submissions SET status = ?, review_note = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_status, new_review_note, utc_now(), submission_id),
        )
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("Could not update submission")
        return json_error("Could not update the submission.", 500)
    finally:
        connection.close()

    return jsonify({
        "success": True,
        "message": "Submission updated successfully.",
        "id": submission_id,
        "status": new_status,
        "review_note": new_review_note,
    })


# ============================================================
# ADMIN RESPONSE / FEEDBACK MANAGEMENT
# ============================================================

@app.route("/api/admin/responses", methods=["GET"])
@admin_required
def admin_get_responses():
    connection = get_db()
    try:
        rows = connection.execute(
            """
            SELECT id, title, category, body, published,
                   created_at, updated_at, admin_id
            FROM responses ORDER BY created_at DESC, id DESC
            """
        ).fetchall()
        responses = [response_public_dict(row) for row in rows]
    finally:
        connection.close()

    return jsonify({
        "success": True,
        "responses": responses,
        "feedback": responses,
        "data": responses,
    })


@app.route("/api/admin/responses", methods=["POST"])
@admin_required
def admin_create_response():
    data = request_data()
    title = str(data.get("title") or "Campus Voice Feedback").strip()[:200]
    category = str(data.get("category") or "General").strip()[:100]
    body = str(
        data.get("body") or data.get("message")
        or data.get("response") or ""
    ).strip()

    if not body:
        return json_error("Please enter the feedback or response message.")
    if len(body) > 20000:
        return json_error("The response is too long.")

    published_value = data.get(
        "published", data.get("is_published", True)
    )
    if isinstance(published_value, str):
        published = published_value.strip().lower() in {
            "1", "true", "yes", "on", "published"
        }
    else:
        published = bool(published_value)

    timestamp = utc_now()
    connection = get_db()
    try:
        cursor = connection.execute(
            """
            INSERT INTO responses (
                title, category, body, published,
                created_at, updated_at, admin_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title or "Campus Voice Feedback",
                category or "General",
                body,
                int(published),
                timestamp,
                timestamp,
                session.get("admin_id"),
            ),
        )
        response_id = cursor.lastrowid
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("Could not save admin response")
        return json_error("Could not save the response.", 500)
    finally:
        connection.close()

    return jsonify({
        "success": True,
        "message": "Feedback response saved successfully.",
        "id": response_id,
        "response_id": response_id,
        "published": published,
    }), 201


@app.route(
    "/api/admin/responses/<int:response_id>",
    methods=["PATCH", "PUT"],
)
@app.route(
    "/api/admin/responses/<int:response_id>/publish",
    methods=["PATCH", "POST"],
)
@admin_required
def admin_update_response(response_id: int):
    data = request_data()
    connection = get_db()
    try:
        existing = connection.execute(
            "SELECT * FROM responses WHERE id = ?", (response_id,)
        ).fetchone()

        if existing is None:
            return json_error("Response not found.", 404)

        title = str(data.get("title", existing["title"])).strip()[:200]
        category = str(data.get("category", existing["category"])).strip()[:100]
        body = str(data.get("body", existing["body"])).strip()

        published = int(existing["published"])
        if "published" in data or "is_published" in data:
            value = data.get("published", data.get("is_published"))
            if isinstance(value, str):
                published = int(value.strip().lower() in {
                    "1", "true", "yes", "on", "published"
                })
            else:
                published = int(bool(value))

        if not body:
            return json_error("The response message cannot be empty.")
        if len(body) > 20000:
            return json_error("The response is too long.")

        connection.execute(
            """
            UPDATE responses
            SET title = ?, category = ?, body = ?,
                published = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                title or "Campus Voice Feedback",
                category or "General",
                body,
                published,
                utc_now(),
                response_id,
            ),
        )
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("Could not update response")
        return json_error("Could not update the response.", 500)
    finally:
        connection.close()

    return jsonify({
        "success": True,
        "message": "Response updated successfully.",
        "id": response_id,
        "published": bool(published),
    })


@app.route(
    "/api/admin/responses/<int:response_id>",
    methods=["DELETE"],
)
@admin_required
def admin_delete_response(response_id: int):
    connection = get_db()
    try:
        cursor = connection.execute(
            "DELETE FROM responses WHERE id = ?", (response_id,)
        )
        connection.commit()
        if cursor.rowcount == 0:
            return json_error("Response not found.", 404)
    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("Could not delete response")
        return json_error("Could not delete the response.", 500)
    finally:
        connection.close()

    return jsonify({
        "success": True,
        "message": "Response deleted successfully.",
        "id": response_id,
    })


# ============================================================
# FLASK COMMANDS
# ============================================================

@app.cli.command("init-db")
def init_db_command():
    init_db()
    print(f"Campus Voice database initialised: {DATABASE_PATH}")


@app.cli.command("create-admin")
def create_admin_command():
    init_db()
    ensure_default_admin()
    print("Administrator setup checked.")


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):
    if request.path.startswith("/api/"):
        return json_error("The requested API endpoint was not found.", 404)
    return "Page not found.", 404


@app.errorhandler(413)
def request_too_large(error):
    message = "The uploaded file is too large. Maximum request size is 12 MB."
    if request.path.startswith("/api/"):
        return json_error(message, 413)
    return message, 413


@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error("Unexpected server error: %s", error)
    if request.path.startswith("/api/"):
        return json_error("An internal server error occurred.", 500)
    return "An internal server error occurred. Please try again later.", 500


# ============================================================
# LOCAL DEVELOPMENT ENTRY POINT
# ============================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in {
        "1", "true", "yes"
    }
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
