
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
    Flask, flash, jsonify, redirect, render_template,
    request, session, url_for, current_app
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "campus_voice.db"

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    DATABASE_PATH=os.environ.get("DATABASE_PATH", str(DEFAULT_DB)),
    MAX_CONTENT_LENGTH=12 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    JSON_SORT_KEYS=False,
)


# ----------------------------- DATABASE -------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    db_path = Path(current_app.config["DATABASE_PATH"])
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path), timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reference TEXT NOT NULL UNIQUE,
                message_type TEXT NOT NULL
                    CHECK(message_type IN ('Text', 'Voice note')),
                category TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                audio_base64 TEXT,
                audio_mime TEXT,
                status TEXT NOT NULL DEFAULT 'Pending'
                    CHECK(status IN ('Pending', 'Approved', 'Rejected')),
                review_note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                body TEXT NOT NULL,
                published INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                admin_id INTEGER,
                FOREIGN KEY(admin_id) REFERENCES admins(id)
                    ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_submissions_created
                ON submissions(created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_submissions_status
                ON submissions(status);

            CREATE INDEX IF NOT EXISTS idx_responses_public
                ON responses(published, created_at DESC);
        """)


# -------------------------- ADMINISTRATOR SETUP ------------------------------

def ensure_default_admin() -> None:
    username = os.environ.get("ADMIN_USERNAME", "meru123").strip()
    password = os.environ.get("ADMIN_PASSWORD", "merupoly123@")

    if not username or not password:
        raise RuntimeError(
            "ADMIN_USERNAME and ADMIN_PASSWORD must not be empty."
        )

    with get_db() as db:
        existing = db.execute(
            "SELECT id FROM admins WHERE username = ?",
            (username,),
        ).fetchone()

        if existing is None:
            db.execute(
                """
                INSERT INTO admins (username, password_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (username, generate_password_hash(password), utc_now()),
            )
        elif os.environ.get("RESET_ADMIN_PASSWORD", "0") == "1":
            db.execute(
                """
                UPDATE admins SET password_hash = ?
                WHERE username = ?
                """,
                (generate_password_hash(password), username),
            )


with app.app_context():
    init_db()
    ensure_default_admin()


# -------------------------------- HELPERS ------------------------------------

def json_error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def read_json() -> dict[str, Any]:
    data = request.get_json(silent=True)

    if isinstance(data, dict):
        return data

    return {}


def read_submission_payload() -> dict[str, Any]:
    """Accept JSON and FormData submissions."""
    data = request.get_json(silent=True)

    if isinstance(data, dict):
        return data

    return request.form.to_dict(flat=True)


def first_value(
    data: dict[str, Any],
    *keys: str,
    default: Any = "",
) -> Any:
    for key in keys:
        value = data.get(key)

        if value is not None and str(value).strip():
            return value

    return default


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            if request.path.startswith("/api/"):
                return json_error(
                    "Administrator login required. Please log in again.",
                    401,
                )

            return redirect(
                url_for("admin_login", next=request.path)
            )

        return view(*args, **kwargs)

    return wrapped


def row_submission(
    row: sqlite3.Row,
    include_audio: bool = False,
) -> dict[str, Any]:
    result = {
        "id": row["reference"],
        "reference": row["reference"],
        "type": row["message_type"],
        "category": row["category"],
        "body": row["body"],
        "details": row["details"],
        "status": row["status"],
        "reviewNote": row["review_note"],
        "date": row["created_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "hasAudio": bool(row["audio_base64"]),
    }

    if include_audio and row["audio_base64"]:
        result["audio"] = (
            f"data:{row['audio_mime'] or 'audio/webm'};base64,"
            f"{row['audio_base64']}"
        )

    return result


def row_response(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "title": row["title"],
        "category": row["category"],
        "body": row["body"],
        "response": row["body"],
        "published": bool(row["published"]),
        "date": row["created_at"],
        "created_at": row["created_at"],
    }


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault(
        "Referrer-Policy", "strict-origin-when-cross-origin"
    )
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.errorhandler(413)
def too_large(_error):
    if request.path.startswith("/api/"):
        return json_error(
            "Upload is too large. Keep the request under 12 MB.",
            413,
        )

    return "Upload too large. Please use a smaller voice note.", 413


# -------------------------------- PAGES ---------------------------------------

@app.get("/")
@app.get("/index.html")
def home():
    return render_template("index.html")


# ----------------------------- ADMIN LOGIN -----------------------------------

@app.get("/admin")
@app.get("/admin/login")
@app.get("/admin_login")
@app.get("/admin_login.html")
def admin_login():
    if session.get("admin_id"):
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_login.html")


@app.post("/admin/login")
@app.post("/admin_login")
@app.post("/admin_login.html")
def admin_login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Enter both username and password.", "error")
        return render_template("admin_login.html"), 400

    with get_db() as db:
        admin = db.execute(
            """
            SELECT id, username, password_hash
            FROM admins
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

    valid_login = (
        admin is not None
        and check_password_hash(admin["password_hash"], password)
    )

    if not valid_login:
        flash(
            "Invalid administrator username or password.",
            "error",
        )
        return render_template("admin_login.html"), 401

    session.clear()
    session["admin_id"] = admin["id"]
    session["admin_username"] = admin["username"]

    target = request.args.get("next", "")

    if not target.startswith("/") or target.startswith("//"):
        target = url_for("admin_dashboard")

    return redirect(target)


@app.get("/admin/dashboard")
@app.get("/admin_dashboard")
@app.get("/admin_dashboard.html")
@admin_required
def admin_dashboard():
    return render_template(
        "admin_dashboard.html",
        admin_username=session.get("admin_username"),
    )


@app.route("/admin/logout", methods=["GET", "POST"])
@app.route("/admin_logout", methods=["GET", "POST"])
def admin_logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("admin_login"))


# ------------------------------ STUDENT APIs ---------------------------------

@app.post("/api/submissions")
@app.post("/api/feedback")
def create_submission():
    """Accept student messages sent as JSON or FormData."""
    data = read_submission_payload()

    category = str(first_value(
        data,
        "category",
        "message_category",
        "messageCategory",
    )).strip()[:100]

    body = str(first_value(
        data, "body", "message", "text"
    )).strip()

    details = str(first_value(
        data, "details", "description"
    )).strip()[:160]

    raw_type = str(first_value(
        data,
        "type",
        "messageType",
        "message_type",
        default="Text",
    )).strip().lower()

    is_voice = "voice" in raw_type or "audio" in raw_type
    message_type = "Voice note" if is_voice else "Text"

    audio_value = first_value(
        data, "audio", "audioData", "audio_data"
    )

    audio_b64 = None
    audio_mime = None

    if not category:
        return json_error("Please choose a message category.")

    if message_type == "Text" and not body:
        return json_error("Please enter your message.")

    if message_type == "Voice note":
        uploaded_audio = (
            request.files.get("audio")
            or request.files.get("voice")
            or request.files.get("audio_file")
            or request.files.get("voice_note")
        )

        audio_bytes = None

        if uploaded_audio and uploaded_audio.filename:
            audio_bytes = uploaded_audio.read()
            audio_mime = uploaded_audio.mimetype or "audio/webm"

        elif isinstance(audio_value, str) and audio_value.startswith("data:"):
            match = re.fullmatch(
                r"data:([a-zA-Z0-9.+/-]+);base64,([A-Za-z0-9+/=\r\n]+)",
                audio_value.strip(),
            )

            if not match:
                return json_error("The voice-note data is invalid.")

            audio_mime, encoded = match.groups()

            try:
                audio_bytes = base64.b64decode(
                    encoded, validate=True
                )
            except (ValueError, binascii.Error):
                return json_error(
                    "The voice-note data could not be decoded."
                )

        if not audio_bytes:
            return json_error(
                "Please record or upload a voice note."
            )

        if len(audio_bytes) > 3 * 1024 * 1024:
            return json_error(
                "Voice notes must be smaller than 3 MB."
            )

        audio_b64 = base64.b64encode(audio_bytes).decode("ascii")
        audio_mime = audio_mime or "audio/webm"

        body = (
            "Voice note submitted. "
            "Use the administrator dashboard to listen."
        )

    reference = "CV-" + secrets.token_hex(5).upper()
    timestamp = utc_now()

    try:
        with get_db() as db:
            db.execute(
                """
                INSERT INTO submissions (
                    reference, message_type, category, body, details,
                    audio_base64, audio_mime, status, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?)
                """,
                (
                    reference,
                    message_type,
                    category,
                    body,
                    details,
                    audio_b64,
                    audio_mime,
                    timestamp,
                    timestamp,
                ),
            )

    except sqlite3.Error:
        current_app.logger.exception(
            "Could not save student submission"
        )
        return json_error(
            "The submission could not be saved. Please try again.",
            500,
        )

    return jsonify({
        "ok": True,
        "message": "Your submission has been received.",
        "submission": {
            "id": reference,
            "reference": reference,
            "type": message_type,
            "category": category,
            "status": "Pending",
            "date": timestamp,
        },
    }), 201


@app.get("/api/responses")
def public_responses():
    with get_db() as db:
        rows = db.execute(
            """
            SELECT id, title, category, body, published, created_at
            FROM responses
            WHERE published = 1
            ORDER BY id DESC
            """
        ).fetchall()

    return jsonify({
        "ok": True,
        "responses": [row_response(row) for row in rows],
    })


# ------------------------- ADMINISTRATOR APIs -------------------------------

@app.get("/api/admin/submissions")
@admin_required
def admin_submissions():
    status = request.args.get("status", "").strip()

    query = "SELECT * FROM submissions"
    params: list[Any] = []

    if status and status.lower() != "all":
        if status not in {"Pending", "Approved", "Rejected"}:
            return json_error("Invalid status filter.")

        query += " WHERE status = ?"
        params.append(status)

    query += " ORDER BY id DESC"

    with get_db() as db:
        rows = db.execute(query, params).fetchall()

    return jsonify({
        "ok": True,
        "submissions": [row_submission(row) for row in rows],
    })


@app.get("/api/admin/submissions/<reference>")
@admin_required
def admin_submission_detail(reference: str):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM submissions WHERE reference = ?",
            (reference,),
        ).fetchone()

    if not row:
        return json_error("Submission not found.", 404)

    return jsonify({
        "ok": True,
        "submission": row_submission(row, include_audio=True),
    })


# FIXED REVIEW ENDPOINTS:
# Supports PATCH on the base URL and POST to both /review and /status.
@app.patch("/api/admin/submissions/<reference>")
@app.post("/api/admin/submissions/<reference>/review")
@app.post("/api/admin/submissions/<reference>/status")
@admin_required
def update_submission(reference: str):
    # Accept JSON and form-encoded requests from different dashboard versions.
    data = read_json()

    if not data and request.form:
        data = request.form.to_dict(flat=True)

    status = str(data.get("status", "")).strip()

    review_note = str(
        data.get(
            "reviewNote",
            data.get(
                "review_note",
                data.get("note", ""),
            ),
        )
    ).strip()[:2000]

    if status and status not in {
        "Pending",
        "Approved",
        "Rejected",
    }:
        return json_error("Invalid submission status.")

    try:
        with get_db() as db:
            row = db.execute(
                """
                SELECT reference
                FROM submissions
                WHERE reference = ?
                """,
                (reference,),
            ).fetchone()

            if row is None:
                return json_error("Submission not found.", 404)

            if status:
                db.execute(
                    """
                    UPDATE submissions
                    SET status = ?, review_note = ?, updated_at = ?
                    WHERE reference = ?
                    """,
                    (
                        status,
                        review_note,
                        utc_now(),
                        reference,
                    ),
                )
            else:
                # Save an internal review note without changing the status.
                db.execute(
                    """
                    UPDATE submissions
                    SET review_note = ?, updated_at = ?
                    WHERE reference = ?
                    """,
                    (
                        review_note,
                        utc_now(),
                        reference,
                    ),
                )

    except sqlite3.Error:
        current_app.logger.exception(
            "Could not update submission review"
        )
        return json_error(
            "Could not save the review. Please try again.",
            500,
        )

    return jsonify({
        "ok": True,
        "message": (
            f"Submission {status.lower()} successfully."
            if status
            else "Review note saved successfully."
        ),
        "reference": reference,
        "status": status or None,
    }), 200


@app.post("/api/admin/responses")
@admin_required
def create_response():
    data = read_json()

    title = str(data.get("title", "")).strip()[:100]
    category = str(data.get("category", "")).strip()[:100]
    body = str(
        data.get("body", data.get("response", ""))
    ).strip()[:2500]

    published = data.get("published", True)

    if not isinstance(published, bool):
        published = True

    if not title or not category or not body:
        return json_error(
            "Title, category and response text are required."
        )

    with get_db() as db:
        cursor = db.execute(
            """
            INSERT INTO responses (
                title, category, body, published, created_at, admin_id
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                category,
                body,
                int(published),
                utc_now(),
                session["admin_id"],
            ),
        )

        response_id = cursor.lastrowid

        row = db.execute(
            "SELECT * FROM responses WHERE id = ?",
            (response_id,),
        ).fetchone()

    return jsonify({
        "ok": True,
        "response": row_response(row),
    }), 201


@app.get("/api/admin/responses")
@admin_required
def admin_responses():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM responses ORDER BY id DESC"
        ).fetchall()

    return jsonify({
        "ok": True,
        "responses": [row_response(row) for row in rows],
    })


@app.patch("/api/admin/responses/<int:response_id>")
@admin_required
def update_response(response_id: int):
    data = read_json()
    published = data.get("published")

    if not isinstance(published, bool):
        return json_error(
            "Provide published as true or false."
        )

    with get_db() as db:
        cursor = db.execute(
            "UPDATE responses SET published = ? WHERE id = ?",
            (int(published), response_id),
        )

        if cursor.rowcount == 0:
            return json_error("Response not found.", 404)

    return jsonify({
        "ok": True,
        "message": "Response visibility updated.",
    })


# -------------------------------- CLI ----------------------------------------

@app.cli.command("create-admin")
def create_admin_command():
    """Create an administrator or securely reset its password."""
    import getpass

    username = input("Admin username: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    password = getpass.getpass(
        "Admin password (minimum 12 characters): "
    )

    if len(password) < 12:
        print("Password must be at least 12 characters.")
        return

    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    password_hash = generate_password_hash(password)

    with get_db() as db:
        existing = db.execute(
            "SELECT id FROM admins WHERE username = ?",
            (username,),
        ).fetchone()

        if existing:
            db.execute(
                """
                UPDATE admins SET password_hash = ?
                WHERE username = ?
                """,
                (password_hash, username),
            )
            print("Administrator password updated.")
        else:
            db.execute(
                """
                INSERT INTO admins (username, password_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (username, password_hash, utc_now()),
            )
            print("Administrator created.")


@app.cli.command("init-db")
def init_db_command():
    """Initialize the database tables."""
    init_db()
    ensure_default_admin()
    print("Campus Voice database is ready.")


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "0") == "1"
    )
