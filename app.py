
from __future__ import annotations

import os
import re
import secrets
import sqlite3
import logging
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps
from uuid import uuid4

from flask import (
    Flask,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    flash,
    render_template,
    render_template_string,
    send_from_directory,
    abort,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# ============================================================
# CAMPUS VOICE - APPLICATION CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = INSTANCE_DIR / "private_uploads"
TEMPLATE_DIR = BASE_DIR / "templates"

INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(
    __name__,
    template_folder=str(TEMPLATE_DIR),
)

app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "change-this-development-secret"),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("COOKIE_SECURE", "").lower() == "true"
        or os.environ.get("RENDER", "").lower() == "true"
    ),
    PERMANENT_SESSION_LIFETIME=3600,
)

DATABASE = Path(
    os.environ.get(
        "CAMPUS_VOICE_DATABASE",
        str(INSTANCE_DIR / "campus_voice.db"),
    )
)

ALLOWED_AUDIO_EXTENSIONS = {
    ".mp3", ".wav", ".ogg", ".oga", ".m4a",
    ".aac", ".webm", ".mp4", ".mpeg", ".3gp",
}

ALLOWED_CATEGORIES = {
    "Teaching and learning",
    "Examinations and assessment",
    "Library and learning resources",
    "Hostels and accommodation",
    "Food and catering",
    "Fees and student services",
    "Facilities, sanitation and safety",
    "Student welfare",
    "Suggestion or innovation",
    "Other",
}

ALLOWED_STATUSES = {
    "pending",
    "under_review",
    "approved",
    "rejected",
    "resolved",
}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("campus_voice")


# ============================================================
# DATABASE
# ============================================================

def get_db():
    """Return a SQLite connection with dictionary-like rows."""
    connection = sqlite3.connect(str(DATABASE), timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db():
    """Create the database tables if they do not exist."""
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reference TEXT NOT NULL UNIQUE,
                category TEXT NOT NULL,
                submission_type TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                audio_filename TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                admin_note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                submission_id INTEGER,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'General announcement',
                published INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                published_at TEXT,
                FOREIGN KEY (submission_id)
                    REFERENCES submissions(id)
                    ON DELETE SET NULL
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_submissions_created
            ON submissions(created_at)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_submissions_status
            ON submissions(status)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_responses_published
            ON responses(published, published_at)
        """)

        # Create the first administrator only if the admin table is empty.
        # Set these environment variables before the first run in production.
        admin_count = db.execute(
            "SELECT COUNT(*) FROM admins"
        ).fetchone()[0]

        if admin_count == 0:
            username = os.environ.get(
                "CAMPUS_ADMIN_USERNAME", "meru123"
            ).strip()

            password = os.environ.get(
                "CAMPUS_ADMIN_PASSWORD", "merupolu@123"
            )

            if not username or not password:
                raise RuntimeError(
                    "Set CAMPUS_ADMIN_USERNAME and CAMPUS_ADMIN_PASSWORD."
                )

            db.execute(
                """
                INSERT INTO admins (username, password_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    generate_password_hash(password),
                    utc_now(),
                ),
            )

            logger.warning(
                "Initial administrator created. Change default credentials "
                "and set environment variables before production deployment."
            )


init_db()


# ============================================================
# SECURITY AND HELPER FUNCTIONS
# ============================================================

def json_error(message, status=400):
    return jsonify({"ok": False, "error": message}), status


def admin_required(function):
    @wraps(function)
    def decorated(*args, **kwargs):
        if not session.get("admin_id"):
            if request.path.startswith("/api/"):
                return json_error("Administrator login required.", 401)

            return redirect(url_for("admin_login"))

        return function(*args, **kwargs)

    return decorated


def new_reference():
    """Create a non-sequential reference for a submission."""
    return "CV-" + secrets.token_hex(4).upper()


def valid_audio_file(file):
    """Basic extension and declared MIME-type validation."""
    if not file or not file.filename:
        return False

    extension = Path(secure_filename(file.filename)).suffix.lower()

    return (
        extension in ALLOWED_AUDIO_EXTENSIONS
        and file.mimetype.lower().startswith("audio/")
        or extension == ".mp4"
        and file.mimetype.lower().startswith(("audio/", "video/"))
    )


def submission_to_dict(row):
    """Convert a private submission row into an admin-only response."""
    item = dict(row)

    # Never expose the private stored filename to the public API.
    item.pop("audio_filename", None)

    item["has_audio"] = bool(row["audio_filename"])
    item["date"] = item.get("created_at")

    return item


def get_admin_submission(reference):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM submissions WHERE reference = ?",
            (reference,),
        ).fetchone()

    return row


# ============================================================
# HOMEPAGE
# ============================================================

@app.route("/")
def index():
    """
    Render the user's index.html from the templates directory.
    """
    return render_template("index.html")


@app.route("/health")
def health():
    """Simple deployment health check."""
    return jsonify({
        "ok": True,
        "application": "Campus Voice",
    })


# ============================================================
# ADMIN LOGIN AND LOGOUT
# ============================================================

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_id"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Also accept JSON login requests.
        if request.is_json:
            data = request.get_json(silent=True) or {}
            username = str(data.get("username", "")).strip()
            password = str(data.get("password", ""))

        with get_db() as db:
            admin = db.execute(
                "SELECT * FROM admins WHERE username = ?",
                (username,),
            ).fetchone()

        if admin and check_password_hash(
            admin["password_hash"], password
        ):
            session.clear()
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            session.permanent = True

            if request.is_json:
                return jsonify({
                    "ok": True,
                    "redirect": url_for("admin_dashboard"),
                })

            return redirect(url_for("admin_dashboard"))

        if request.is_json:
            return json_error("Invalid username or password.", 401)

        flash("Invalid username or password.", "error")

    # Use your existing admin login template when available.
    if (TEMPLATE_DIR / "admin_login.html").exists():
        return render_template("admin_login.html")

    # Fallback login page if the template has not yet been created.
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Admin Login | Campus Voice</title>
      <style>
        * { box-sizing: border-box; }
        body {
          margin: 0; min-height: 100vh; display: grid;
          place-items: center; padding: 20px;
          font-family: Arial, sans-serif;
          background: #edf5ff; color: #243447;
        }
        .card {
          width: 100%; max-width: 420px; background: white;
          padding: 30px; border-radius: 18px;
          box-shadow: 0 15px 40px #173b5920;
        }
        h1 { color: #1f70c8; }
        label { display: block; margin: 16px 0 7px; }
        input {
          width: 100%; padding: 12px; border-radius: 9px;
          border: 1px solid #dce8f4;
        }
        button {
          margin-top: 20px; width: 100%; padding: 13px;
          border: 0; border-radius: 9px;
          background: #8b5e3c; color: white;
          font-weight: bold; cursor: pointer;
        }
        .error { color: #a33; }
        a { color: #1f70c8; }
      </style>
    </head>
    <body>
      <main class="card">
        <h1>Campus Voice</h1>
        <p>Administrator sign in</p>
        {% for category, message in get_flashed_messages(with_categories=true) %}
          <p class="error">{{ message }}</p>
        {% endfor %}
        <form method="post">
          <label for="username">Username</label>
          <input id="username" name="username"
                 autocomplete="username" required>
          <label for="password">Password</label>
          <input id="password" type="password" name="password"
                 autocomplete="current-password" required>
          <button type="submit">Login securely</button>
        </form>
        <p><a href="/">Return to homepage</a></p>
      </main>
    </body>
    </html>
    """)


@app.route("/admin/logout", methods=["GET", "POST"])
@app.route("/admin_logout", methods=["GET", "POST"])
def admin_logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("admin_login"))


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin_dashboard")
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    """
    Render the existing dashboard if present.
    Otherwise show a basic working dashboard using the admin API.
    """
    if (TEMPLATE_DIR / "admin_dashboard.html").exists():
        return render_template("admin_dashboard.html")

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Admin Dashboard | Campus Voice</title>
      <style>
        * { box-sizing: border-box; }
        body { margin: 0; font-family: Arial, sans-serif;
               background: #f6f9fd; color: #243447; }
        header { background: #173b59; color: white; padding: 18px 5%; }
        main { max-width: 1100px; margin: auto; padding: 25px; }
        .toolbar { display: flex; justify-content: space-between;
                   flex-wrap: wrap; gap: 12px; align-items: center; }
        .panel { background: white; padding: 20px; margin-top: 18px;
                 border: 1px solid #dce8f4; border-radius: 14px; }
        button, select, textarea, input {
          padding: 10px; border: 1px solid #dce8f4;
          border-radius: 8px; font: inherit;
        }
        button { cursor: pointer; background: #2b8ef1; color: white;
                 border: 0; font-weight: bold; }
        .brown { background: #8b5e3c; }
        .danger { background: #a33; }
        .item { border-top: 1px solid #dce8f4; padding: 18px 0; }
        .item p { white-space: pre-wrap; overflow-wrap: anywhere; }
        textarea { width: 100%; min-height: 90px; }
        input[type=text] { width: 100%; }
        small { color: #68798b; }
        audio { width: 100%; margin: 10px 0; }
        .actions { display: flex; gap: 8px; flex-wrap: wrap; }
      </style>
    </head>
    <body>
      <header>
        <div class="toolbar">
          <div>
            <strong>Campus Voice Administration</strong><br>
            <small style="color:#d0dce5">
              Signed in as {{ session.get('admin_username', 'admin') }}
            </small>
          </div>
          <form method="post" action="{{ url_for('admin_logout') }}">
            <button class="brown" type="submit">Logout</button>
          </form>
        </div>
      </header>
      <main>
        <h1>Feedback dashboard</h1>
        <p>Review submissions and publish official replies.</p>
        <div class="toolbar">
          <select id="filter">
            <option value="">All statuses</option>
            <option value="pending">Pending</option>
            <option value="under_review">Under review</option>
            <option value="approved">Approved</option>
            <option value="rejected">Rejected</option>
            <option value="resolved">Resolved</option>
          </select>
          <button onclick="loadSubmissions()">Refresh submissions</button>
        </div>
        <div id="summary" class="panel">Loading...</div>
        <div id="submissions" class="panel">Loading submissions...</div>
        <section class="panel">
          <h2>Publish an official response</h2>
          <form id="replyForm">
            <label>Submission reference (optional)</label>
            <input id="replyReference" type="text"
                   placeholder="e.g. CV-A1B2C3D4">
            <p><label>Response title</label></p>
            <input id="replyTitle" type="text" required maxlength="160">
            <p><label>Response category</label></p>
            <input id="replyCategory" type="text"
                   value="General announcement" maxlength="100">
            <p><label>Official response</label></p>
            <textarea id="replyBody" required maxlength="5000"></textarea>
            <p>
              <label>
                <input id="replyPublished" type="checkbox" checked>
                Publish this response on the homepage
              </label>
            </p>
            <button type="submit">Save response</button>
          </form>
          <p id="replyMessage"></p>
        </section>
      </main>
      <script>
      const escapeHTML = value => String(value ?? "").replace(/[&<>"']/g, c => ({
        "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
      }[c]));

      async function api(url, options={}) {
        const response = await fetch(url, {
          credentials: "same-origin",
          ...options,
          headers: {
            "Accept": "application/json",
            ...(options.headers || {})
          }
        });
        const data = await response.json();
        if (!response.ok || data.ok === false) {
          throw new Error(data.error || "Request failed");
        }
        return data;
      }

      async function loadSubmissions() {
        const target = document.getElementById("submissions");
        target.textContent = "Loading submissions...";
        try {
          const data = await api("/api/admin/submissions");
          const items = data.submissions || [];
          document.getElementById("summary").textContent =
            "Total submissions: " + items.length +
            " | Pending: " + items.filter(x => x.status === "pending").length +
            " | Resolved: " + items.filter(x => x.status === "resolved").length;

          const filter = document.getElementById("filter").value;
          const visible = items.filter(x => !filter || x.status === filter);

          if (!visible.length) {
            target.textContent = "No submissions found.";
            return;
          }

          target.replaceChildren();
          visible.forEach(item => {
            const article = document.createElement("article");
            article.className = "item";

            const title = document.createElement("h3");
            title.textContent = item.category + " — " + item.reference;

            const meta = document.createElement("small");
            meta.textContent = "Type: " + item.submission_type +
              " | Status: " + item.status + " | Received: " + item.created_at;

            const body = document.createElement("p");
            body.textContent = item.body || "(Voice-note submission)";

            const details = document.createElement("p");
            details.textContent = item.details ? "Context: " + item.details : "";

            article.append(title, meta, body, details);

            if (item.has_audio) {
              const audio = document.createElement("audio");
              audio.controls = true;
              audio.preload = "none";
              audio.src = "/admin/audio/" + encodeURIComponent(item.reference);
              article.appendChild(audio);
            }

            const status = document.createElement("select");
            ["pending", "under_review", "approved", "rejected", "resolved"]
              .forEach(value => {
                const option = document.createElement("option");
                option.value = value;
                option.textContent = value.replace("_", " ");
                option.selected = item.status === value;
                status.appendChild(option);
              });

            const note = document.createElement("textarea");
            note.placeholder = "Private administrator note";
            note.value = item.admin_note || "";
            note.maxLength = 3000;

            const actions = document.createElement("div");
            actions.className = "actions";

            const save = document.createElement("button");
            save.textContent = "Save review";
            save.onclick = async () => {
              try {
                await api("/api/admin/submissions/" +
                  encodeURIComponent(item.reference), {
                    method: "PATCH",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({
                      status: status.value,
                      admin_note: note.value
                    })
                  });
                alert("Submission updated.");
                loadSubmissions();
              } catch (error) {
                alert(error.message);
              }
            };

            const reply = document.createElement("button");
            reply.className = "brown";
            reply.textContent = "Reply to this submission";
            reply.onclick = () => {
              document.getElementById("replyReference").value = item.reference;
              document.getElementById("replyCategory").value = item.category;
              document.getElementById("replyTitle").focus();
              document.getElementById("replyForm").scrollIntoView({
                behavior: "smooth"
              });
            };

            actions.append(save, reply);
            article.append(status, document.createElement("br"), note, actions);
            target.appendChild(article);
          });
        } catch (error) {
          target.textContent = "Could not load submissions: " + error.message;
        }
      }

      document.getElementById("filter").addEventListener("change", loadSubmissions);

      document.getElementById("replyForm").addEventListener("submit", async event => {
        event.preventDefault();
        const message = document.getElementById("replyMessage");
        message.textContent = "Saving...";
        try {
          await api("/api/admin/responses", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
              reference: document.getElementById("replyReference").value.trim(),
              title: document.getElementById("replyTitle").value.trim(),
              category: document.getElementById("replyCategory").value.trim(),
              body: document.getElementById("replyBody").value.trim(),
              published: document.getElementById("replyPublished").checked
            })
          });
          message.textContent = "Official response saved.";
          document.getElementById("replyForm").reset();
          document.getElementById("replyCategory").value = "General announcement";
          document.getElementById("replyPublished").checked = true;
        } catch (error) {
          message.textContent = error.message;
        }
      });

      loadSubmissions();
      setInterval(() => {
        if (!document.hidden) loadSubmissions();
      }, 15000);
      </script>
    </body>
    </html>
    """)


# ============================================================
# PUBLIC SUBMISSION API
# Compatible with the supplied index.html
# ============================================================

@app.route("/api/submissions", methods=["POST"])
def create_submission():
    """
    Accept multipart/form-data fields:
      category, category_id, type, body, message, details, audio
    """
    category = (
        request.form.get("category", "").strip()
        or request.form.get("category_id", "").strip()
    )

    submission_type = request.form.get("type", "Text").strip()
    body = (
        request.form.get("body", "").strip()
        or request.form.get("message", "").strip()
    )
    details = request.form.get("details", "").strip()

    if category not in ALLOWED_CATEGORIES:
        return json_error("Please select a valid message category.")

    if len(body) > 3000:
        return json_error("Your message must not exceed 3000 characters.")

    if len(details) > 160:
        return json_error("Optional context must not exceed 160 characters.")

    audio_file = request.files.get("audio")

    if submission_type.lower() in {"voice", "voice note", "audio"}:
        if not audio_file or not audio_file.filename:
            return json_error("Please record or upload a voice note.")

        if not valid_audio_file(audio_file):
            return json_error(
                "Unsupported audio format. Choose a supported audio file."
            )

        submission_type = "Voice note"
        body = ""
    else:
        submission_type = "Text"

        if not body:
            return json_error("Please enter your message.")

        if audio_file and audio_file.filename:
            return json_error(
                "Please submit either text or a voice note, not both."
            )

    # Create a private filename independent of the original upload name.
    audio_filename = None
    reference = new_reference()
    saved_path = None

    if audio_file and audio_file.filename:
        extension = Path(
            secure_filename(audio_file.filename)
        ).suffix.lower()

        audio_filename = f"{uuid4().hex}{extension}"
        saved_path = UPLOAD_DIR / audio_filename

        try:
            audio_file.save(saved_path)

            if saved_path.stat().st_size == 0:
                saved_path.unlink(missing_ok=True)
                return json_error("The uploaded audio file is empty.")

            if saved_path.stat().st_size > 10 * 1024 * 1024:
                saved_path.unlink(missing_ok=True)
                return json_error("Audio files must not exceed 10 MB.")

        except Exception:
            logger.exception("Audio upload failed")
            if saved_path:
                saved_path.unlink(missing_ok=True)
            return json_error("Could not save your audio file.", 500)

    timestamp = utc_now()

    try:
        with get_db() as db:
            cursor = db.execute(
                """
                INSERT INTO submissions (
                    reference, category, submission_type,
                    body, details, audio_filename,
                    status, admin_note, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, 'pending', '', ?, ?)
                """,
                (
                    reference,
                    category,
                    submission_type,
                    body,
                    details,
                    audio_filename,
                    timestamp,
                    timestamp,
                ),
            )

            submission_id = cursor.lastrowid

    except Exception:
        logger.exception("Could not save submission")

        if saved_path:
            saved_path.unlink(missing_ok=True)

        return json_error("The submission could not be saved.", 500)

    logger.info("New submission received: %s", reference)

    return jsonify({
        "ok": True,
        "success": True,
        "reference": reference,
        "message": "Your anonymous submission has been received.",
    }), 201


# ============================================================
# PUBLIC OFFICIAL RESPONSES API
# Only published responses are visible on the homepage.
# ============================================================

@app.route("/api/responses", methods=["GET"])
def public_responses():
    with get_db() as db:
        rows = db.execute(
            """
            SELECT
                r.id,
                r.title,
                r.body,
                r.category,
                r.created_at,
                r.published_at,
                r.published,
                s.reference
            FROM responses r
            LEFT JOIN submissions s ON s.id = r.submission_id
            WHERE r.published = 1
            ORDER BY COALESCE(r.published_at, r.created_at) DESC, r.id DESC
            LIMIT 100
            """
        ).fetchall()

    responses = []

    for row in rows:
        responses.append({
            "id": row["id"],
            "title": row["title"],
            "body": row["body"],
            "response": row["body"],
            "category": row["category"],
            "date": row["published_at"] or row["created_at"],
            "created_at": row["created_at"],
            "published_at": row["published_at"],
            "published": True,
            "is_published": True,
        })

    return jsonify({
        "ok": True,
        "responses": responses,
    })


# ============================================================
# ADMIN SUBMISSIONS API
# ============================================================

@app.route("/api/admin/submissions", methods=["GET"])
@admin_required
def admin_list_submissions():
    status = request.args.get("status", "").strip()

    with get_db() as db:
        if status and status in ALLOWED_STATUSES:
            rows = db.execute(
                """
                SELECT * FROM submissions
                WHERE status = ?
                ORDER BY created_at DESC, id DESC
                """,
                (status,),
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT * FROM submissions
                ORDER BY created_at DESC, id DESC
                """
            ).fetchall()

    return jsonify({
        "ok": True,
        "submissions": [submission_to_dict(row) for row in rows],
    })


@app.route("/api/admin/submissions/<reference>", methods=["PATCH"])
@admin_required
def update_submission(reference):
    data = request.get_json(silent=True) or {}

    status = data.get("status")
    admin_note = data.get("admin_note")

    if status is None and admin_note is None:
        return json_error("Provide a status or administrator note.")

    if status is not None and status not in ALLOWED_STATUSES:
        return json_error("Invalid submission status.")

    if admin_note is not None:
        admin_note = str(admin_note).strip()

        if len(admin_note) > 3000:
            return json_error("Administrator note is too long.")

    row = get_admin_submission(reference)

    if not row:
        return json_error("Submission not found.", 404)

    updates = []
    values = []

    if status is not None:
        updates.append("status = ?")
        values.append(status)

    if admin_note is not None:
        updates.append("admin_note = ?")
        values.append(admin_note)

    updates.append("updated_at = ?")
    values.append(utc_now())
    values.append(reference)

    with get_db() as db:
        db.execute(
            f"""
            UPDATE submissions
            SET {", ".join(updates)}
            WHERE reference = ?
            """,
            values,
        )

        updated = db.execute(
            "SELECT * FROM submissions WHERE reference = ?",
            (reference,),
        ).fetchone()

    return jsonify({
        "ok": True,
        "message": "Submission updated.",
        "submission": submission_to_dict(updated),
    })


# ============================================================
# ADMIN PRIVATE AUDIO ACCESS
# Audio files are never exposed through /static.
# ============================================================

@app.route("/admin/audio/<reference>", methods=["GET"])
@admin_required
def admin_audio(reference):
    row = get_admin_submission(reference)

    if not row or not row["audio_filename"]:
        abort(404)

    filename = row["audio_filename"]

    # Prevent path traversal and only serve files from private storage.
    if Path(filename).name != filename:
        abort(404)

    file_path = UPLOAD_DIR / filename

    if not file_path.is_file():
        abort(404)

    return send_from_directory(
        str(UPLOAD_DIR),
        filename,
        as_attachment=False,
        conditional=True,
        max_age=0,
    )


# ============================================================
# ADMIN OFFICIAL RESPONSE MANAGEMENT
# ============================================================

@app.route("/api/admin/responses", methods=["GET"])
@admin_required
def admin_list_responses():
    with get_db() as db:
        rows = db.execute(
            """
            SELECT r.*, s.reference
            FROM responses r
            LEFT JOIN submissions s ON s.id = r.submission_id
            ORDER BY r.created_at DESC, r.id DESC
            """
        ).fetchall()

    return jsonify({
        "ok": True,
        "responses": [dict(row) for row in rows],
    })


@app.route("/api/admin/responses", methods=["POST"])
@admin_required
def create_response():
    data = request.get_json(silent=True) or {}

    reference = str(data.get("reference", "")).strip()
    title = str(data.get("title", "")).strip()
    body = str(data.get("body", data.get("response", ""))).strip()
    category = str(data.get("category", "General announcement")).strip()
    published = data.get("published", False)

    if not title:
        return json_error("Response title is required.")

    if not body:
        return json_error("Response body is required.")

    if len(title) > 160 or len(body) > 5000:
        return json_error("The title or response exceeds the allowed length.")

    if len(category) > 100:
        return json_error("Response category is too long.")

    if not isinstance(published, bool):
        return json_error("Published must be true or false.")

    submission_id = None

    if reference:
        submission = get_admin_submission(reference)

        if not submission:
            return json_error("The specified submission was not found.", 404)

        submission_id = submission["id"]

    timestamp = utc_now()
    published_at = timestamp if published else None

    with get_db() as db:
        cursor = db.execute(
            """
            INSERT INTO responses (
                submission_id, title, body, category,
                published, created_at, published_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                submission_id,
                title,
                body,
                category or "General announcement",
                int(published),
                timestamp,
                published_at,
            ),
        )

        response_id = cursor.lastrowid

        # A response marked as published can also mark the submission resolved.
        if submission_id is not None and published:
            db.execute(
                """
                UPDATE submissions
                SET status = 'resolved', updated_at = ?
                WHERE id = ?
                """,
                (timestamp, submission_id),
            )

    return jsonify({
        "ok": True,
        "message": "Official response saved.",
        "id": response_id,
        "published": published,
    }), 201


@app.route("/api/admin/responses/<int:response_id>", methods=["PATCH"])
@admin_required
def update_response(response_id):
    data = request.get_json(silent=True) or {}

    with get_db() as db:
        row = db.execute(
            "SELECT * FROM responses WHERE id = ?",
            (response_id,),
        ).fetchone()

        if not row:
            return json_error("Response not found.", 404)

        updates = []
        values = []

        if "title" in data:
            title = str(data["title"]).strip()

            if not title or len(title) > 160:
                return json_error("Enter a valid response title.")

            updates.append("title = ?")
            values.append(title)

        if "body" in data or "response" in data:
            body = str(data.get("body", data.get("response", ""))).strip()

            if not body or len(body) > 5000:
                return json_error("Enter a valid response body.")

            updates.append("body = ?")
            values.append(body)

        if "category" in data:
            category = str(data["category"]).strip()

            if len(category) > 100:
                return json_error("Response category is too long.")

            updates.append("category = ?")
            values.append(category or "General announcement")

        if "published" in data:
            published = data["published"]

            if not isinstance(published, bool):
                return json_error("Published must be true or false.")

            updates.append("published = ?")
            values.append(int(published))

            updates.append("published_at = ?")
            values.append(utc_now() if published else None)

        if not updates:
            return json_error("No changes were provided.")

        values.append(response_id)

        db.execute(
            f"UPDATE responses SET {', '.join(updates)} WHERE id = ?",
            values,
        )

        updated = db.execute(
            "SELECT * FROM responses WHERE id = ?",
            (response_id,),
        ).fetchone()

    return jsonify({
        "ok": True,
        "message": "Response updated.",
        "response": dict(updated),
    })


@app.route("/api/admin/responses/<int:response_id>", methods=["DELETE"])
@admin_required
def delete_response(response_id):
    with get_db() as db:
        cursor = db.execute(
            "DELETE FROM responses WHERE id = ?",
            (response_id,),
        )

        if cursor.rowcount == 0:
            return json_error("Response not found.", 404)

    return jsonify({
        "ok": True,
        "message": "Response deleted.",
    })


# ============================================================
# BASIC SECURITY HEADERS AND ERROR HANDLING
# ============================================================

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"

    return response


@app.errorhandler(413)
def file_too_large(_error):
    if request.path.startswith("/api/"):
        return json_error("Upload exceeds the 10 MB limit.", 413)

    return "Upload exceeds the 10 MB limit.", 413


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"):
        return json_error("The requested resource was not found.", 404)

    return "Page not found.", 404


@app.errorhandler(500)
def internal_error(error):
    logger.error("Application error: %s", error)

    if request.path.startswith("/api/"):
        return json_error("An internal server error occurred.", 500)

    return "An internal server error occurred.", 500


# ============================================================
# RUN LOCALLY
# ============================================================

if __name__ == "__main__":
    # Debug mode should only be enabled during local development.
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "").lower() == "true",
    )
