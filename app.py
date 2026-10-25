from __future__ import annotations

import logging
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from uuid import uuid4

from flask import (
    Flask, abort, flash, jsonify, redirect, render_template,
    render_template_string, request, send_from_directory, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# ============================================================
# CAMPUS VOICE - CONFIGURATION
# ============================================================
BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
INSTANCE_DIR = Path(os.environ.get("CAMPUS_VOICE_INSTANCE", str(BASE_DIR / "instance")))
UPLOAD_DIR = Path(os.environ.get("CAMPUS_VOICE_UPLOAD_DIR", str(INSTANCE_DIR / "private_uploads")))
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "change-this-development-secret"),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("COOKIE_SECURE", "").lower() == "true"
                           or os.environ.get("RENDER", "").lower() == "true"),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
)

DATABASE = Path(os.environ.get("CAMPUS_VOICE_DATABASE", str(INSTANCE_DIR / "campus_voice.db")))
ALLOWED_AUDIO_EXTENSIONS = {
    ".mp3", ".wav", ".ogg", ".oga", ".m4a", ".aac", ".webm", ".mp4", ".mpeg", ".3gp"
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
ALLOWED_STATUSES = {"pending", "under_review", "approved", "rejected", "resolved"}
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("campus_voice")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    db = sqlite3.connect(str(DATABASE), timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 30000")
    return db


def init_db() -> None:
    with get_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS submissions (
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
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'General announcement',
            published INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            published_at TEXT,
            FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE SET NULL
        )""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_submissions_created ON submissions(created_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_responses_published ON responses(published, published_at)")
        count = db.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        if count == 0:
            username = os.environ.get("CAMPUS_ADMIN_USERNAME", "meru123").strip()
            password = os.environ.get("CAMPUS_ADMIN_PASSWORD", "merupolu@123")
            if not username or not password:
                raise RuntimeError("Set CAMPUS_ADMIN_USERNAME and CAMPUS_ADMIN_PASSWORD.")
            db.execute(
                "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), utc_now()),
            )
            logger.warning("Initial Campus Voice admin account created. Set production credentials in environment variables.")


init_db()


def json_error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            if request.path.startswith("/api/"):
                return json_error("Administrator login required. Please sign in again.", 401)
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def new_reference() -> str:
    return "CV-" + secrets.token_hex(4).upper()


def valid_audio_file(file) -> bool:
    if not file or not file.filename:
        return False
    ext = Path(secure_filename(file.filename)).suffix.lower()
    mime = (file.mimetype or "").lower()
    if ext not in ALLOWED_AUDIO_EXTENSIONS:
        return False
    # Browsers sometimes label recordings as application/octet-stream.
    return mime.startswith(("audio/", "video/")) or mime == "application/octet-stream"


def submission_to_dict(row) -> dict:
    item = dict(row)
    item["has_audio"] = bool(item.get("audio_filename"))
    item.pop("audio_filename", None)
    item["date"] = item.get("created_at")
    return item


def get_submission(reference: str):
    with get_db() as db:
        return db.execute("SELECT * FROM submissions WHERE reference = ?", (reference,)).fetchone()


# ============================================================
# PUBLIC PAGES / COMPATIBILITY ROUTES
# ============================================================
@app.route("/")
def index():
    if (TEMPLATE_DIR / "index.html").exists():
        return render_template("index.html")
    return "Campus Voice template templates/index.html is missing.", 500


@app.route("/health")
def health():
    return jsonify({"ok": True, "application": "Campus Voice"})


@app.route("/admin_login", methods=["GET", "POST"])
@app.route("/admin_login.html", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_id"):
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        if request.is_json:
            data = request.get_json(silent=True) or {}
            username = str(data.get("username", "")).strip()
            password = str(data.get("password", ""))
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
        with get_db() as db:
            admin = db.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            session.permanent = True
            if request.is_json:
                return jsonify({"ok": True, "redirect": url_for("admin_dashboard")})
            next_url = request.args.get("next", "")
            # Only permit local relative redirects.
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("admin_dashboard"))
        if request.is_json:
            return json_error("Invalid username or password.", 401)
        flash("Invalid username or password.", "error")
    if (TEMPLATE_DIR / "admin_login.html").exists():
        return render_template("admin_login.html")
    return render_template_string(LOGIN_FALLBACK)


LOGIN_FALLBACK = """<!doctype html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'><title>Admin Login | Campus Voice</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;font-family:Arial;background:#edf5ff;color:#243447}.card{width:100%;max-width:420px;background:white;padding:30px;border-radius:18px;box-shadow:0 15px 40px #173b5920}h1{color:#1f70c8}label{display:block;margin:16px 0 7px}input{width:100%;padding:12px;border:1px solid #dce8f4;border-radius:9px}button{margin-top:20px;width:100%;padding:13px;border:0;border-radius:9px;background:#8b5e3c;color:white;font-weight:bold;cursor:pointer}.error{color:#a33}a{color:#1f70c8}</style></head><body><main class='card'><h1>Campus Voice</h1><p>Administrator sign in</p>{% for category,message in get_flashed_messages(with_categories=true) %}<p class='error'>{{ message }}</p>{% endfor %}<form method='post'><label for='username'>Username</label><input id='username' name='username' autocomplete='username' required><label for='password'>Password</label><input id='password' type='password' name='password' autocomplete='current-password' required><button type='submit'>Login securely</button></form><p><a href='/'>Return to homepage</a></p></main></body></html>"""


@app.route("/admin/logout", methods=["GET", "POST"])
@app.route("/admin_logout", methods=["GET", "POST"])
def admin_logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("admin_login"))


@app.route("/admin_dashboard")
@app.route("/admin/dashboard")
@app.route("/admin_dashboard.html")
@admin_required
def admin_dashboard():
    if (TEMPLATE_DIR / "admin_dashboard.html").exists():
        return render_template("admin_dashboard.html")
    return render_template_string(DASHBOARD_FALLBACK)


DASHBOARD_FALLBACK = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Campus Voice Admin</title><style>*{box-sizing:border-box}body{margin:0;font-family:Arial;background:#f6f9fd;color:#243447}header{background:#173b59;color:#fff;padding:18px 5%}main{max-width:1100px;margin:auto;padding:25px}.toolbar,.actions{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}.panel{background:#fff;padding:20px;margin-top:18px;border:1px solid #dce8f4;border-radius:14px}button,select,textarea,input{padding:10px;border:1px solid #dce8f4;border-radius:8px;font:inherit}button{cursor:pointer;background:#2b8ef1;color:white;border:0;font-weight:bold}.brown{background:#8b5e3c}.item{border-top:1px solid #dce8f4;padding:18px 0}.item p{white-space:pre-wrap;overflow-wrap:anywhere}textarea,input[type=text]{width:100%}textarea{min-height:90px}small{color:#68798b}audio{width:100%;margin:10px 0}</style></head><body><header><div class="toolbar"><div><strong>Campus Voice Administration</strong><br><small style="color:#d0dce5">Signed in as {{ session.get('admin_username','admin') }}</small></div><form method="post" action="{{ url_for('admin_logout') }}"><button class="brown">Logout</button></form></div></header><main><h1>Feedback dashboard</h1><p>Review anonymous submissions and publish official replies.</p><div class="toolbar"><select id="filter"><option value="">All statuses</option><option value="pending">Pending</option><option value="under_review">Under review</option><option value="approved">Approved</option><option value="rejected">Rejected</option><option value="resolved">Resolved</option></select><button id="refresh">Refresh</button></div><div id="summary" class="panel">Loading...</div><div id="submissions" class="panel">Loading submissions...</div><section class="panel"><h2>Publish an official response</h2><form id="replyForm"><label>Submission reference (optional)</label><input id="replyReference" type="text" placeholder="CV-A1B2C3D4"><p><label>Response title</label></p><input id="replyTitle" type="text" required maxlength="160"><p><label>Response category</label></p><input id="replyCategory" type="text" value="General announcement" maxlength="100"><p><label>Official response</label></p><textarea id="replyBody" required maxlength="5000"></textarea><p><label><input id="replyPublished" type="checkbox" checked> Publish this response on the homepage</label></p><button type="submit">Save response</button></form><p id="replyMessage" role="status"></p></section></main><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(url,options={}){const r=await fetch(url,{credentials:'same-origin',...options,headers:{Accept:'application/json',...(options.headers||{})}});let d;try{d=await r.json()}catch{throw Error('Server returned an invalid response.')}if(!r.ok||d.ok===false)throw Error(d.error||'Request failed');return d}
async function loadSubmissions(){const target=document.getElementById('submissions');target.textContent='Loading submissions...';try{const d=await api('/api/admin/submissions?status=all');const all=d.submissions||[];document.getElementById('summary').textContent=`Total: ${all.length} | Pending: ${all.filter(x=>x.status==='pending').length} | Resolved: ${all.filter(x=>x.status==='resolved').length}`;const f=document.getElementById('filter').value;const items=all.filter(x=>!f||x.status===f);target.replaceChildren();if(!items.length){target.textContent='No submissions found.';return}for(const item of items){const a=document.createElement('article');a.className='item';const h=document.createElement('h3');h.textContent=`${item.category} — ${item.reference}`;const m=document.createElement('small');m.textContent=`Type: ${item.submission_type} | Status: ${item.status} | Received: ${item.created_at}`;const p=document.createElement('p');p.textContent=item.body||'(Voice-note submission)';const detail=document.createElement('p');detail.textContent=item.details?'Context: '+item.details:'';a.append(h,m,p,detail);if(item.has_audio){const audio=document.createElement('audio');audio.controls=true;audio.preload='none';audio.src='/admin/audio/'+encodeURIComponent(item.reference);a.append(audio)}const status=document.createElement('select');for(const v of ['pending','under_review','approved','rejected','resolved']){const o=document.createElement('option');o.value=v;o.textContent=v.replace('_',' ');o.selected=item.status===v;status.append(o)}const note=document.createElement('textarea');note.placeholder='Private administrator note';note.value=item.admin_note||'';note.maxLength=3000;const actions=document.createElement('div');actions.className='actions';const save=document.createElement('button');save.textContent='Save review';save.onclick=async()=>{try{await api('/api/admin/submissions/'+encodeURIComponent(item.reference),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:status.value,admin_note:note.value})});await loadSubmissions()}catch(e){alert(e.message)}};const reply=document.createElement('button');reply.className='brown';reply.textContent='Reply to this submission';reply.onclick=()=>{document.getElementById('replyReference').value=item.reference;document.getElementById('replyCategory').value=item.category;document.getElementById('replyTitle').focus();document.getElementById('replyForm').scrollIntoView({behavior:'smooth'})};actions.append(save,reply);a.append(status,document.createElement('br'),note,actions);target.append(a)}}catch(e){target.textContent='Could not load submissions: '+e.message;if(e.message.toLowerCase().includes('sign in'))target.textContent+=' Reload this page after logging in again.'}}
document.getElementById('filter').addEventListener('change',loadSubmissions);document.getElementById('refresh').addEventListener('click',loadSubmissions);document.getElementById('replyForm').addEventListener('submit',async e=>{e.preventDefault();const msg=document.getElementById('replyMessage');msg.textContent='Saving...';try{await api('/api/admin/responses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reference:document.getElementById('replyReference').value.trim(),title:document.getElementById('replyTitle').value.trim(),category:document.getElementById('replyCategory').value.trim(),body:document.getElementById('replyBody').value.trim(),published:document.getElementById('replyPublished').checked})});msg.textContent='Official response saved.';e.target.reset();document.getElementById('replyCategory').value='General announcement';document.getElementById('replyPublished').checked=true}catch(err){msg.textContent=err.message}});loadSubmissions();setInterval(()=>{if(!document.hidden)loadSubmissions()},20000);
</script></body></html>'''


# ============================================================
# PUBLIC SUBMISSION API
# ============================================================
@app.route("/api/submissions", methods=["POST"])
def create_submission():
    category = (request.form.get("category", "").strip()
                or request.form.get("category_id", "").strip())
    submission_type = request.form.get("type", "Text").strip().lower()
    body = (request.form.get("body", "").strip()
            or request.form.get("message", "").strip())
    details = request.form.get("details", "").strip()
    audio_file = request.files.get("audio")

    if category not in ALLOWED_CATEGORIES:
        return json_error("Please select a valid message category.")
    if len(body) > 3000:
        return json_error("Your message must not exceed 3000 characters.")
    if len(details) > 160:
        return json_error("Optional context must not exceed 160 characters.")

    is_voice = submission_type in {"voice", "voice note", "audio", "voicenote"}
    if is_voice:
        if not audio_file or not audio_file.filename:
            return json_error("Please record or upload a voice note.")
        if not valid_audio_file(audio_file):
            return json_error("Unsupported audio format. Choose a supported audio file.")
        submission_type = "Voice note"
        body = ""
    else:
        submission_type = "Text"
        if not body:
            return json_error("Please enter your message.")
        if audio_file and audio_file.filename:
            return json_error("Please submit either text or a voice note, not both.")

    reference = new_reference()
    audio_filename = None
    saved_path = None
    if is_voice:
        ext = Path(secure_filename(audio_file.filename)).suffix.lower()
        audio_filename = f"{uuid4().hex}{ext}"
        saved_path = UPLOAD_DIR / audio_filename
        try:
            audio_file.save(saved_path)
            size = saved_path.stat().st_size
            if size <= 0:
                saved_path.unlink(missing_ok=True)
                return json_error("The uploaded audio file is empty.")
            if size > 10 * 1024 * 1024:
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
            db.execute("""INSERT INTO submissions
                (reference, category, submission_type, body, details, audio_filename,
                 status, admin_note, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', '', ?, ?)""",
                (reference, category, submission_type, body, details,
                 audio_filename, timestamp, timestamp))
    except Exception:
        logger.exception("Could not save submission")
        if saved_path:
            saved_path.unlink(missing_ok=True)
        return json_error("The submission could not be saved.", 500)

    logger.info("New submission received: %s", reference)
    return jsonify({"ok": True, "success": True, "reference": reference,
                    "message": "Your anonymous submission has been received."}), 201


# ============================================================
# PUBLIC RESPONSES: PUBLISHED ONLY
# ============================================================
@app.route("/api/responses", methods=["GET"])
def public_responses():
    with get_db() as db:
        rows = db.execute("""SELECT r.id, r.title, r.body, r.category, r.created_at,
            r.published_at FROM responses r WHERE r.published = 1
            ORDER BY COALESCE(r.published_at, r.created_at) DESC, r.id DESC LIMIT 100""").fetchall()
    items = [{"id": r["id"], "title": r["title"], "body": r["body"],
              "response": r["body"], "category": r["category"],
              "date": r["published_at"] or r["created_at"],
              "created_at": r["created_at"], "published_at": r["published_at"],
              "published": True, "is_published": True} for r in rows]
    return jsonify({"ok": True, "responses": items})


# ============================================================
# ADMIN SUBMISSION API
# ============================================================
@app.route("/api/admin/submissions", methods=["GET"])
@admin_required
def admin_list_submissions():
    status = request.args.get("status", "").strip()
    with get_db() as db:
        if status and status.lower() != "all" and status in ALLOWED_STATUSES:
            rows = db.execute("SELECT * FROM submissions WHERE status = ? ORDER BY created_at DESC, id DESC", (status,)).fetchall()
        else:
            rows = db.execute("SELECT * FROM submissions ORDER BY created_at DESC, id DESC").fetchall()
    return jsonify({"ok": True, "submissions": [submission_to_dict(r) for r in rows]})


@app.route("/api/admin/submissions/<reference>", methods=["PATCH"])
@admin_required
def update_submission(reference):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    note = data.get("admin_note")
    if status is None and note is None:
        return json_error("Provide a status or administrator note.")
    if status is not None and status not in ALLOWED_STATUSES:
        return json_error("Invalid submission status.")
    if note is not None:
        note = str(note).strip()
        if len(note) > 3000:
            return json_error("Administrator note is too long.")
    with get_db() as db:
        row = db.execute("SELECT * FROM submissions WHERE reference = ?", (reference,)).fetchone()
        if not row:
            return json_error("Submission not found.", 404)
        changes, values = [], []
        if status is not None:
            changes.append("status = ?")
            values.append(status)
        if note is not None:
            changes.append("admin_note = ?")
            values.append(note)
        changes.append("updated_at = ?")
        values.extend([utc_now(), reference])
        db.execute(f"UPDATE submissions SET {', '.join(changes)} WHERE reference = ?", values)
        updated = db.execute("SELECT * FROM submissions WHERE reference = ?", (reference,)).fetchone()
    return jsonify({"ok": True, "message": "Submission updated.", "submission": submission_to_dict(updated)})


@app.route("/admin/audio/<reference>", methods=["GET"])
@admin_required
def admin_audio(reference):
    row = get_submission(reference)
    if not row or not row["audio_filename"]:
        abort(404)
    filename = row["audio_filename"]
    if Path(filename).name != filename:
        abort(404)
    path = UPLOAD_DIR / filename
    if not path.is_file():
        abort(404)
    return send_from_directory(str(UPLOAD_DIR), filename, as_attachment=False, conditional=True, max_age=0)


# ============================================================
# ADMIN OFFICIAL RESPONSE MANAGEMENT
# ============================================================
@app.route("/api/admin/responses", methods=["GET"])
@admin_required
def admin_list_responses():
    with get_db() as db:
        rows = db.execute("""SELECT r.*, s.reference FROM responses r
            LEFT JOIN submissions s ON s.id = r.submission_id
            ORDER BY r.created_at DESC, r.id DESC""").fetchall()
    return jsonify({"ok": True, "responses": [dict(r) for r in rows]})


@app.route("/api/admin/responses", methods=["POST"])
@admin_required
def create_response():
    data = request.get_json(silent=True) or {}
    reference = str(data.get("reference", "")).strip()
    title = str(data.get("title", "")).strip()
    body = str(data.get("body", data.get("response", ""))).strip()
    category = str(data.get("category", "General announcement")).strip() or "General announcement"
    published = data.get("published", False)
    if not title or len(title) > 160:
        return json_error("Response title is required and must be at most 160 characters.")
    if not body or len(body) > 5000:
        return json_error("Response body is required and must be at most 5000 characters.")
    if len(category) > 100:
        return json_error("Response category is too long.")
    if not isinstance(published, bool):
        return json_error("Published must be true or false.")
    submission_id = None
    if reference:
        submission = get_submission(reference)
        if not submission:
            return json_error("The specified submission was not found.", 404)
        submission_id = submission["id"]
    timestamp = utc_now()
    with get_db() as db:
        cursor = db.execute("""INSERT INTO responses
            (submission_id, title, body, category, published, created_at, published_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (submission_id, title, body, category, int(published), timestamp, timestamp if published else None))
        response_id = cursor.lastrowid
        if submission_id is not None and published:
            db.execute("UPDATE submissions SET status = 'resolved', updated_at = ? WHERE id = ?", (timestamp, submission_id))
    return jsonify({"ok": True, "message": "Official response saved.", "id": response_id, "published": published}), 201


@app.route("/api/admin/responses/<int:response_id>", methods=["PATCH"])
@admin_required
def update_response(response_id):
    data = request.get_json(silent=True) or {}
    with get_db() as db:
        row = db.execute("SELECT * FROM responses WHERE id = ?", (response_id,)).fetchone()
        if not row:
            return json_error("Response not found.", 404)
        changes, values = [], []
        if "title" in data:
            title = str(data["title"]).strip()
            if not title or len(title) > 160:
                return json_error("Enter a valid response title.")
            changes.append("title = ?"); values.append(title)
        if "body" in data or "response" in data:
            body = str(data.get("body", data.get("response", ""))).strip()
            if not body or len(body) > 5000:
                return json_error("Enter a valid response body.")
            changes.append("body = ?"); values.append(body)
        if "category" in data:
            category = str(data["category"]).strip()
            if len(category) > 100:
                return json_error("Response category is too long.")
            changes.append("category = ?"); values.append(category or "General announcement")
        if "published" in data:
            published = data["published"]
            if not isinstance(published, bool):
                return json_error("Published must be true or false.")
            changes.append("published = ?"); values.append(int(published))
            changes.append("published_at = ?"); values.append(utc_now() if published else None)
        if not changes:
            return json_error("No changes were provided.")
        values.append(response_id)
        db.execute(f"UPDATE responses SET {', '.join(changes)} WHERE id = ?", values)
        updated = db.execute("SELECT * FROM responses WHERE id = ?", (response_id,)).fetchone()
    return jsonify({"ok": True, "message": "Response updated.", "response": dict(updated)})


@app.route("/api/admin/responses/<int:response_id>", methods=["DELETE"])
@admin_required
def delete_response(response_id):
    with get_db() as db:
        cursor = db.execute("DELETE FROM responses WHERE id = ?", (response_id,))
        if cursor.rowcount == 0:
            return json_error("Response not found.", 404)
    return jsonify({"ok": True, "message": "Response deleted."})


# ============================================================
# SECURITY HEADERS / ERROR HANDLERS
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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")),
            debug=os.environ.get("FLASK_DEBUG", "").lower() == "true")
