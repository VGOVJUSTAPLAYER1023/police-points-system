import os
import sqlite3
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import psycopg
    HAS_PSYCOPG = True
except ImportError:
    HAS_PSYCOPG = False

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

RANKS = [
    "Police Officer",
    "Corporal",
    "Sergeant",
    "Lieutenant",
    "Captain",
    "Major",
    "Colonel",
    "Chief of Police",
]

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

def use_postgres():
    return bool(DATABASE_URL and HAS_PSYCOPG)

def db():
    if use_postgres():
        conn = psycopg.connect(DATABASE_URL)
        conn.row_factory = psycopg.rows.dict_row
        return conn
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "police.db"))
    conn.row_factory = sqlite3.Row
    return conn

def qmark(sql):
    return sql.replace("?", "%s") if use_postgres() else sql

def init_db():
    conn = db()
    if use_postgres():
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS personnel (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            rank TEXT NOT NULL,
            points INTEGER NOT NULL DEFAULT 0,
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS point_log (
            id SERIAL PRIMARY KEY,
            personnel_id INTEGER NOT NULL REFERENCES personnel(id) ON DELETE CASCADE,
            amount INTEGER NOT NULL,
            reason TEXT NOT NULL,
            changed_by TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
    else:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS personnel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            rank TEXT NOT NULL,
            points INTEGER NOT NULL DEFAULT 0,
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS point_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            personnel_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            reason TEXT NOT NULL,
            changed_by TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(personnel_id) REFERENCES personnel(id) ON DELETE CASCADE
        );
        """)
    existing = conn.execute(qmark("SELECT 1 FROM users WHERE username = ?"), ("admin",)).fetchone()
    if not existing:
        conn.execute(
            qmark("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)"),
            ("admin", generate_password_hash("ChangeMe123!"), "admin")
        )
    person_exists = conn.execute("SELECT 1 FROM personnel LIMIT 1").fetchone()
    if not person_exists:
        samples = [
            ("Juan Dela Cruz", "Police Officer", 25, "Example record"),
            ("Maria Santos", "Sergeant", 60, "Example record"),
            ("Alex Reyes", "Lieutenant", 95, "Example record"),
        ]
        for row in samples:
            conn.execute(qmark(
                "INSERT INTO personnel (name, rank, points, notes) VALUES (?, ?, ?, ?)"
            ), row)
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("mod_login", next=request.path))
        return f(*args, **kwargs)
    return wrapped

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("mod_login", next=request.path))
            if session.get("role") not in roles:
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for("mod_home"))
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.context_processor
def context():
    return {
        "current_user": session.get("username"),
        "current_role": session.get("role")
    }

# -------- PUBLIC AREA --------

@app.route("/")
def public_home():
    q = request.args.get("q", "").strip()
    conn = db()
    if q:
        people = conn.execute(qmark(
            "SELECT id, name, rank, points FROM personnel "
            "WHERE name LIKE ? OR rank LIKE ? ORDER BY name"
        ), (f"%{q}%", f"%{q}%")).fetchall()
    else:
        people = []
    conn.close()
    return render_template("public.html", people=people, q=q)

@app.route("/personnel/<int:person_id>")
def public_personnel(person_id):
    conn = db()
    person = conn.execute(qmark(
        "SELECT id, name, rank, points, notes FROM personnel WHERE id = ?"
    ), (person_id,)).fetchone()
    conn.close()
    if not person:
        return "Personnel record not found.", 404
    return render_template("public_person.html", person=person)

# -------- MODERATOR AREA --------

@app.route("/mod")
@login_required
def mod_home():
    conn = db()
    people = conn.execute("SELECT * FROM personnel ORDER BY name").fetchall()
    conn.close()
    return render_template("mod.html", people=people, ranks=RANKS)

@app.route("/mod/login", methods=["GET", "POST"])
def mod_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = db()
        user = conn.execute(qmark(
            "SELECT * FROM users WHERE username = ?"
        ), (username,)).fetchone()
        conn.close()
        if user and user["role"] in ("admin", "moderator") and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(request.args.get("next") or url_for("mod_home"))
        flash("Invalid moderator credentials.", "error")
    return render_template("login.html", title="Moderator Login", subtitle="Authorized moderators only.")

@app.route("/admin")
@role_required("admin")
def admin_home():
    conn = db()
    users = conn.execute(
        "SELECT id, username, role, created_at FROM users ORDER BY username"
    ).fetchall()
    conn.close()
    return render_template("admin.html", users=users)

@app.post("/admin/users/add")
@role_required("admin")
def add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "moderator")
    if role not in ("moderator", "viewer"):
        role = "moderator"
    if len(username) < 3 or len(password) < 8:
        flash("Username must be 3+ characters and password 8+ characters.", "error")
        return redirect(url_for("admin_home"))
    conn = db()
    try:
        conn.execute(qmark(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)"
        ), (username, generate_password_hash(password), role))
        conn.commit()
        flash("Access account created.", "success")
    except Exception:
        conn.rollback()
        flash("That username may already exist.", "error")
    finally:
        conn.close()
    return redirect(url_for("admin_home"))

@app.post("/admin/users/<int:user_id>/delete")
@role_required("admin")
def delete_user(user_id):
    if user_id == session["user_id"]:
        flash("You cannot remove your own account.", "error")
        return redirect(url_for("admin_home"))
    conn = db()
    conn.execute(qmark("DELETE FROM users WHERE id = ?"), (user_id,))
    conn.commit()
    conn.close()
    flash("Account removed.", "success")
    return redirect(url_for("admin_home"))

# -------- MODERATOR ACTIONS --------

@app.post("/mod/personnel/add")
@role_required("admin", "moderator")
def add_personnel():
    name = request.form.get("name", "").strip()
    rank = request.form.get("rank", "").strip()
    notes = request.form.get("notes", "").strip()
    if not name or rank not in RANKS:
        flash("Enter a name and choose a valid rank.", "error")
        return redirect(url_for("mod_home"))
    conn = db()
    conn.execute(qmark(
        "INSERT INTO personnel (name, rank, notes) VALUES (?, ?, ?)"
    ), (name, rank, notes))
    conn.commit()
    conn.close()
    flash("Personnel added.", "success")
    return redirect(url_for("mod_home"))

@app.post("/mod/personnel/<int:person_id>/points")
@role_required("admin", "moderator")
def update_points(person_id):
    try:
        amount = int(request.form.get("amount", "0"))
    except ValueError:
        amount = 0
    reason = request.form.get("reason", "").strip()
    if amount == 0 or not reason:
        flash("Enter a non-zero point change and a reason.", "error")
        return redirect(url_for("mod_home"))
    conn = db()
    person = conn.execute(qmark("SELECT * FROM personnel WHERE id = ?"), (person_id,)).fetchone()
    if not person:
        conn.close()
        return "Not found", 404
    new_points = max(0, person["points"] + amount)
    actual_change = new_points - person["points"]
    conn.execute(qmark("UPDATE personnel SET points = ? WHERE id = ?"), (new_points, person_id))
    conn.execute(qmark(
        "INSERT INTO point_log (personnel_id, amount, reason, changed_by) VALUES (?, ?, ?, ?)"
    ), (person_id, actual_change, reason, session["username"]))
    conn.commit()
    conn.close()
    flash(f"Points updated for {person['name']}.", "success")
    return redirect(url_for("mod_home"))

@app.post("/mod/personnel/<int:person_id>/rank")
@role_required("admin", "moderator")
def update_rank(person_id):
    rank = request.form.get("rank", "")
    if rank not in RANKS:
        flash("Invalid rank.", "error")
        return redirect(url_for("mod_home"))
    conn = db()
    conn.execute(qmark("UPDATE personnel SET rank = ? WHERE id = ?"), (rank, person_id))
    conn.commit()
    conn.close()
    flash("Rank updated.", "success")
    return redirect(url_for("mod_home"))

@app.post("/mod/personnel/<int:person_id>/delete")
@role_required("admin", "moderator")
def delete_personnel(person_id):
    conn = db()
    conn.execute(qmark("DELETE FROM point_log WHERE personnel_id = ?"), (person_id,))
    conn.execute(qmark("DELETE FROM personnel WHERE id = ?"), (person_id,))
    conn.commit()
    conn.close()
    flash("Personnel removed.", "success")
    return redirect(url_for("mod_home"))

@app.get("/mod/logout")
def logout():
    session.clear()
    return redirect(url_for("public_home"))

@app.get("/api/search")
def api_search():
    q = request.args.get("q", "").strip()
    conn = db()
    rows = conn.execute(qmark(
        "SELECT id, name, rank, points FROM personnel "
        "WHERE name LIKE ? OR rank LIKE ? ORDER BY name LIMIT 50"
    ), (f"%{q}%", f"%{q}%")).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
