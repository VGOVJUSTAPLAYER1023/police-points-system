import os
import sqlite3
import secrets
from functools import wraps
from io import BytesIO

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
    send_file,
)
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image

try:
    import psycopg
    HAS_PSYCOPG = True
except ImportError:
    HAS_PSYCOPG = False


# =========================================================
# APP CONFIG
# =========================================================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

MAX_PROFILE_IMAGE_BYTES = 5 * 1024 * 1024
PERSONNEL_PER_PAGE = 15


# =========================================================
# ROLES / RANKS / STATUS / DEPARTMENTS
# =========================================================

ROLES = [
    "PNP — Philippine National Police",
    "Government",
    "Management Team",
    "Medical Services",
    "Fire & Rescue",
    "Legal / Justice",
    "Civilian",
    "Criminal",
    "Business / Organization",
    "DPWH — Department of Public Works and Highways",
    "LTO — Land Transportation Office",
    "Media Team",
    "Other",
]

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

STATUSES = [
    "Active",
    "LOA",
    "Suspended",
    "Inactive",
    "Retired",
    "Training",
]

DEPARTMENTS = [
    "Pampanga Police Office",
    "Patrol Unit",
    "Traffic Unit",
    "Investigation Unit",
    "Special Operations",
    "Administration",
    "Internal Affairs",
    "Fire & Rescue",
    "Medical Services",
    "Government",
    "DPWH",
    "LTO",
    "Media Team",
    "Civilian",
    "Other",
]


# =========================================================
# DATABASE
# =========================================================

def use_postgres():
    return bool(DATABASE_URL and HAS_PSYCOPG)


def db():
    if use_postgres():
        conn = psycopg.connect(DATABASE_URL)
        conn.row_factory = psycopg.rows.dict_row
        return conn

    conn = sqlite3.connect(
        os.path.join(os.path.dirname(__file__), "police.db")
    )
    conn.row_factory = sqlite3.Row
    return conn


def qmark(sql):
    """
    Convert SQLite-style ? placeholders to PostgreSQL %s.
    """
    return sql.replace("?", "%s") if use_postgres() else sql


# =========================================================
# DATABASE INITIALIZATION / MIGRATION
# =========================================================

def init_db():
    conn = db()

    if use_postgres():

        # USERS
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # PERSONNEL
        conn.execute("""
            CREATE TABLE IF NOT EXISTS personnel (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                rank TEXT NOT NULL,
                points INTEGER NOT NULL DEFAULT 0,
                notes TEXT DEFAULT '',
                role TEXT DEFAULT 'PNP — Philippine National Police',
                department TEXT DEFAULT 'Pampanga Police Office',
                status TEXT DEFAULT 'Active',
                profile_token TEXT UNIQUE,
                profile_image BYTEA,
                profile_image_mime TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Upgrade existing v1/v2 database
        conn.execute(
            "ALTER TABLE personnel ADD COLUMN IF NOT EXISTS role TEXT "
            "DEFAULT 'PNP — Philippine National Police'"
        )

        conn.execute(
            "ALTER TABLE personnel ADD COLUMN IF NOT EXISTS department TEXT "
            "DEFAULT 'Pampanga Police Office'"
        )

        conn.execute(
            "ALTER TABLE personnel ADD COLUMN IF NOT EXISTS status TEXT "
            "DEFAULT 'Active'"
        )

        conn.execute(
            "ALTER TABLE personnel ADD COLUMN IF NOT EXISTS profile_token TEXT"
        )

        conn.execute(
            "ALTER TABLE personnel ADD COLUMN IF NOT EXISTS profile_image BYTEA"
        )

        conn.execute(
            "ALTER TABLE personnel ADD COLUMN IF NOT EXISTS profile_image_mime TEXT"
        )

        # POINT LOG
        conn.execute("""
            CREATE TABLE IF NOT EXISTS point_log (
                id SERIAL PRIMARY KEY,
                personnel_id INTEGER NOT NULL
                    REFERENCES personnel(id)
                    ON DELETE CASCADE,
                amount INTEGER NOT NULL,
                reason TEXT NOT NULL,
                changed_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # CRIMINAL RECORDS
        conn.execute("""
            CREATE TABLE IF NOT EXISTS criminal_records (
                id SERIAL PRIMARY KEY,
                personnel_id INTEGER NOT NULL
                    REFERENCES personnel(id)
                    ON DELETE CASCADE,
                case_number TEXT DEFAULT '',
                charge TEXT NOT NULL,
                description TEXT DEFAULT '',
                record_status TEXT NOT NULL DEFAULT 'Open',
                case_date TEXT DEFAULT '',
                created_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Give existing personnel a unique profile token
        rows = conn.execute(
            "SELECT id FROM personnel WHERE profile_token IS NULL"
        ).fetchall()

        for row in rows:
            conn.execute(
                "UPDATE personnel SET profile_token = %s WHERE id = %s",
                (secrets.token_urlsafe(24), row["id"])
            )

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS personnel_profile_token_idx
            ON personnel(profile_token)
        """)

    else:

        # USERS
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
                role TEXT DEFAULT 'PNP — Philippine National Police',
                department TEXT DEFAULT 'Pampanga Police Office',
                status TEXT DEFAULT 'Active',
                profile_token TEXT UNIQUE,
                profile_image BLOB,
                profile_image_mime TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS point_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                personnel_id INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                reason TEXT NOT NULL,
                changed_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(personnel_id)
                    REFERENCES personnel(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS criminal_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                personnel_id INTEGER NOT NULL,
                case_number TEXT DEFAULT '',
                charge TEXT NOT NULL,
                description TEXT DEFAULT '',
                record_status TEXT NOT NULL DEFAULT 'Open',
                case_date TEXT DEFAULT '',
                created_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(personnel_id)
                    REFERENCES personnel(id)
                    ON DELETE CASCADE
            );
        """)

        # Upgrade old SQLite personnel table
        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(personnel)"
            ).fetchall()
        }

        migrations = [
            (
                "role",
                "TEXT DEFAULT 'PNP — Philippine National Police'"
            ),
            (
                "department",
                "TEXT DEFAULT 'Pampanga Police Office'"
            ),
            (
                "status",
                "TEXT DEFAULT 'Active'"
            ),
            (
                "profile_token",
                "TEXT"
            ),
            (
                "profile_image",
                "BLOB"
            ),
            (
                "profile_image_mime",
                "TEXT"
            ),
        ]

        for column, definition in migrations:
            if column not in columns:
                conn.execute(
                    f"ALTER TABLE personnel ADD COLUMN {column} {definition}"
                )

        rows = conn.execute(
            "SELECT id FROM personnel WHERE profile_token IS NULL"
        ).fetchall()

        for row in rows:
            conn.execute(
                "UPDATE personnel SET profile_token = ? WHERE id = ?",
                (secrets.token_urlsafe(24), row["id"])
            )

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS personnel_profile_token_idx
            ON personnel(profile_token)
        """)

    # DEFAULT ADMIN
    existing_admin = conn.execute(
        qmark("SELECT 1 FROM users WHERE username = ?"),
        ("admin",)
    ).fetchone()

    if not existing_admin:
        conn.execute(
            qmark("""
                INSERT INTO users
                (username, password_hash, role)
                VALUES (?, ?, ?)
            """),
            (
                "admin",
                generate_password_hash("ChangeMe123!"),
                "admin",
            )
        )

    # SAMPLE DATA ONLY IF EMPTY
    person_exists = conn.execute(
        "SELECT 1 FROM personnel LIMIT 1"
    ).fetchone()

    if not person_exists:

        sample_people = [
            (
                "Juan Dela Cruz",
                "Police Officer",
                25,
                "Example record",
                "PNP — Philippine National Police",
                "Pampanga Police Office",
                "Active",
                secrets.token_urlsafe(24),
            ),
            (
                "Maria Santos",
                "Sergeant",
                60,
                "Example record",
                "PNP — Philippine National Police",
                "Investigation Unit",
                "Active",
                secrets.token_urlsafe(24),
            ),
            (
                "Alex Reyes",
                "Lieutenant",
                95,
                "Example record",
                "Government",
                "Administration",
                "Active",
                secrets.token_urlsafe(24),
            ),
        ]

        for person in sample_people:
            conn.execute(
                qmark("""
                    INSERT INTO personnel
                    (
                        name,
                        rank,
                        points,
                        notes,
                        role,
                        department,
                        status,
                        profile_token
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """),
                person
            )

    conn.commit()
    conn.close()


# =========================================================
# AUTHORIZATION
# =========================================================

def login_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):

        if not session.get("user_id"):
            return redirect(
                url_for(
                    "mod_login",
                    next=request.path
                )
            )

        return function(*args, **kwargs)

    return wrapped


def role_required(*roles):
    def decorator(function):

        @wraps(function)
        def wrapped(*args, **kwargs):

            if not session.get("user_id"):
                return redirect(
                    url_for(
                        "mod_login",
                        next=request.path
                    )
                )

            if session.get("role") not in roles:

                flash(
                    "You do not have permission to access this page.",
                    "error"
                )

                return redirect(
                    url_for("mod_home")
                )

            return function(*args, **kwargs)

        return wrapped

    return decorator


@app.context_processor
def context():
    return {
        "current_user": session.get("username"),
        "current_role": session.get("role"),
        "roles": ROLES,
        "ranks": RANKS,
        "statuses": STATUSES,
        "departments": DEPARTMENTS,
    }


# =========================================================
# PUBLIC SEARCH
# =========================================================

@app.route("/")
def public_home():

    q = request.args.get("q", "").strip()

    selected_role = request.args.get("role", "").strip()
    selected_department = request.args.get(
        "department", ""
    ).strip()
    selected_rank = request.args.get(
        "rank", ""
    ).strip()
    selected_status = request.args.get(
        "status", ""
    ).strip()

    try:
        page = max(
            1,
            int(request.args.get("page", "1"))
        )
    except ValueError:
        page = 1

    offset = (page - 1) * PERSONNEL_PER_PAGE

    conn = db()

    conditions = []
    params = []

    # CASE-INSENSITIVE SEARCH
    if q:

        search_value = f"%{q}%"

        conditions.append("""
            (
                LOWER(name) LIKE LOWER(?)
                OR LOWER(rank) LIKE LOWER(?)
                OR LOWER(role) LIKE LOWER(?)
                OR LOWER(department) LIKE LOWER(?)
            )
        """)

        params.extend([
            search_value,
            search_value,
            search_value,
            search_value,
        ])

    if selected_role:
        conditions.append("role = ?")
        params.append(selected_role)

    if selected_department:
        conditions.append("department = ?")
        params.append(selected_department)

    if selected_rank:
        conditions.append("rank = ?")
        params.append(selected_rank)

    if selected_status:
        conditions.append("status = ?")
        params.append(selected_status)

    where_clause = ""

    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    total_row = conn.execute(
        qmark(
            f"""
            SELECT COUNT(*) AS total
            FROM personnel
            {where_clause}
            """
        ),
        tuple(params),
    ).fetchone()

    total = total_row["total"]

    people = conn.execute(
        qmark(
            f"""
            SELECT
                id,
                name,
                rank,
                points,
                role,
                department,
                status
            FROM personnel
            {where_clause}
            ORDER BY name COLLATE NOCASE
            LIMIT ? OFFSET ?
            """
        ),
        tuple(params) + (
            PERSONNEL_PER_PAGE,
            offset,
        ),
    ).fetchall()

    conn.close()

    total_pages = max(
        1,
        (total + PERSONNEL_PER_PAGE - 1)
        // PERSONNEL_PER_PAGE
    )

    return render_template(
        "public.html",
        people=people,
        q=q,
        page=page,
        total_pages=total_pages,
        total=total,
        selected_role=selected_role,
        selected_department=selected_department,
        selected_rank=selected_rank,
        selected_status=selected_status,
    )


# =========================================================
# PUBLIC PROFILE
# =========================================================

@app.route("/personnel/<int:person_id>")
def public_personnel(person_id):

    conn = db()

    person = conn.execute(
        qmark("""
            SELECT
                id,
                name,
                rank,
                points,
                notes,
                role,
                department,
                status
            FROM personnel
            WHERE id = ?
        """),
        (person_id,),
    ).fetchone()

    if not person:
        conn.close()
        return "Personnel record not found.", 404

    criminal_records = conn.execute(
        qmark("""
            SELECT
                id,
                case_number,
                charge,
                description,
                record_status,
                case_date,
                created_by,
                created_at
            FROM criminal_records
            WHERE personnel_id = ?
            ORDER BY created_at DESC, id DESC
        """),
        (person_id,),
    ).fetchall()

    conn.close()

    return render_template(
        "public_person.html",
        person=person,
        criminal_records=criminal_records,
    )


# =========================================================
# PROFILE PICTURE
# =========================================================

@app.route("/profile-image/<int:person_id>")
def profile_image(person_id):

    conn = db()

    row = conn.execute(
        qmark("""
            SELECT
                profile_image,
                profile_image_mime
            FROM personnel
            WHERE id = ?
        """),
        (person_id,),
    ).fetchone()

    conn.close()

    if not row or not row["profile_image"]:
        return "", 404

    return send_file(
        BytesIO(bytes(row["profile_image"])),
        mimetype=row["profile_image_mime"] or "image/jpeg",
        max_age=300,
    )


@app.post("/mod/personnel/<int:person_id>/profile")
@role_required("admin", "moderator")
def upload_profile_picture(person_id):

    file = request.files.get("photo")

    if not file or not file.filename:

        flash(
            "Please choose a profile picture.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    raw = file.read(
        MAX_PROFILE_IMAGE_BYTES + 1
    )

    if len(raw) > MAX_PROFILE_IMAGE_BYTES:

        flash(
            "Profile picture must be 5 MB or smaller.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    try:

        image = Image.open(
            BytesIO(raw)
        )

        image.verify()

        image = Image.open(
            BytesIO(raw)
        ).convert("RGB")

    except Exception:

        flash(
            "Invalid image. Please upload JPG, PNG, or WebP.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    # Resize for database efficiency
    image.thumbnail(
        (700, 700),
        Image.Resampling.LANCZOS
    )

    output = BytesIO()

    image.save(
        output,
        format="JPEG",
        quality=88,
        optimize=True,
    )

    image_bytes = output.getvalue()

    conn = db()

    exists = conn.execute(
        qmark(
            "SELECT id FROM personnel WHERE id = ?"
        ),
        (person_id,),
    ).fetchone()

    if not exists:

        conn.close()

        flash(
            "Personnel record not found.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    conn.execute(
        qmark("""
            UPDATE personnel
            SET
                profile_image = ?,
                profile_image_mime = ?
            WHERE id = ?
        """),
        (
            image_bytes,
            "image/jpeg",
            person_id,
        ),
    )

    conn.commit()
    conn.close()

    flash(
        "Profile picture updated.",
        "success"
    )

    return redirect(
        url_for("mod_home")
    )


@app.post("/mod/personnel/<int:person_id>/profile/remove")
@role_required("admin", "moderator")
def remove_profile_picture(person_id):

    conn = db()

    conn.execute(
        qmark("""
            UPDATE personnel
            SET
                profile_image = NULL,
                profile_image_mime = NULL
            WHERE id = ?
        """),
        (person_id,),
    )

    conn.commit()
    conn.close()

    flash(
        "Profile picture removed.",
        "success"
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# MODERATOR AREA
# =========================================================

@app.route("/mod")
@login_required
def mod_home():

    conn = db()

    people = conn.execute(
        """
        SELECT
            id,
            name,
            rank,
            points,
            role,
            department,
            status,
            profile_token
        FROM personnel
        ORDER BY name
        """
    ).fetchall()

    conn.close()

    return render_template(
        "mod.html",
        people=people,
    )


@app.route(
    "/mod/login",
    methods=["GET", "POST"]
)
def mod_login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        conn = db()

        user = conn.execute(
            qmark("""
                SELECT *
                FROM users
                WHERE username = ?
            """),
            (username,),
        ).fetchone()

        conn.close()

        if (
            user
            and user["role"]
            in ("admin", "moderator")
            and check_password_hash(
                user["password_hash"],
                password,
            )
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            return redirect(
                request.args.get("next")
                or url_for("mod_home")
            )

        flash(
            "Invalid moderator credentials.",
            "error"
        )

    return render_template(
        "login.html",
        title="Moderator Login",
        subtitle="Authorized moderators only.",
    )


# =========================================================
# ADMIN AREA
# =========================================================

@app.route("/admin")
@role_required("admin")
def admin_home():

    conn = db()

    users = conn.execute(
        """
        SELECT
            id,
            username,
            role,
            created_at
        FROM users
        ORDER BY username
        """
    ).fetchall()

    people = conn.execute(
        """
        SELECT
            id,
            name,
            rank,
            role,
            department,
            status
        FROM personnel
        ORDER BY name
        """
    ).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        users=users,
        people=people,
    )


@app.post("/admin/users/add")
@role_required("admin")
def add_user():

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    role = request.form.get(
        "role",
        "moderator"
    )

    if role not in (
        "moderator",
        "viewer",
    ):
        role = "moderator"

    if (
        len(username) < 3
        or len(password) < 8
    ):

        flash(
            "Username must be at least 3 characters and password at least 8 characters.",
            "error",
        )

        return redirect(
            url_for("admin_home")
        )

    conn = db()

    try:

        conn.execute(
            qmark("""
                INSERT INTO users
                (
                    username,
                    password_hash,
                    role
                )
                VALUES (?, ?, ?)
            """),
            (
                username,
                generate_password_hash(password),
                role,
            ),
        )

        conn.commit()

        flash(
            "Access account created.",
            "success",
        )

    except Exception:

        conn.rollback()

        flash(
            "That username may already exist.",
            "error",
        )

    finally:

        conn.close()

    return redirect(
        url_for("admin_home")
    )


@app.post("/admin/users/<int:user_id>/delete")
@role_required("admin")
def delete_user(user_id):

    if user_id == session["user_id"]:

        flash(
            "You cannot remove your own account.",
            "error",
        )

        return redirect(
            url_for("admin_home")
        )

    conn = db()

    conn.execute(
        qmark(
            "DELETE FROM users WHERE id = ?"
        ),
        (user_id,),
    )

    conn.commit()
    conn.close()

    flash(
        "Account removed.",
        "success",
    )

    return redirect(
        url_for("admin_home")
    )


# =========================================================
# ADD PERSONNEL
# =========================================================

@app.post("/mod/personnel/add")
@role_required("admin", "moderator")
def add_personnel():

    name = request.form.get(
        "name",
        ""
    ).strip()

    rank = request.form.get(
        "rank",
        ""
    ).strip()

    role = request.form.get(
        "role",
        "PNP — Philippine National Police"
    ).strip()

    department = request.form.get(
        "department",
        "Pampanga Police Office"
    ).strip()

    status = request.form.get(
        "status",
        "Active"
    ).strip()

    notes = request.form.get(
        "notes",
        ""
    ).strip()

    if not name:
        flash(
            "Name is required.",
            "error"
        )
        return redirect(
            url_for("mod_home")
        )

    if rank not in RANKS:
        flash(
            "Invalid rank.",
            "error"
        )
        return redirect(
            url_for("mod_home")
        )

    if role not in ROLES:
        flash(
            "Invalid role.",
            "error"
        )
        return redirect(
            url_for("mod_home")
        )

    if department not in DEPARTMENTS:
        flash(
            "Invalid department.",
            "error"
        )
        return redirect(
            url_for("mod_home")
        )

    if status not in STATUSES:
        flash(
            "Invalid status.",
            "error"
        )
        return redirect(
            url_for("mod_home")
        )

    conn = db()

    conn.execute(
        qmark("""
            INSERT INTO personnel
            (
                name,
                rank,
                points,
                notes,
                role,
                department,
                status,
                profile_token
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """),
        (
            name,
            rank,
            0,
            notes,
            role,
            department,
            status,
            secrets.token_urlsafe(24),
        ),
    )

    conn.commit()
    conn.close()

    flash(
        "Personnel added.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# UPDATE POINTS
# =========================================================

@app.post("/mod/personnel/<int:person_id>/points")
@role_required("admin", "moderator")
def update_points(person_id):

    try:
        amount = int(
            request.form.get(
                "amount",
                "0"
            )
        )
    except ValueError:
        amount = 0

    reason = request.form.get(
        "reason",
        ""
    ).strip()

    if amount == 0:

        flash(
            "Point change cannot be zero.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    if not reason:

        flash(
            "A reason is required.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    conn = db()

    person = conn.execute(
        qmark(
            "SELECT * FROM personnel WHERE id = ?"
        ),
        (person_id,),
    ).fetchone()

    if not person:

        conn.close()

        return "Personnel not found.", 404

    new_points = max(
        0,
        person["points"] + amount
    )

    actual_change = (
        new_points - person["points"]
    )

    conn.execute(
        qmark("""
            UPDATE personnel
            SET points = ?
            WHERE id = ?
        """),
        (
            new_points,
            person_id,
        ),
    )

    conn.execute(
        qmark("""
            INSERT INTO point_log
            (
                personnel_id,
                amount,
                reason,
                changed_by
            )
            VALUES (?, ?, ?, ?)
        """),
        (
            person_id,
            actual_change,
            reason,
            session["username"],
        ),
    )

    conn.commit()
    conn.close()

    flash(
        f"Points updated for {person['name']}.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# UPDATE RANK
# =========================================================

@app.post("/mod/personnel/<int:person_id>/rank")
@role_required("admin", "moderator")
def update_rank(person_id):

    rank = request.form.get(
        "rank",
        ""
    ).strip()

    if rank not in RANKS:

        flash(
            "Invalid rank.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    conn = db()

    conn.execute(
        qmark("""
            UPDATE personnel
            SET rank = ?
            WHERE id = ?
        """),
        (
            rank,
            person_id,
        ),
    )

    conn.commit()
    conn.close()

    flash(
        "Rank updated.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# UPDATE ROLE
# =========================================================

@app.post("/mod/personnel/<int:person_id>/role")
@role_required("admin", "moderator")
def update_role(person_id):

    role = request.form.get(
        "role",
        ""
    ).strip()

    if role not in ROLES:

        flash(
            "Invalid role.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    conn = db()

    conn.execute(
        qmark("""
            UPDATE personnel
            SET role = ?
            WHERE id = ?
        """),
        (
            role,
            person_id,
        ),
    )

    conn.commit()
    conn.close()

    flash(
        "Role updated.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# UPDATE DEPARTMENT
# =========================================================

@app.post("/mod/personnel/<int:person_id>/department")
@role_required("admin", "moderator")
def update_department(person_id):

    department = request.form.get(
        "department",
        ""
    ).strip()

    if department not in DEPARTMENTS:

        flash(
            "Invalid department.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    conn = db()

    conn.execute(
        qmark("""
            UPDATE personnel
            SET department = ?
            WHERE id = ?
        """),
        (
            department,
            person_id,
        ),
    )

    conn.commit()
    conn.close()

    flash(
        "Department updated.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# UPDATE STATUS
# =========================================================

@app.post("/mod/personnel/<int:person_id>/status")
@role_required("admin", "moderator")
def update_status(person_id):

    status = request.form.get(
        "status",
        ""
    ).strip()

    if status not in STATUSES:

        flash(
            "Invalid status.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    conn = db()

    conn.execute(
        qmark("""
            UPDATE personnel
            SET status = ?
            WHERE id = ?
        """),
        (
            status,
            person_id,
        ),
    )

    conn.commit()
    conn.close()

    flash(
        "Status updated.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# CRIMINAL RECORDS
# =========================================================

@app.post("/mod/personnel/<int:person_id>/criminal/add")
@role_required("admin", "moderator")
def add_criminal_record(person_id):

    case_number = request.form.get(
        "case_number",
        ""
    ).strip()

    charge = request.form.get(
        "charge",
        ""
    ).strip()

    description = request.form.get(
        "description",
        ""
    ).strip()

    record_status = request.form.get(
        "record_status",
        "Open"
    ).strip()

    case_date = request.form.get(
        "case_date",
        ""
    ).strip()

    if not charge:

        flash(
            "Charge is required.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    conn = db()

    person = conn.execute(
        qmark(
            "SELECT id FROM personnel WHERE id = ?"
        ),
        (person_id,),
    ).fetchone()

    if not person:

        conn.close()

        return "Personnel not found.", 404

    conn.execute(
        qmark("""
            INSERT INTO criminal_records
            (
                personnel_id,
                case_number,
                charge,
                description,
                record_status,
                case_date,
                created_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """),
        (
            person_id,
            case_number,
            charge,
            description,
            record_status,
            case_date,
            session["username"],
        ),
    )

    conn.commit()
    conn.close()

    flash(
        "Criminal record added.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


@app.post("/mod/criminal/<int:record_id>/delete")
@role_required("admin", "moderator")
def delete_criminal_record(record_id):

    conn = db()

    conn.execute(
        qmark(
            "DELETE FROM criminal_records WHERE id = ?"
        ),
        (record_id,),
    )

    conn.commit()
    conn.close()

    flash(
        "Criminal record removed.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# DELETE PERSONNEL
# =========================================================

@app.post("/mod/personnel/<int:person_id>/delete")
@role_required("admin", "moderator")
def delete_personnel(person_id):

    conn = db()

    conn.execute(
        qmark(
            "DELETE FROM criminal_records WHERE personnel_id = ?"
        ),
        (person_id,),
    )

    conn.execute(
        qmark(
            "DELETE FROM point_log WHERE personnel_id = ?"
        ),
        (person_id,),
    )

    conn.execute(
        qmark(
            "DELETE FROM personnel WHERE id = ?"
        ),
        (person_id,),
    )

    conn.commit()
    conn.close()

    flash(
        "Personnel removed.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# LOGOUT
# =========================================================

@app.get("/mod/logout")
def logout():

    session.clear()

    return redirect(
        url_for("public_home")
    )


# =========================================================
# API SEARCH
# =========================================================

@app.get("/api/search")
def api_search():

    q = request.args.get(
        "q",
        ""
    ).strip()

    conn = db()

    if q:

        search_value = f"%{q}%"

        rows = conn.execute(
            qmark("""
                SELECT
                    id,
                    name,
                    rank,
                    points,
                    role,
                    department,
                    status
                FROM personnel
                WHERE
                    LOWER(name) LIKE LOWER(?)
                    OR LOWER(rank) LIKE LOWER(?)
                    OR LOWER(role) LIKE LOWER(?)
                    OR LOWER(department) LIKE LOWER(?)
                ORDER BY name COLLATE NOCASE
                LIMIT 50
            """),
            (
                search_value,
                search_value,
                search_value,
                search_value,
            ),
        ).fetchall()

    else:

        rows = conn.execute(
            """
            SELECT
                id,
                name,
                rank,
                points,
                role,
                department,
                status
            FROM personnel
            ORDER BY name COLLATE NOCASE
            LIMIT 50
            """
        ).fetchall()

    conn.close()

    return jsonify([
        dict(row)
        for row in rows
    ])


# =========================================================
# STARTUP
# =========================================================

with app.app_context():
    init_db()


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=True,
    )
