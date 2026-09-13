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

# =========================================================
# OPTIONAL POSTGRESQL
# =========================================================

try:
    import psycopg

    HAS_PSYCOPG = True

except ImportError:
    HAS_PSYCOPG = False


# =========================================================
# APP CONFIG
# =========================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key"
)

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    ""
).strip()

MAX_PROFILE_IMAGE_SIZE = 5 * 1024 * 1024
PERSONNEL_PER_PAGE = 15


# =========================================================
# ROLES
# =========================================================

ROLES = [
    "PNP — Philippine National Police",
    "Government",
    "Management Team",
    "BFP — Bureau of Fire Protection",
    "Medical Services",
    "Legal / Justice",
    "Civilian",
    "Criminal",
    "Business / Organization",
    "DPWH — Department of Public Works and Highways",
    "LTO — Land Transportation Office",
    "Media Team",
    "Other",
]


# =========================================================
# COMBINED RANKS
# =========================================================

RANKS = [

    # PNP
    "Police Officer",
    "Corporal",
    "Sergeant",
    "Lieutenant",
    "Captain",
    "Major",
    "Colonel",
    "Chief of Police",

    # Government
    "Governor",
    "Vice Governor",
    "Mayor",
    "Vice Mayor",
    "Municipal Executive",
    "Judge",
    "Vice Judge",
    "Lawyer",

    # Management
    "Owner",
    "Co-Owner",
    "Management",
    "Supervisor",

    # BFP
    "Fire Director",
    "Fire Chief Superintendent",
    "Fire Senior Superintendent",
    "Fire Superintendent",
    "Fire Chief Inspector",
    "Fire Senior Inspector",
    "Fire Inspector",
    "Senior Fire Officer",
    "Fire Officer 3",
    "Fire Officer 2",
    "Fire Officer 1",

    # General / Other
    "Staff",
    "Employee",
    "Director",
    "Officer",
    "Member",
    "Manager",
    "Representative",
    "Citizen",
    "None",
]


# =========================================================
# STATUS
# =========================================================

STATUSES = [
    "Active",
    "LOA",
    "Suspended",
    "Inactive",
    "Retired",
    "Training",
]


# =========================================================
# DEPARTMENTS
# =========================================================

DEPARTMENTS = [
    "Pampanga Police Office",
    "Patrol Unit",
    "Traffic Unit",
    "Investigation Unit",
    "Special Operations",
    "Administration",
    "Internal Affairs",
    "BFP",
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
    return bool(
        DATABASE_URL and HAS_PSYCOPG
    )


def db():
    if use_postgres():

        connection = psycopg.connect(
            DATABASE_URL
        )

        connection.row_factory = psycopg.rows.dict_row

        return connection

    connection = sqlite3.connect(
        os.path.join(
            os.path.dirname(__file__),
            "police.db"
        )
    )

    connection.row_factory = sqlite3.Row

    return connection


def sql(query):
    """
    Convert SQLite ? placeholders into
    PostgreSQL %s placeholders.
    """

    if use_postgres():
        return query.replace("?", "%s")

    return query


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def init_db():

    connection = db()

    # =====================================================
    # POSTGRESQL
    # =====================================================

    if use_postgres():

        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
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
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS point_log (
                id SERIAL PRIMARY KEY,
                personnel_id INTEGER NOT NULL
                    REFERENCES personnel(id)
                    ON DELETE CASCADE,
                amount INTEGER NOT NULL,
                reason TEXT NOT NULL,
                changed_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
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
            )
        """)

        # Existing database upgrades

        connection.execute("""
            ALTER TABLE personnel
            ADD COLUMN IF NOT EXISTS role TEXT
            DEFAULT 'PNP — Philippine National Police'
        """)

        connection.execute("""
            ALTER TABLE personnel
            ADD COLUMN IF NOT EXISTS department TEXT
            DEFAULT 'Pampanga Police Office'
        """)

        connection.execute("""
            ALTER TABLE personnel
            ADD COLUMN IF NOT EXISTS status TEXT
            DEFAULT 'Active'
        """)

        connection.execute("""
            ALTER TABLE personnel
            ADD COLUMN IF NOT EXISTS profile_token TEXT
        """)

        connection.execute("""
            ALTER TABLE personnel
            ADD COLUMN IF NOT EXISTS profile_image BYTEA
        """)

        connection.execute("""
            ALTER TABLE personnel
            ADD COLUMN IF NOT EXISTS profile_image_mime TEXT
        """)

        missing_tokens = connection.execute("""
            SELECT id
            FROM personnel
            WHERE profile_token IS NULL
        """).fetchall()

        for person in missing_tokens:

            token = secrets.token_urlsafe(32)

            connection.execute(
                """
                UPDATE personnel
                SET profile_token = %s
                WHERE id = %s
                """,
                (
                    token,
                    person["id"],
                )
            )

        connection.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            personnel_profile_token_index
            ON personnel(profile_token)
        """)

    # =====================================================
    # SQLITE
    # =====================================================

    else:

        connection.executescript("""
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

        columns = {
            row["name"]
            for row in connection.execute(
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

                connection.execute(
                    f"""
                    ALTER TABLE personnel
                    ADD COLUMN {column} {definition}
                    """
                )

        missing_tokens = connection.execute("""
            SELECT id
            FROM personnel
            WHERE profile_token IS NULL
        """).fetchall()

        for person in missing_tokens:

            token = secrets.token_urlsafe(32)

            connection.execute(
                """
                UPDATE personnel
                SET profile_token = ?
                WHERE id = ?
                """,
                (
                    token,
                    person["id"],
                )
            )

        connection.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            personnel_profile_token_index
            ON personnel(profile_token)
        """)

    # =====================================================
    # DEFAULT ADMIN
    # =====================================================

    admin_exists = connection.execute(
        sql("""
            SELECT 1
            FROM users
            WHERE username = ?
        """),
        ("admin",),
    ).fetchone()

    if not admin_exists:

        connection.execute(
            sql("""
                INSERT INTO users
                (
                    username,
                    password_hash,
                    role
                )
                VALUES (?, ?, ?)
            """),
            (
                "admin",
                generate_password_hash(
                    "ChangeMe123!"
                ),
                "admin",
            ),
        )

    # =====================================================
    # SAMPLE RECORDS IF EMPTY
    # =====================================================

    has_people = connection.execute(
        """
        SELECT 1
        FROM personnel
        LIMIT 1
        """
    ).fetchone()

    if not has_people:

        sample_people = [

            (
                "Juan Dela Cruz",
                "Police Officer",
                25,
                "Example record",
                "PNP — Philippine National Police",
                "Pampanga Police Office",
                "Active",
                secrets.token_urlsafe(32),
            ),

            (
                "Maria Santos",
                "Sergeant",
                60,
                "Example record",
                "PNP — Philippine National Police",
                "Investigation Unit",
                "Active",
                secrets.token_urlsafe(32),
            ),

            (
                "Alex Reyes",
                "Governor",
                95,
                "Example record",
                "Government",
                "Government",
                "Active",
                secrets.token_urlsafe(32),
            ),

        ]

        for person in sample_people:

            connection.execute(
                sql("""
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
                person,
            )

    connection.commit()
    connection.close()


# =========================================================
# AUTHORIZATION
# =========================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("user_id"):

            return redirect(
                url_for(
                    "mod_login",
                    next=request.path
                )
            )

        return function(
            *args,
            **kwargs
        )

    return wrapper


def role_required(*allowed_roles):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            if not session.get("user_id"):

                return redirect(
                    url_for(
                        "mod_login",
                        next=request.path
                    )
                )

            if session.get("role") not in allowed_roles:

                flash(
                    "You do not have permission to access this page.",
                    "error",
                )

                return redirect(
                    url_for("mod_home")
                )

            return function(
                *args,
                **kwargs
            )

        return wrapper

    return decorator


@app.context_processor
def inject_context():

    return {
        "current_user":
            session.get("username"),

        "current_role":
            session.get("role"),

        "roles":
            ROLES,

        "ranks":
            RANKS,

        "statuses":
            STATUSES,

        "departments":
            DEPARTMENTS,
    }


# =========================================================
# PUBLIC SEARCH
# =========================================================

@app.route("/")
def public_home():

    search = request.args.get(
        "q",
        ""
    ).strip()

    selected_role = request.args.get(
        "role",
        ""
    ).strip()

    selected_department = request.args.get(
        "department",
        ""
    ).strip()

    selected_rank = request.args.get(
        "rank",
        ""
    ).strip()

    selected_status = request.args.get(
        "status",
        ""
    ).strip()

    try:

        page = int(
            request.args.get(
                "page",
                "1"
            )
        )

    except ValueError:

        page = 1

    page = max(
        page,
        1
    )

    offset = (
        page - 1
    ) * PERSONNEL_PER_PAGE

    connection = db()

    conditions = []
    params = []

    # CASE-INSENSITIVE SEARCH

    if search:

        value = f"%{search}%"

        conditions.append("""
            (
                LOWER(name) LIKE LOWER(?)
                OR LOWER(rank) LIKE LOWER(?)
                OR LOWER(role) LIKE LOWER(?)
                OR LOWER(department) LIKE LOWER(?)
            )
        """)

        params.extend([
            value,
            value,
            value,
            value,
        ])

    # FILTERS

    if selected_role:

        conditions.append(
            "role = ?"
        )

        params.append(
            selected_role
        )

    if selected_department:

        conditions.append(
            "department = ?"
        )

        params.append(
            selected_department
        )

    if selected_rank:

        conditions.append(
            "rank = ?"
        )

        params.append(
            selected_rank
        )

    if selected_status:

        conditions.append(
            "status = ?"
        )

        params.append(
            selected_status
        )

    where_clause = ""

    if conditions:

        where_clause = (
            "WHERE "
            + " AND ".join(
                conditions
            )
        )

    # TOTAL RECORDS

    total_row = connection.execute(
        sql(
            f"""
                SELECT COUNT(*) AS total
                FROM personnel
                {where_clause}
            """
        ),
        tuple(params),
    ).fetchone()

    total = total_row["total"]

    # RECORDS

    people = connection.execute(
        sql(
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
                ORDER BY LOWER(name)
                LIMIT ? OFFSET ?
            """
        ),
        tuple(params)
        + (
            PERSONNEL_PER_PAGE,
            offset,
        ),
    ).fetchall()

    connection.close()

    total_pages = max(
        1,
        (
            total
            + PERSONNEL_PER_PAGE
            - 1
        )
        // PERSONNEL_PER_PAGE
    )

    return render_template(
        "public.html",
        people=people,
        q=search,
        page=page,
        total=total,
        total_pages=total_pages,
        selected_role=selected_role,
        selected_department=selected_department,
        selected_rank=selected_rank,
        selected_status=selected_status,
    )


# =========================================================
# PUBLIC PROFILE
# =========================================================

@app.route(
    "/personnel/<int:person_id>"
)
def public_personnel(person_id):

    connection = db()

    person = connection.execute(
        sql("""
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
        (
            person_id,
        ),
    ).fetchone()

    if not person:

        connection.close()

        return (
            "Personnel record not found.",
            404,
        )

    criminal_records = connection.execute(
        sql("""
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
            ORDER BY created_at DESC
        """),
        (
            person_id,
        ),
    ).fetchall()

    connection.close()

    return render_template(
        "public_person.html",
        person=person,
        criminal_records=criminal_records,
    )


# =========================================================
# PROFILE IMAGE
# =========================================================

@app.route(
    "/profile-image/<int:person_id>"
)
def profile_image(person_id):

    connection = db()

    image = connection.execute(
        sql("""
            SELECT
                profile_image,
                profile_image_mime
            FROM personnel
            WHERE id = ?
        """),
        (
            person_id,
        ),
    ).fetchone()

    connection.close()

    if not image:
        return "", 404

    if not image["profile_image"]:
        return "", 404

    return send_file(
        BytesIO(
            bytes(
                image["profile_image"]
            )
        ),
        mimetype=(
            image["profile_image_mime"]
            or "image/jpeg"
        ),
        max_age=300,
    )


# =========================================================
# MODERATOR LOGIN
# =========================================================

@app.route(
    "/mod/login",
    methods=[
        "GET",
        "POST",
    ],
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

        connection = db()

        user = connection.execute(
            sql("""
                SELECT *
                FROM users
                WHERE username = ?
            """),
            (
                username,
            ),
        ).fetchone()

        connection.close()

        if (
            user
            and user["role"]
            in (
                "admin",
                "moderator",
            )
            and check_password_hash(
                user["password_hash"],
                password,
            )
        ):

            session.clear()

            session["user_id"] = (
                user["id"]
            )

            session["username"] = (
                user["username"]
            )

            session["role"] = (
                user["role"]
            )

            return redirect(
                request.args.get(
                    "next"
                )
                or url_for(
                    "mod_home"
                )
            )

        flash(
            "Invalid moderator credentials.",
            "error",
        )

    return render_template(
        "login.html",
        title="Moderator Login",
        subtitle="Authorized moderators only.",
    )


# =========================================================
# MODERATOR HOME
# =========================================================

@app.route("/mod")
@login_required
def mod_home():

    connection = db()

    people = connection.execute(
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
        ORDER BY LOWER(name)
        """
    ).fetchall()

    connection.close()

    return render_template(
        "mod.html",
        people=people,
    )


# =========================================================
# ADD PERSONNEL
# =========================================================

@app.post(
    "/mod/personnel/add"
)
@role_required(
    "admin",
    "moderator",
)
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
        ""
    ).strip()

    department = request.form.get(
        "department",
        ""
    ).strip()

    status = request.form.get(
        "status",
        ""
    ).strip()

    notes = request.form.get(
        "notes",
        ""
    ).strip()

    if not name:

        flash(
            "Name is required.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    if rank not in RANKS:

        flash(
            "Invalid rank.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    if role not in ROLES:

        flash(
            "Invalid role.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    if department not in DEPARTMENTS:

        flash(
            "Invalid department.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    if status not in STATUSES:

        flash(
            "Invalid status.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    connection = db()

    connection.execute(
        sql("""
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
            secrets.token_urlsafe(32),
        ),
    )

    connection.commit()
    connection.close()

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

@app.post(
    "/mod/personnel/<int:person_id>/points"
)
@role_required(
    "admin",
    "moderator",
)
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

    connection = db()

    person = connection.execute(
        sql("""
            SELECT *
            FROM personnel
            WHERE id = ?
        """),
        (
            person_id,
        ),
    ).fetchone()

    if not person:

        connection.close()

        return (
            "Personnel not found.",
            404,
        )

    new_points = max(
        0,
        person["points"]
        + amount,
    )

    actual_change = (
        new_points
        - person["points"]
    )

    connection.execute(
        sql("""
            UPDATE personnel
            SET points = ?
            WHERE id = ?
        """),
        (
            new_points,
            person_id,
        ),
    )

    connection.execute(
        sql("""
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

    connection.commit()
    connection.close()

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

@app.post(
    "/mod/personnel/<int:person_id>/rank"
)
@role_required(
    "admin",
    "moderator",
)
def update_rank(person_id):

    rank = request.form.get(
        "rank",
        ""
    ).strip()

    if rank not in RANKS:

        flash(
            "Invalid rank.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    connection = db()

    connection.execute(
        sql("""
            UPDATE personnel
            SET rank = ?
            WHERE id = ?
        """),
        (
            rank,
            person_id,
        ),
    )

    connection.commit()
    connection.close()

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

@app.post(
    "/mod/personnel/<int:person_id>/role"
)
@role_required(
    "admin",
    "moderator",
)
def update_role(person_id):

    role = request.form.get(
        "role",
        ""
    ).strip()

    if role not in ROLES:

        flash(
            "Invalid role.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    connection = db()

    connection.execute(
        sql("""
            UPDATE personnel
            SET role = ?
            WHERE id = ?
        """),
        (
            role,
            person_id,
        ),
    )

    connection.commit()
    connection.close()

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

@app.post(
    "/mod/personnel/<int:person_id>/department"
)
@role_required(
    "admin",
    "moderator",
)
def update_department(person_id):

    department = request.form.get(
        "department",
        ""
    ).strip()

    if department not in DEPARTMENTS:

        flash(
            "Invalid department.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    connection = db()

    connection.execute(
        sql("""
            UPDATE personnel
            SET department = ?
            WHERE id = ?
        """),
        (
            department,
            person_id,
        ),
    )

    connection.commit()
    connection.close()

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

@app.post(
    "/mod/personnel/<int:person_id>/status"
)
@role_required(
    "admin",
    "moderator",
)
def update_status(person_id):

    status = request.form.get(
        "status",
        ""
    ).strip()

    if status not in STATUSES:

        flash(
            "Invalid status.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    connection = db()

    connection.execute(
        sql("""
            UPDATE personnel
            SET status = ?
            WHERE id = ?
        """),
        (
            status,
            person_id,
        ),
    )

    connection.commit()
    connection.close()

    flash(
        "Status updated.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# PROFILE PICTURE UPLOAD
# =========================================================

@app.post(
    "/mod/personnel/<int:person_id>/profile"
)
@role_required(
    "admin",
    "moderator",
)
def upload_profile_picture(person_id):

    photo = request.files.get(
        "photo"
    )

    if not photo or not photo.filename:

        flash(
            "Please select a profile picture.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    raw = photo.read(
        MAX_PROFILE_IMAGE_SIZE + 1
    )

    if len(raw) > MAX_PROFILE_IMAGE_SIZE:

        flash(
            "The profile picture must be 5 MB or smaller.",
            "error",
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
            "Invalid image. Please use JPG, PNG, or WebP.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    image.thumbnail(
        (
            700,
            700,
        ),
        Image.Resampling.LANCZOS,
    )

    output = BytesIO()

    image.save(
        output,
        format="JPEG",
        quality=88,
        optimize=True,
    )

    connection = db()

    person = connection.execute(
        sql("""
            SELECT id
            FROM personnel
            WHERE id = ?
        """),
        (
            person_id,
        ),
    ).fetchone()

    if not person:

        connection.close()

        flash(
            "Personnel not found.",
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    connection.execute(
        sql("""
            UPDATE personnel
            SET
                profile_image = ?,
                profile_image_mime = ?
            WHERE id = ?
        """),
        (
            output.getvalue(),
            "image/jpeg",
            person_id,
        ),
    )

    connection.commit()
    connection.close()

    flash(
        "Profile picture updated.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# REMOVE PROFILE PICTURE
# =========================================================

@app.post(
    "/mod/personnel/<int:person_id>/profile/remove"
)
@role_required(
    "admin",
    "moderator",
)
def remove_profile_picture(person_id):

    connection = db()

    connection.execute(
        sql("""
            UPDATE personnel
            SET
                profile_image = NULL,
                profile_image_mime = NULL
            WHERE id = ?
        """),
        (
            person_id,
        ),
    )

    connection.commit()
    connection.close()

    flash(
        "Profile picture removed.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# CRIMINAL RECORD
# =========================================================

@app.post(
    "/mod/personnel/<int:person_id>/criminal/add"
)
@role_required(
    "admin",
    "moderator",
)
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
            "error",
        )

        return redirect(
            url_for("mod_home")
        )

    connection = db()

    exists = connection.execute(
        sql("""
            SELECT id
            FROM personnel
            WHERE id = ?
        """),
        (
            person_id,
        ),
    ).fetchone()

    if not exists:

        connection.close()

        return (
            "Personnel not found.",
            404,
        )

    connection.execute(
        sql("""
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

    connection.commit()
    connection.close()

    flash(
        "Criminal record added.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# DELETE CRIMINAL RECORD
# =========================================================

@app.post(
    "/mod/criminal/<int:record_id>/delete"
)
@role_required(
    "admin",
    "moderator",
)
def delete_criminal_record(record_id):

    connection = db()

    connection.execute(
        sql("""
            DELETE FROM criminal_records
            WHERE id = ?
        """),
        (
            record_id,
        ),
    )

    connection.commit()
    connection.close()

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

@app.post(
    "/mod/personnel/<int:person_id>/delete"
)
@role_required(
    "admin",
    "moderator",
)
def delete_personnel(person_id):

    connection = db()

    connection.execute(
        sql("""
            DELETE FROM point_log
            WHERE personnel_id = ?
        """),
        (
            person_id,
        ),
    )

    connection.execute(
        sql("""
            DELETE FROM criminal_records
            WHERE personnel_id = ?
        """),
        (
            person_id,
        ),
    )

    connection.execute(
        sql("""
            DELETE FROM personnel
            WHERE id = ?
        """),
        (
            person_id,
        ),
    )

    connection.commit()
    connection.close()

    flash(
        "Personnel removed.",
        "success",
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# ADMIN
# =========================================================

@app.route("/admin")
@role_required("admin")
def admin_home():

    connection = db()

    users = connection.execute(
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

    people = connection.execute(
        """
        SELECT
            id,
            name,
            rank,
            role,
            department,
            status
        FROM personnel
        ORDER BY LOWER(name)
        """
    ).fetchall()

    connection.close()

    return render_template(
        "admin.html",
        users=users,
        people=people,
    )


# =========================================================
# ADD USER
# =========================================================

@app.post(
    "/admin/users/add"
)
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

    connection = db()

    try:

        connection.execute(
            sql("""
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
                generate_password_hash(
                    password
                ),
                role,
            ),
        )

        connection.commit()

        flash(
            "Account created.",
            "success",
        )

    except Exception:

        connection.rollback()

        flash(
            "That username may already exist.",
            "error",
        )

    finally:

        connection.close()

    return redirect(
        url_for("admin_home")
    )


# =========================================================
# DELETE USER
# =========================================================

@app.post(
    "/admin/users/<int:user_id>/delete"
)
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

    connection = db()

    connection.execute(
        sql("""
            DELETE FROM users
            WHERE id = ?
        """),
        (
            user_id,
        ),
    )

    connection.commit()
    connection.close()

    flash(
        "Account removed.",
        "success",
    )

    return redirect(
        url_for("admin_home")
    )


# =========================================================
# LOGOUT
# =========================================================

@app.get(
    "/mod/logout"
)
def logout():

    session.clear()

    return redirect(
        url_for("public_home")
    )


# =========================================================
# SEARCH API
# =========================================================

@app.get(
    "/api/search"
)
def api_search():

    search = request.args.get(
        "q",
        ""
    ).strip()

    connection = db()

    if search:

        value = f"%{search}%"

        rows = connection.execute(
            sql("""
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
                ORDER BY LOWER(name)
                LIMIT 50
            """),
            (
                value,
                value,
                value,
                value,
            ),
        ).fetchall()

    else:

        rows = connection.execute(
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
                ORDER BY LOWER(name)
                LIMIT 50
            """
        ).fetchall()

    connection.close()

    return jsonify(
        [
            dict(row)
            for row in rows
        ]
    )


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
