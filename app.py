import os
import sqlite3
import secrets
from io import BytesIO
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    send_file,
)

from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key"
)

DATABASE_URL = os.environ.get("DATABASE_URL")

MAX_PROFILE_IMAGE_SIZE = 5 * 1024 * 1024
PERSONNEL_PER_PAGE = 15


# =========================================================
# OPTIONS
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

DEPARTMENTS = [
    "Pampanga Police Office",

    # Specialized Police Units
    "SWAT — Special Weapons and Tactics",
    "SAF — Special Action Force",
    "HPG — Highway Patrol Group",
    "TS — Training Service",
    "PSPG — Police Security and Protection Group",
    "PDEA — Philippine Drug Enforcement Agency",
    "CIDG — Criminal Investigation and Detection Group",

    # Other Departments
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

RANKS = [
    # Police
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
    "Government Director",
    "Government Officer",
    "Government Staff",
    "Government Employee",

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

    # DPWH
    "DPWH Director",
    "DPWH Assistant Director",
    "DPWH Division Chief",
    "DPWH Engineer",
    "DPWH Senior Engineer",
    "DPWH Engineer II",
    "DPWH Engineer I",
    "DPWH Inspector",
    "DPWH Staff",
    "DPWH Employee",

    # Management
    "Owner",
    "Co-Owner",
    "Management",
    "Supervisor",

    # General
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

STATUSES = [
    "Active",
    "LOA",
    "Suspended",
    "Inactive",
    "Retired",
    "Training",
]


# =========================================================
# DATABASE HELPERS
# =========================================================

def is_postgres():
    return bool(
        DATABASE_URL
        and DATABASE_URL.startswith(
            ("postgres://", "postgresql://")
        )
    )


def get_db():
    if is_postgres():

        if psycopg is None:
            raise RuntimeError(
                "PostgreSQL is configured but psycopg is not installed."
            )

        return psycopg.connect(
            DATABASE_URL,
            row_factory=dict_row
        )

    db = sqlite3.connect("police_points.db")
    db.row_factory = sqlite3.Row
    return db


def placeholder():
    return "%s" if is_postgres() else "?"


def row_value(row, key, index=None, default=None):
    """
    Safely get a value from either a dict-like row or sqlite row/tuple.
    """

    if row is None:
        return default

    try:
        if isinstance(row, dict):
            return row.get(key, default)
    except Exception:
        pass

    try:
        return row[key]
    except Exception:
        pass

    if index is not None:
        try:
            return row[index]
        except Exception:
            pass

    return default


def execute(
    query,
    params=(),
    fetchone=False,
    fetchall=False,
    commit=False,
):
    db = get_db()

    try:
        cur = db.cursor()

        cur.execute(query, params)

        result = None

        if fetchone:
            result = cur.fetchone()

        elif fetchall:
            result = cur.fetchall()

        if commit:
            db.commit()

        return result

    finally:
        db.close()


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def init_db():

    db = get_db()

    try:

        cur = db.cursor()

        # -------------------------------------------------
        # USERS
        # -------------------------------------------------

        if is_postgres():

            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'moderator',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # -------------------------------------------------
            # PERSONNEL
            # -------------------------------------------------

            cur.execute("""
                CREATE TABLE IF NOT EXISTS personnel (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    rank TEXT DEFAULT 'None',
                    points INTEGER DEFAULT 0,
                    notes TEXT DEFAULT '',
                    role TEXT DEFAULT '',
                    department TEXT DEFAULT '',
                    status TEXT DEFAULT 'Active',
                    profile_token TEXT UNIQUE,
                    profile_image BYTEA,
                    profile_image_mime TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # -------------------------------------------------
            # POINT LOG
            # -------------------------------------------------

            cur.execute("""
                CREATE TABLE IF NOT EXISTS point_log (
                    id SERIAL PRIMARY KEY,
                    personnel_id INTEGER NOT NULL,
                    amount INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    changed_by TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # -------------------------------------------------
            # CRIMINAL RECORDS
            # -------------------------------------------------

            cur.execute("""
                CREATE TABLE IF NOT EXISTS criminal_records (
                    id SERIAL PRIMARY KEY,
                    personnel_id INTEGER NOT NULL,
                    case_number TEXT DEFAULT '',
                    charge TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    record_status TEXT DEFAULT 'Open',
                    case_date TEXT DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

        else:

            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'moderator',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS personnel (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    rank TEXT DEFAULT 'None',
                    points INTEGER DEFAULT 0,
                    notes TEXT DEFAULT '',
                    role TEXT DEFAULT '',
                    department TEXT DEFAULT '',
                    status TEXT DEFAULT 'Active',
                    profile_token TEXT UNIQUE,
                    profile_image BLOB,
                    profile_image_mime TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS point_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    personnel_id INTEGER NOT NULL,
                    amount INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    changed_by TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS criminal_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    personnel_id INTEGER NOT NULL,
                    case_number TEXT DEFAULT '',
                    charge TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    record_status TEXT DEFAULT 'Open',
                    case_date TEXT DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

        db.commit()

        # -------------------------------------------------
        # SQLITE MIGRATION
        # -------------------------------------------------

        if not is_postgres():

            cur.execute("PRAGMA table_info(personnel)")

            columns = {
                row[1]
                for row in cur.fetchall()
            }

            migrations = {
                "notes":
                    "ALTER TABLE personnel ADD COLUMN notes TEXT DEFAULT ''",

                "role":
                    "ALTER TABLE personnel ADD COLUMN role TEXT DEFAULT ''",

                "department":
                    "ALTER TABLE personnel ADD COLUMN department TEXT DEFAULT ''",

                "status":
                    "ALTER TABLE personnel ADD COLUMN status TEXT DEFAULT 'Active'",

                "profile_token":
                    "ALTER TABLE personnel ADD COLUMN profile_token TEXT",

                "profile_image":
                    "ALTER TABLE personnel ADD COLUMN profile_image BLOB",

                "profile_image_mime":
                    "ALTER TABLE personnel ADD COLUMN profile_image_mime TEXT",
            }

            for column, sql in migrations.items():

                if column not in columns:
                    cur.execute(sql)

            db.commit()

        # -------------------------------------------------
        # PROFILE TOKENS
        # -------------------------------------------------

        cur.execute("""
            SELECT id
            FROM personnel
            WHERE profile_token IS NULL
               OR profile_token = ''
        """)

        rows = cur.fetchall()

        ph = placeholder()

        for row in rows:

            person_id = row_value(
                row,
                "id",
                0
            )

            token = secrets.token_urlsafe(24)

            cur.execute(
                f"""
                UPDATE personnel
                SET profile_token = {ph}
                WHERE id = {ph}
                """,
                (
                    token,
                    person_id
                )
            )

        db.commit()

        # -------------------------------------------------
        # DEFAULT ADMIN
        # -------------------------------------------------

        cur.execute(
            f"""
            SELECT id
            FROM users
            WHERE LOWER(username) = LOWER({ph})
            """,
            ("admin",)
        )

        admin_exists = cur.fetchone()

        if not admin_exists:

            password_hash = generate_password_hash(
                "ChangeMe123!"
            )

            cur.execute(
                f"""
                INSERT INTO users
                (
                    username,
                    password_hash,
                    role
                )
                VALUES (
                    {ph},
                    {ph},
                    {ph}
                )
                """,
                (
                    "admin",
                    password_hash,
                    "admin"
                )
            )

            db.commit()

            print(
                "=============================================="
            )
            print(
                "DEFAULT ADMIN CREATED"
            )
            print(
                "Username: admin"
            )
            print(
                "Password: ChangeMe123!"
            )
            print(
                "PLEASE CHANGE THIS PASSWORD"
            )
            print(
                "=============================================="
            )

    finally:
        db.close()


# =========================================================
# AUTHENTICATION
# =========================================================

def current_role():
    return session.get("role")


@app.context_processor
def inject_globals():
    return {
        "current_role": current_role()
    }


def login_required(role=None):

    def decorator(view):

        @wraps(view)
        def wrapped(*args, **kwargs):

            if "user_id" not in session:

                return redirect(
                    url_for(
                        "mod_login",
                        next=request.path
                    )
                )

            user_role = session.get("role")

            if role == "moderator":

                if user_role not in [
                    "moderator",
                    "admin"
                ]:
                    abort(403)

            elif role == "admin":

                if user_role != "admin":
                    abort(403)

            return view(*args, **kwargs)

        return wrapped

    return decorator


# =========================================================
# PUBLIC HOME / SEARCH
# =========================================================

@app.route("/")
def public_home():

    q = request.args.get(
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
        page = max(
            int(request.args.get("page", 1)),
            1
        )
    except (ValueError, TypeError):
        page = 1

    ph = placeholder()

    conditions = []
    params = []

    # -------------------------------------------------
    # SEARCH
    # -------------------------------------------------

    if q:

        search = f"%{q}%"

        conditions.append(
            f"""
            (
                name ILIKE {ph}
                OR rank ILIKE {ph}
                OR role ILIKE {ph}
                OR department ILIKE {ph}
                OR status ILIKE {ph}
            )
            """
            if is_postgres()
            else
            f"""
            (
                LOWER(name) LIKE LOWER({ph})
                OR LOWER(rank) LIKE LOWER({ph})
                OR LOWER(role) LIKE LOWER({ph})
                OR LOWER(department) LIKE LOWER({ph})
                OR LOWER(status) LIKE LOWER({ph})
            )
            """
        )

        params.extend([
            search,
            search,
            search,
            search,
            search,
        ])

    # -------------------------------------------------
    # FILTERS
    # -------------------------------------------------

    if selected_role:

        conditions.append(
            f"role = {ph}"
        )

        params.append(
            selected_role
        )

    if selected_department:

        conditions.append(
            f"department = {ph}"
        )

        params.append(
            selected_department
        )

    if selected_rank:

        conditions.append(
            f"rank = {ph}"
        )

        params.append(
            selected_rank
        )

    if selected_status:

        conditions.append(
            f"status = {ph}"
        )

        params.append(
            selected_status
        )

    where = ""

    if conditions:

        where = (
            " WHERE "
            + " AND ".join(conditions)
        )

    # -------------------------------------------------
    # TOTAL
    # -------------------------------------------------

    total_row = execute(
        f"""
        SELECT COUNT(*) AS total
        FROM personnel
        {where}
        """,
        tuple(params),
        fetchone=True
    )

    total = row_value(
        total_row,
        "total",
        0,
        0
    )

    total = int(total or 0)

    total_pages = max(
        (
            total
            + PERSONNEL_PER_PAGE
            - 1
        )
        // PERSONNEL_PER_PAGE,
        1
    )

    if page > total_pages:
        page = total_pages

    offset = (
        page - 1
    ) * PERSONNEL_PER_PAGE

    # -------------------------------------------------
    # RESULTS
    # -------------------------------------------------

    people = execute(
        f"""
        SELECT
            id,
            name,
            rank,
            points,
            notes,
            role,
            department,
            status,
            profile_token,
            created_at
        FROM personnel
        {where}
        ORDER BY LOWER(name)
        LIMIT {ph}
        OFFSET {ph}
        """,
        tuple(
            params
            + [
                PERSONNEL_PER_PAGE,
                offset
            ]
        ),
        fetchall=True
    )

    return render_template(
        "public.html",
        people=people,
        roles=ROLES,
        departments=DEPARTMENTS,
        ranks=RANKS,
        statuses=STATUSES,
        selected_role=selected_role,
        selected_department=selected_department,
        selected_rank=selected_rank,
        selected_status=selected_status,
        page=page,
        total_pages=total_pages,
        total=total,
        q=q,
    )


# =========================================================
# PUBLIC PERSONNEL PROFILE
# =========================================================

@app.route(
    "/personnel/<int:person_id>"
)
def public_person(person_id):

    ph = placeholder()

    person = execute(
        f"""
        SELECT
            id,
            name,
            rank,
            points,
            notes,
            role,
            department,
            status,
            profile_token,
            created_at
        FROM personnel
        WHERE id = {ph}
        """,
        (
            person_id,
        ),
        fetchone=True
    )

    if not person:
        abort(404)

    criminal_records = execute(
        f"""
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
        WHERE personnel_id = {ph}
        ORDER BY created_at DESC
        """,
        (
            person_id,
        ),
        fetchall=True
    )

    return render_template(
        "public_person.html",
        person=person,
        criminal_records=criminal_records
    )


# =========================================================
# PROFILE IMAGE
# =========================================================

@app.route(
    "/profile-image/<int:person_id>"
)
def profile_image(person_id):

    ph = placeholder()

    row = execute(
        f"""
        SELECT
            profile_image,
            profile_image_mime
        FROM personnel
        WHERE id = {ph}
        """,
        (
            person_id,
        ),
        fetchone=True
    )

    image_data = row_value(
        row,
        "profile_image",
        0
    )

    image_mime = row_value(
        row,
        "profile_image_mime",
        1,
        "image/png"
    )

    if not image_data:

        # 1x1 transparent PNG
        empty_png = (
            b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\rIHDR"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00"
            b"\x1f\x15\xc4\x89"
            b"\x00\x00\x00\rIDAT"
            b"\x08\xd7c\xf8\xcf\xc0\x00"
            b"\x00\x03\x01\x01\x00"
            b"\x18\xdd\x8d\xb1"
            b"\x00\x00\x00\x00"
            b"IEND\xaeB`\x82"
        )

        return send_file(
            BytesIO(empty_png),
            mimetype="image/png"
        )

    return send_file(
        BytesIO(bytes(image_data)),
        mimetype=image_mime or "image/png"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/mod/login",
    methods=["GET", "POST"]
)
def mod_login():

    next_url = (
        request.args.get("next")
        or request.form.get("next")
        or ""
    )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            flash(
                "Please enter your username and password.",
                "error"
            )

            return render_template(
                "login.html",
                next_url=next_url
            )

        ph = placeholder()

        user = execute(
            f"""
            SELECT
                id,
                username,
                password_hash,
                role
            FROM users
            WHERE LOWER(username) = LOWER({ph})
            """,
            (
                username,
            ),
            fetchone=True
        )

        user_id = row_value(
            user,
            "id",
            0
        )

        stored_username = row_value(
            user,
            "username",
            1
        )

        password_hash = row_value(
            user,
            "password_hash",
            2
        )

        user_role = row_value(
            user,
            "role",
            3
        )

        if (
            user
            and password_hash
            and check_password_hash(
                password_hash,
                password
            )
        ):

            session.clear()

            session["user_id"] = user_id
            session["username"] = stored_username
            session["role"] = user_role

            if (
                next_url
                and next_url.startswith("/")
            ):
                return redirect(next_url)

            return redirect(
                url_for("mod_home")
            )

        flash(
            "Invalid username or password.",
            "error"
        )

    return render_template(
        "login.html",
        next_url=next_url
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/mod/logout"
)
def logout():

    session.clear()

    return redirect(
        url_for("public_home")
    )


# =========================================================
# MODERATOR DASHBOARD
# =========================================================

@app.route("/mod")
@login_required("moderator")
def mod_home():

    people = execute(
        """
        SELECT
            id,
            name,
            rank,
            points,
            notes,
            role,
            department,
            status,
            profile_token,
            created_at
        FROM personnel
        ORDER BY LOWER(name)
        """,
        fetchall=True
    )

    return render_template(
        "mod.html",
        people=people,
        roles=ROLES,
        departments=DEPARTMENTS,
        ranks=RANKS,
        statuses=STATUSES
    )


# =========================================================
# ADD PERSONNEL
# =========================================================

@app.route(
    "/mod/personnel/add",
    methods=["POST"]
)
@login_required("moderator")
def add_personnel():

    name = request.form.get(
        "name",
        ""
    ).strip()

    rank = request.form.get(
        "rank",
        "None"
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
        "Active"
    ).strip()

    notes = request.form.get(
        "notes",
        ""
    ).strip()

    if not name:

        flash(
            "Personnel name is required.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    profile_token = secrets.token_urlsafe(24)

    ph = placeholder()

    execute(
        f"""
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
        VALUES
        (
            {ph},
            {ph},
            {ph},
            {ph},
            {ph},
            {ph},
            {ph},
            {ph}
        )
        """,
        (
            name,
            rank,
            0,
            notes,
            role,
            department,
            status,
            profile_token
        ),
        commit=True
    )

    flash(
        f"{name} was added successfully.",
        "success"
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# UPDATE PERSONNEL
# =========================================================

@app.route(
    "/mod/personnel/<int:person_id>/update",
    methods=["POST"]
)
@login_required("moderator")
def update_personnel(person_id):

    name = request.form.get(
        "name",
        ""
    ).strip()

    rank = request.form.get(
        "rank",
        "None"
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
        "Active"
    ).strip()

    notes = request.form.get(
        "notes",
        ""
    ).strip()

    if not name:

        flash(
            "Personnel name cannot be empty.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    ph = placeholder()

    execute(
        f"""
        UPDATE personnel
        SET
            name = {ph},
            rank = {ph},
            role = {ph},
            department = {ph},
            status = {ph},
            notes = {ph}
        WHERE id = {ph}
        """,
        (
            name,
            rank,
            role,
            department,
            status,
            notes,
            person_id
        ),
        commit=True
    )

    flash(
        "Personnel information updated.",
        "success"
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# UPDATE POINTS
# =========================================================

@app.route(
    "/mod/personnel/<int:person_id>/points",
    methods=["POST"]
)
@login_required("moderator")
def update_points(person_id):

    try:

        amount = int(
            request.form.get(
                "amount",
                "0"
            )
        )

    except (ValueError, TypeError):

        flash(
            "Points must be a number.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    reason = request.form.get(
        "reason",
        ""
    ).strip()

    if not reason:

        flash(
            "A reason is required when changing points.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    ph = placeholder()

    person = execute(
        f"""
        SELECT
            name,
            points
        FROM personnel
        WHERE id = {ph}
        """,
        (
            person_id,
        ),
        fetchone=True
    )

    if not person:
        abort(404)

    person_name = row_value(
        person,
        "name",
        0,
        "Unknown"
    )

    old_points = int(
        row_value(
            person,
            "points",
            1,
            0
        ) or 0
    )

    new_points = max(
        old_points + amount,
        0
    )

    actual_change = (
        new_points
        - old_points
    )

    execute(
        f"""
        UPDATE personnel
        SET points = {ph}
        WHERE id = {ph}
        """,
        (
            new_points,
            person_id
        ),
        commit=True
    )

    execute(
        f"""
        INSERT INTO point_log
        (
            personnel_id,
            amount,
            reason,
            changed_by
        )
        VALUES
        (
            {ph},
            {ph},
            {ph},
            {ph}
        )
        """,
        (
            person_id,
            actual_change,
            reason,
            session.get(
                "username",
                "Unknown"
            )
        ),
        commit=True
    )

    flash(
        f"Points updated for {person_name}.",
        "success"
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# POINT HISTORY
# =========================================================

@app.route(
    "/mod/personnel/<int:person_id>/points/history"
)
@login_required("moderator")
def point_history(person_id):

    ph = placeholder()

    person = execute(
        f"""
        SELECT
            id,
            name,
            points
        FROM personnel
        WHERE id = {ph}
        """,
        (
            person_id,
        ),
        fetchone=True
    )

    if not person:
        abort(404)

    logs = execute(
        f"""
        SELECT
            id,
            amount,
            reason,
            changed_by,
            created_at
        FROM point_log
        WHERE personnel_id = {ph}
        ORDER BY created_at DESC
        """,
        (
            person_id,
        ),
        fetchall=True
    )

    return render_template(
        "point_history.html",
        person=person,
        logs=logs
    )


# =========================================================
# UPLOAD PROFILE IMAGE
# =========================================================

@app.route(
    "/mod/personnel/<int:person_id>/profile-image",
    methods=["POST"]
)
@login_required("moderator")
def upload_profile_image(person_id):

    file = request.files.get(
        "profile_image"
    )

    if not file or not file.filename:

        flash(
            "Please select an image.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    data = file.read()

    if len(data) > MAX_PROFILE_IMAGE_SIZE:

        flash(
            "Profile image is too large. Maximum size is 5MB.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    try:

        image = Image.open(
            BytesIO(data)
        )

        image.verify()

        image = Image.open(
            BytesIO(data)
        )

        if image.mode not in (
            "RGB",
            "RGBA"
        ):
            image = image.convert(
                "RGBA"
            )

        output = BytesIO()

        image.save(
            output,
            format="PNG"
        )

        image_data = output.getvalue()

    except Exception:

        flash(
            "Invalid image file.",
            "error"
        )

        return redirect(
            url_for("mod_home")
        )

    ph = placeholder()

    execute(
        f"""
        UPDATE personnel
        SET
            profile_image = {ph},
            profile_image_mime = {ph}
        WHERE id = {ph}
        """,
        (
            image_data,
            "image/png",
            person_id
        ),
        commit=True
    )

    flash(
        "Profile picture updated.",
        "success"
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# REMOVE PROFILE IMAGE
# =========================================================

@app.route(
    "/mod/personnel/<int:person_id>/profile-image/remove",
    methods=["POST"]
)
@login_required("moderator")
def remove_profile_image(person_id):

    ph = placeholder()

    execute(
        f"""
        UPDATE personnel
        SET
            profile_image = NULL,
            profile_image_mime = NULL
        WHERE id = {ph}
        """,
        (
            person_id,
        ),
        commit=True
    )

    flash(
        "Profile picture removed.",
        "success"
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# CRIMINAL RECORD
# =========================================================

@app.route(
    "/mod/personnel/<int:person_id>/criminal-record/add",
    methods=["POST"]
)
@login_required("moderator")
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

    ph = placeholder()

    execute(
        f"""
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
        VALUES
        (
            {ph},
            {ph},
            {ph},
            {ph},
            {ph},
            {ph},
            {ph}
        )
        """,
        (
            person_id,
            case_number,
            charge,
            description,
            record_status,
            case_date,
            session.get(
                "username",
                "Unknown"
            )
        ),
        commit=True
    )

    flash(
        "Criminal record added.",
        "success"
    )

    return redirect(
        url_for("mod_home")
    )


@app.route(
    "/mod/criminal-record/<int:record_id>/delete",
    methods=["POST"]
)
@login_required("moderator")
def delete_criminal_record(record_id):

    ph = placeholder()

    execute(
        f"""
        DELETE FROM criminal_records
        WHERE id = {ph}
        """,
        (
            record_id,
        ),
        commit=True
    )

    flash(
        "Criminal record deleted.",
        "success"
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# DELETE PERSONNEL
# =========================================================

@app.route(
    "/mod/personnel/<int:person_id>/delete",
    methods=["POST"]
)
@login_required("moderator")
def delete_personnel(person_id):

    ph = placeholder()

    execute(
        f"""
        DELETE FROM point_log
        WHERE personnel_id = {ph}
        """,
        (
            person_id,
        ),
        commit=True
    )

    execute(
        f"""
        DELETE FROM criminal_records
        WHERE personnel_id = {ph}
        """,
        (
            person_id,
        ),
        commit=True
    )

    execute(
        f"""
        DELETE FROM personnel
        WHERE id = {ph}
        """,
        (
            person_id,
        ),
        commit=True
    )

    flash(
        "Personnel record deleted.",
        "success"
    )

    return redirect(
        url_for("mod_home")
    )


# =========================================================
# ADMIN
# =========================================================

@app.route("/admin")
@login_required("admin")
def admin_home():

    users = execute(
        """
        SELECT
            id,
            username,
            role,
            created_at
        FROM users
        ORDER BY LOWER(username)
        """,
        fetchall=True
    )

    people = execute(
        """
        SELECT
            id,
            name,
            rank,
            points,
            role,
            department,
            status,
            profile_token,
            created_at
        FROM personnel
        ORDER BY LOWER(name)
        """,
        fetchall=True
    )

    return render_template(
        "admin.html",
        users=users,
        people=people,
        roles=ROLES,
        departments=DEPARTMENTS,
        ranks=RANKS,
        statuses=STATUSES
    )


# =========================================================
# CREATE STAFF
# =========================================================

@app.route(
    "/admin/staff/create",
    methods=["POST"]
)
@login_required("admin")
def create_staff():

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
    ).strip()

    if role not in (
        "moderator",
        "admin"
    ):
        role = "moderator"

    if not username or not password:

        flash(
            "Username and password are required.",
            "error"
        )

        return redirect(
            url_for("admin_home")
        )

    ph = placeholder()

    existing = execute(
        f"""
        SELECT id
        FROM users
        WHERE LOWER(username) = LOWER({ph})
        """,
        (
            username,
        ),
        fetchone=True
    )

    if existing:

        flash(
            "That username already exists.",
            "error"
        )

        return redirect(
            url_for("admin_home")
        )

    password_hash = generate_password_hash(
        password
    )

    execute(
        f"""
        INSERT INTO users
        (
            username,
            password_hash,
            role
        )
        VALUES
        (
            {ph},
            {ph},
            {ph}
        )
        """,
        (
            username,
            password_hash,
            role
        ),
        commit=True
    )

    flash(
        f"Staff account '{username}' created.",
        "success"
    )

    return redirect(
        url_for("admin_home")
    )


# =========================================================
# DELETE STAFF
# =========================================================

@app.route(
    "/admin/staff/<int:user_id>/delete",
    methods=["POST"]
)
@login_required("admin")
def delete_staff(user_id):

    ph = placeholder()

    user = execute(
        f"""
        SELECT username
        FROM users
        WHERE id = {ph}
        """,
        (
            user_id,
        ),
        fetchone=True
    )

    if not user:
        abort(404)

    target_username = row_value(
        user,
        "username",
        0,
        ""
    )

    if session.get("user_id") == user_id:

        flash(
            "You cannot delete the account you are currently using.",
            "error"
        )

        return redirect(
            url_for("admin_home")
        )

    execute(
        f"""
        DELETE FROM users
        WHERE id = {ph}
        """,
        (
            user_id,
        ),
        commit=True
    )

    flash(
        f"Staff account '{target_username}' deleted.",
        "success"
    )

    return redirect(
        url_for("admin_home")
    )


# =========================================================
# CHANGE STAFF ROLE
# =========================================================

@app.route(
    "/admin/staff/<int:user_id>/role",
    methods=["POST"]
)
@login_required("admin")
def update_staff_role(user_id):

    role = request.form.get(
        "role",
        "moderator"
    ).strip()

    if role not in (
        "moderator",
        "admin"
    ):

        flash(
            "Invalid staff role.",
            "error"
        )

        return redirect(
            url_for("admin_home")
        )

    ph = placeholder()

    execute(
        f"""
        UPDATE users
        SET role = {ph}
        WHERE id = {ph}
        """,
        (
            role,
            user_id
        ),
        commit=True
    )

    flash(
        "Staff role updated.",
        "success"
    )

    return redirect(
        url_for("admin_home")
    )


# =========================================================
# API SEARCH
# =========================================================

@app.route(
    "/api/search"
)
def api_search():

    q = request.args.get(
        "q",
        ""
    ).strip()

    ph = placeholder()

    params = []
    where = ""

    if q:

        search = f"%{q}%"

        if is_postgres():

            where = f"""
                WHERE
                    name ILIKE {ph}
                    OR rank ILIKE {ph}
                    OR role ILIKE {ph}
                    OR department ILIKE {ph}
                    OR status ILIKE {ph}
            """

        else:

            where = f"""
                WHERE
                    LOWER(name) LIKE LOWER({ph})
                    OR LOWER(rank) LIKE LOWER({ph})
                    OR LOWER(role) LIKE LOWER({ph})
                    OR LOWER(department) LIKE LOWER({ph})
                    OR LOWER(status) LIKE LOWER({ph})
            """

        params = [
            search,
            search,
            search,
            search,
            search
        ]

    rows = execute(
        f"""
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
        {where}
        ORDER BY LOWER(name)
        LIMIT 50
        """,
        tuple(params),
        fetchall=True
    )

    results = []

    for row in rows:

        results.append({
            "id": row_value(row, "id", 0),
            "name": row_value(row, "name", 1),
            "rank": row_value(row, "rank", 2),
            "points": row_value(row, "points", 3),
            "role": row_value(row, "role", 4),
            "department": row_value(row, "department", 5),
            "status": row_value(row, "status", 6),
            "profile_token": row_value(row, "profile_token", 7),
        })

    return {
        "results": results,
        "count": len(results)
    }


# =========================================================
# ERRORS
# =========================================================

@app.errorhandler(403)
def forbidden(error):

    return (
        render_template(
            "error.html",
            error_code=403,
            error_message="You do not have permission to access this page."
        ),
        403
    )


@app.errorhandler(404)
def not_found(error):

    return (
        render_template(
            "error.html",
            error_code=404,
            error_message="The requested page could not be found."
        ),
        404
    )


@app.errorhandler(500)
def internal_error(error):

    print(
        "INTERNAL SERVER ERROR:",
        repr(error)
    )

    return (
        render_template(
            "error.html",
            error_code=500,
            error_message="An internal server error occurred."
        ),
        500
    )


# =========================================================
# STARTUP
# =========================================================

init_db()


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
