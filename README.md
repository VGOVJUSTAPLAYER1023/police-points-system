# Police Personnel Rank & Points Website

This version is organized into three areas:

- PUBLIC: `/` — anyone can search and view rank/points.
- MODERATOR: `/mod` — login required; moderators can manage personnel, points, and ranks.
- ADMIN: `/admin` — admin-only; manage moderator/viewer accounts.

## Database
- Local development: SQLite (`police.db`)
- Production: PostgreSQL via `DATABASE_URL`

## Local Windows run

```cmd
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
py app.py
```

Open `http://127.0.0.1:5000/`.

Default admin:
- Username: `admin`
- Password: `ChangeMe123!`

Change/remove this immediately.

## Render deployment

1. Upload the project files to GitHub.
2. In Render, create a PostgreSQL database.
3. Create a Web Service connected to the GitHub repository.
4. Build command: `pip install -r requirements.txt`
5. Start command: `gunicorn app:app`
6. Add the PostgreSQL connection string as the `DATABASE_URL` environment variable.
7. Add/keep `SECRET_KEY` as a strong random environment variable.

The included `render.yaml` is a starting point, but depending on the Render plan/interface you may prefer creating the database and web service separately.

## Recommended URL structure

Public:
`https://YOUR-DOMAIN/`

Moderator:
`https://YOUR-DOMAIN/mod`

Admin:
`https://YOUR-DOMAIN/admin`

## Security
Use HTTPS, strong passwords, a private admin URL, backups, and appropriate access controls. Do not store sensitive real-world law-enforcement records unless you have authorization and appropriate security/compliance controls.
