# Copyright (c) 2026 Alexander Schou. All rights reserved.
# Proprietary software. Unauthorized copying, modification, or distribution is prohibited.

import os
import re
import base64
import hashlib
import html
import urllib.parse
import secrets

import psycopg
from psycopg.rows import dict_row
from psycopg import sql
from plan_regression import record_plan_observation

from fastapi import FastAPI, Query, HTTPException, Request
from oracle_router import build_oracle_router
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel, Field

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config


VERSION = "1.6.0"

DB_HOST = os.getenv("PGSCOPE_DB_HOST", "pg-lab-rw")
DB_PORT = int(os.getenv("PGSCOPE_DB_PORT", "5432"))
DB_NAME = os.getenv("PGSCOPE_DB_NAME", "pgscope")
DB_USER = os.getenv("PGSCOPE_DB_USER", "pgscope_api")
DB_PASSWORD = os.getenv("PGSCOPE_DB_PASSWORD", "")

NAMESPACE = os.getenv(
    "PGSCOPE_NAMESPACE",
    "default",
)

K8S_API = None


def kubernetes_api():
    global K8S_API

    if K8S_API is None:
        k8s_config.load_incluster_config()
        K8S_API = k8s_client.CoreV1Api()

    return K8S_API


def read_secret_value(
    secret_name: str,
    secret_key: str,
):
    if not secret_name:
        raise RuntimeError(
            "No Kubernetes secret is configured for this cluster."
        )

    if not secret_key:
        raise RuntimeError(
            "No secret key is configured for this cluster."
        )

    secret = kubernetes_api().read_namespaced_secret(
        name=secret_name,
        namespace=NAMESPACE,
    )

    if not secret.data:
        raise RuntimeError(
            f"Secret {secret_name} contains no data."
        )

    encoded = secret.data.get(secret_key)

    if encoded is None:
        raise RuntimeError(
            f"Secret {secret_name} does not contain key {secret_key}."
        )

    return base64.b64decode(
        encoded
    ).decode("utf-8")


def monitored_cluster(
    cluster_id: str,
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    cluster_id,
                    cluster_name,
                    host,
                    port,
                    username,
                    secret_name,
                    secret_key,
                    enabled
                FROM monitored_clusters
                WHERE cluster_id = %s
                  AND enabled = true
                  AND engine = 'postgresql'
                """,
                (cluster_id,),
            )
            row = cur.fetchone()

    if not row:
        raise RuntimeError(
            f"Cluster {cluster_id} is not configured or enabled."
        )

    return row


def source_connection_for_cluster(
    cluster_id: str,
    database: str,
):
    cluster = monitored_cluster(
        cluster_id
    )

    password = read_secret_value(
        cluster["secret_name"],
        cluster["secret_key"],
    )

    return psycopg.connect(
        host=cluster["host"],
        port=cluster["port"],
        dbname=database,
        user=cluster["username"],
        password=password,
        connect_timeout=5,
        row_factory=dict_row,
    )



AUTH_COOKIE_NAME = "pgscope_session"
AUTH_SESSION_HOURS = int(
    os.getenv(
        "PGSCOPE_SESSION_HOURS",
        "12",
    )
)
AUTH_COOKIE_SECURE = (
    os.getenv(
        "PGSCOPE_COOKIE_SECURE",
        "false",
    ).lower()
    == "true"
)


def password_hash(
    password: str,
    salt: bytes | None = None,
):
    if salt is None:
        salt = secrets.token_bytes(16)

    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2 ** 14,
        r=8,
        p=1,
        dklen=32,
    )

    return (
        salt.hex()
        + ":"
        + derived.hex()
    )


def password_matches(
    password: str,
    stored_hash: str,
):
    try:
        salt_hex, expected_hex = (
            stored_hash.split(
                ":",
                1,
            )
        )

        candidate = password_hash(
            password,
            bytes.fromhex(
                salt_hex
            ),
        )

        return secrets.compare_digest(
            candidate,
            stored_hash,
        )

    except Exception:
        return False


def ensure_default_admin():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT count(*) AS count
                FROM pgscope_users
                """
            )

            count = cur.fetchone()[
                "count"
            ]

            if count == 0:
                cur.execute(
                    """
                    INSERT INTO pgscope_users (
                        username,
                        password_hash,
                        role,
                        must_change_password,
                        enabled
                    )
                    VALUES (%s, %s, 'admin', true, true)
                    """,
                    (
                        "admin",
                        password_hash(
                            "admin"
                        ),
                    ),
                )

        conn.commit()


def create_session(
    user_id: int,
):
    token = secrets.token_urlsafe(
        32
    )

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO pgscope_sessions (
                    token_hash,
                    user_id,
                    expires_at
                )
                VALUES (
                    %s,
                    %s,
                    now()
                    + (%s * interval '1 hour')
                )
                """,
                (
                    token_hash,
                    user_id,
                    AUTH_SESSION_HOURS,
                ),
            )

        conn.commit()

    return token


def session_user(
    token: str | None,
):
    if not token:
        return None

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    u.id,
                    u.username,
                    u.role,
                    u.must_change_password,
                    s.expires_at
                FROM pgscope_sessions s
                JOIN pgscope_users u
                  ON u.id = s.user_id
                WHERE s.token_hash = %s
                  AND s.expires_at > now()
                  AND u.enabled = true
                """,
                (
                    token_hash,
                ),
            )

            return cur.fetchone()


def delete_session(
    token: str | None,
):
    if not token:
        return

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM pgscope_sessions
                WHERE token_hash = %s
                """,
                (
                    token_hash,
                ),
            )

        conn.commit()


def login_html(
    error: str | None = None,
):
    safe_error = html.escape(
        error or "",
        quote=True,
    )
    error_html = (
        f'<div class="error">{safe_error}</div>'
        if error
        else ""
    )

    return f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>PgScope Login</title>
<style>
body {{
    margin: 0;
    min-height: 100vh;
    display: grid;
    place-items: center;
    background: #0f172a;
    color: #e5e7eb;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
}}
.login-card {{
    width: min(380px, calc(100vw - 40px));
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 26px;
}}
h1 {{ margin: 0 0 4px; }}
.subtitle {{ color: #94a3b8; margin-bottom: 22px; }}
label {{ display:block; margin: 12px 0 6px; }}
input {{
    width: 100%;
    box-sizing: border-box;
    padding: 10px;
    border-radius: 7px;
    border: 1px solid #475569;
    background: #0f172a;
    color: #e5e7eb;
}}
button {{
    width: 100%;
    margin-top: 18px;
    padding: 10px;
    border-radius: 7px;
    border: 1px solid #3b82f6;
    background: #2563eb;
    color: white;
    font-weight: 700;
    cursor: pointer;
}}
.error {{
    background: #7f1d1d;
    color: #fecaca;
    border-radius: 7px;
    padding: 9px;
    margin-bottom: 14px;
}}

.oracle-sql-link {{
    color: #60a5fa;
    cursor: pointer;
    font-family: Menlo, Monaco, monospace;
    font-weight: 700;
}}

.oracle-sql-link:hover {{
    text-decoration: underline;
}}

.oracle-clickable-row {{
    cursor: pointer;
}}

.oracle-clickable-row:hover td {{
    background: rgba(59, 130, 246, .08);
}}

.oracle-detail-grid {{
    display: grid;
    grid-template-columns: repeat(
        auto-fit,
        minmax(150px, 1fr)
    );
    gap: 12px;
    margin: 16px 0;
}}

.oracle-detail-card {{
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 12px;
}}

.oracle-detail-card .label {{
    color: #94a3b8;
    font-size: 12px;
    margin-bottom: 5px;
}}

.oracle-detail-card .value {{
    font-size: 18px;
    font-weight: 700;
}}

.oracle-sql-text {{
    font-family: Menlo, Monaco, monospace;
    white-space: pre-wrap;
    background: #0f172a;
    border-radius: 8px;
    padding: 14px;
    margin: 12px 0 20px;
}}

.oracle-detail-section {{
    margin-top: 24px;
}}

.oracle-plan-form {{
    display: grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(170px, 1fr)
        );
    gap: 10px;
    margin: 12px 0;
}}

.oracle-plan-form input {{
    width: 100%;
    box-sizing: border-box;
    background: #0f172a;
    color: #e5e7eb;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 8px;
}}

.oracle-plan-table td {{
    vertical-align: top;
}}

.oracle-plan-operation {{
    font-family: Menlo, Monaco, monospace;
    white-space: nowrap;
}}

.oracle-plan-predicate {{
    font-family: Menlo, Monaco, monospace;
    font-size: 11px;
    white-space: pre-wrap;
}}

.oracle-status {{
    color: #94a3b8;
    margin: 8px 0;
}}

.oracle-error {{
    color: #f87171;
    font-weight: 700;
}}

.oracle-close {{
    float: right;
}}


</style>
</head>
<body>
<div class="login-card">
<h1>PgScope</h1>
<div class="subtitle">PostgreSQL &amp; Oracle Performance Advisor</div>
{error_html}
<form method="post" action="/login">
<label>Username</label>
<input name="username" autocomplete="username" autofocus>
<label>Password</label>
<input name="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form>
</div>
</body>
</html>
"""


def change_password_html(
    username: str,
    error: str | None = None,
):
    safe_username = html.escape(
        username,
        quote=True,
    )
    safe_error = html.escape(
        error or "",
        quote=True,
    )
    error_html = (
        f'<div class="error">{safe_error}</div>'
        if error
        else ""
    )

    return f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Change PgScope Password</title>
<style>
body {{
    margin: 0;
    min-height: 100vh;
    display: grid;
    place-items: center;
    background: #0f172a;
    color: #e5e7eb;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
}}
.card {{
    width: min(430px, calc(100vw - 40px));
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 26px;
}}
h1 {{ margin-top: 0; }}
.notice {{
    background: #713f12;
    color: #fde68a;
    border-radius: 7px;
    padding: 10px;
    margin-bottom: 16px;
}}
.error {{
    background: #7f1d1d;
    color: #fecaca;
    border-radius: 7px;
    padding: 9px;
    margin-bottom: 14px;
}}
label {{ display:block; margin: 12px 0 6px; }}
input {{
    width: 100%;
    box-sizing: border-box;
    padding: 10px;
    border-radius: 7px;
    border: 1px solid #475569;
    background: #0f172a;
    color: #e5e7eb;
}}
button {{
    width: 100%;
    margin-top: 18px;
    padding: 10px;
    border-radius: 7px;
    border: 1px solid #3b82f6;
    background: #2563eb;
    color: white;
    font-weight: 700;
    cursor: pointer;
}}
</style>
</head>
<body>
<div class="card">
<h1>Change password</h1>
<div class="notice">
The default administrator password must be changed before PgScope can be used.
</div>
<div>User: <strong>{safe_username}</strong></div>
{error_html}
<form method="post" action="/change-password">
<label>New password</label>
<input name="new_password" type="password" autocomplete="new-password">
<label>Confirm new password</label>
<input name="confirm_password" type="password" autocomplete="new-password">
<button type="submit">Change password</button>
</form>
</div>
</body>
</html>
"""


app = FastAPI(
    title="PgScope API",
    version=VERSION,
)

@app.middleware("http")
async def pgscope_auth_middleware(
    request: Request,
    call_next,
):
    path = request.url.path

    if path in (
        "/health",
        "/health/live",
        "/health/ready",
        "/login",
    ):
        return await call_next(
            request
        )

    try:
        user = session_user(
            request.cookies.get(
                AUTH_COOKIE_NAME
            )
        )
    except Exception:
        user = None

    if not user:
        if path.startswith(
            "/api/"
        ):
            return JSONResponse(
                {
                    "detail":
                        "Authentication required"
                },
                status_code=401,
            )

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    request.state.user = user

    if (
        user["must_change_password"]
        and path not in (
            "/change-password",
            "/logout",
        )
    ):
        if path.startswith(
            "/api/"
        ):
            return JSONResponse(
                {
                    "detail":
                        "Password change required"
                },
                status_code=403,
            )

        return RedirectResponse(
            "/change-password",
            status_code=303,
        )

    return await call_next(
        request
    )


@app.middleware("http")
async def pgscope_security_headers(
    request: Request,
    call_next,
):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    forwarded_proto = request.headers.get(
        "x-forwarded-proto",
        request.url.scheme,
    )
    if forwarded_proto == "https":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


@app.get(
    "/login",
    response_class=HTMLResponse,
)
def login_page(
    request: Request,
):
    try:
        ensure_default_admin()
    except Exception as exc:
        return HTMLResponse(
            login_html(
                "Authentication database is not ready: "
                + str(exc)
            ),
            status_code=503,
        )

    user = session_user(
        request.cookies.get(
            AUTH_COOKIE_NAME
        )
    )

    if user:
        target = (
            "/change-password"
            if user[
                "must_change_password"
            ]
            else "/"
        )

        return RedirectResponse(
            target,
            status_code=303,
        )

    return HTMLResponse(
        login_html()
    )


@app.post(
    "/login",
    response_class=HTMLResponse,
)
async def login_submit(
    request: Request,
):
    ensure_default_admin()

    body = (
        await request.body()
    ).decode("utf-8")

    form = urllib.parse.parse_qs(
        body
    )

    username = (
        form.get(
            "username",
            [""],
        )[0]
    ).strip()

    password = form.get(
        "password",
        [""],
    )[0]

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    username,
                    password_hash,
                    role,
                    must_change_password,
                    enabled
                FROM pgscope_users
                WHERE username = %s
                """,
                (
                    username,
                ),
            )

            user = cur.fetchone()

    if (
        not user
        or not user["enabled"]
        or not password_matches(
            password,
            user["password_hash"],
        )
    ):
        return HTMLResponse(
            login_html(
                "Invalid username or password."
            ),
            status_code=401,
        )

    token = create_session(
        user["id"]
    )

    target = (
        "/change-password"
        if user[
            "must_change_password"
        ]
        else "/"
    )

    response = RedirectResponse(
        target,
        status_code=303,
    )

    response.set_cookie(
        AUTH_COOKIE_NAME,
        token,
        httponly=True,
        secure=AUTH_COOKIE_SECURE,
        samesite="lax",
        max_age=(
            AUTH_SESSION_HOURS
            * 3600
        ),
    )

    return response


@app.get(
    "/change-password",
    response_class=HTMLResponse,
)
def change_password_page(
    request: Request,
):
    user = request.state.user

    return HTMLResponse(
        change_password_html(
            user["username"]
        )
    )


@app.post(
    "/change-password",
    response_class=HTMLResponse,
)
async def change_password_submit(
    request: Request,
):
    user = request.state.user

    body = (
        await request.body()
    ).decode("utf-8")

    form = urllib.parse.parse_qs(
        body
    )

    new_password = form.get(
        "new_password",
        [""],
    )[0]

    confirm_password = form.get(
        "confirm_password",
        [""],
    )[0]

    if new_password != confirm_password:
        return HTMLResponse(
            change_password_html(
                user["username"],
                "Passwords do not match.",
            ),
            status_code=400,
        )

    if len(new_password) < 10:
        return HTMLResponse(
            change_password_html(
                user["username"],
                "Use at least 10 characters.",
            ),
            status_code=400,
        )

    if (
        user["username"] == "admin"
        and new_password == "admin"
    ):
        return HTMLResponse(
            change_password_html(
                user["username"],
                "The default password cannot be reused.",
            ),
            status_code=400,
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE pgscope_users
                SET
                    password_hash = %s,
                    must_change_password = false,
                    updated_at = now()
                WHERE id = %s
                """,
                (
                    password_hash(
                        new_password
                    ),
                    user["id"],
                ),
            )

            cur.execute(
                """
                DELETE FROM pgscope_sessions
                WHERE user_id = %s
                """,
                (
                    user["id"],
                ),
            )

        conn.commit()

    token = create_session(
        user["id"]
    )

    response = RedirectResponse(
        "/",
        status_code=303,
    )

    response.set_cookie(
        AUTH_COOKIE_NAME,
        token,
        httponly=True,
        secure=AUTH_COOKIE_SECURE,
        samesite="lax",
        max_age=(
            AUTH_SESSION_HOURS
            * 3600
        ),
    )

    return response


@app.get("/logout")
def logout(
    request: Request,
):
    delete_session(
        request.cookies.get(
            AUTH_COOKIE_NAME
        )
    )

    response = RedirectResponse(
        "/login",
        status_code=303,
    )

    response.delete_cookie(
        AUTH_COOKIE_NAME
    )

    return response



def get_connection():
    return psycopg.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        row_factory=dict_row,
    )


app.include_router(build_oracle_router(get_connection, read_secret_value))


@app.get("/health/live")
def health_live():
    return {
        "status": "ok",
        "version": VERSION,
    }


@app.get("/health/ready")
def health_ready():
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT now() AS database_time")
                row = cur.fetchone()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="PgScope storage database is unavailable.",
        ) from exc

    return {
        "status": "ok",
        "version": VERSION,
        "database_time": row["database_time"],
    }


@app.get("/health")
def health():
    """Backward-compatible readiness endpoint."""
    return health_ready()


@app.get("/api/cluster-overview")
def cluster_overview():
    sql = """
    WITH clusters AS (
        SELECT DISTINCT
            cluster_id,
            cluster_name
        FROM query_snapshots
        WHERE cluster_id IS NOT NULL
    ),
    dbs AS (
        SELECT
            cluster_id,
            count(DISTINCT database_name) AS database_count
        FROM query_snapshots
        WHERE cluster_id IS NOT NULL
        GROUP BY cluster_id
    ),
    latest AS (
        SELECT
            cluster_id,
            max(captured_at) AS last_collection
        FROM query_snapshots
        WHERE cluster_id IS NOT NULL
        GROUP BY cluster_id
    ),
    recent_findings AS (
        SELECT
            cluster_id,
            count(*) FILTER (
                WHERE severity = 'CRITICAL'
            ) AS critical_count,
            count(*) FILTER (
                WHERE severity = 'WARNING'
            ) AS warning_count
        FROM findings
        WHERE captured_at >= now() - interval '1 hour'
          AND cluster_id IS NOT NULL
        GROUP BY cluster_id
    )
    SELECT
        c.cluster_id,
        c.cluster_name,
        coalesce(d.database_count, 0) AS database_count,
        coalesce(rf.critical_count, 0) AS critical_count,
        coalesce(rf.warning_count, 0) AS warning_count,
        l.last_collection,
        EXTRACT(
            EPOCH FROM (now() - l.last_collection)
        )::int AS seconds_since_collection,
        CASE
            WHEN l.last_collection IS NULL THEN 'UNKNOWN'
            WHEN now() - l.last_collection > interval '2 minutes' THEN 'OFFLINE'
            ELSE 'HEALTHY'
        END AS health_status,

        CASE
            WHEN coalesce(rf.critical_count, 0) > 0 THEN 'CRITICAL'
            WHEN coalesce(rf.warning_count, 0) > 0 THEN 'WARNING'
            ELSE 'OK'
        END AS performance_status
    FROM clusters c
    LEFT JOIN dbs d
      ON d.cluster_id = c.cluster_id
    LEFT JOIN latest l
      ON l.cluster_id = c.cluster_id
    LEFT JOIN recent_findings rf
      ON rf.cluster_id = c.cluster_id
    ORDER BY
        CASE
            WHEN l.last_collection IS NULL THEN 3
            WHEN now() - l.last_collection > interval '2 minutes' THEN 2
            ELSE 0
        END DESC,
        CASE
            WHEN coalesce(rf.critical_count, 0) > 0 THEN 2
            WHEN coalesce(rf.warning_count, 0) > 0 THEN 1
            ELSE 0
        END DESC,
        c.cluster_name
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall()


@app.get("/api/clusters")
def clusters():
    sql = """
    SELECT
        cluster_id,
        cluster_name
    FROM monitored_clusters
    WHERE enabled = true AND engine = 'postgresql'
    ORDER BY cluster_name, cluster_id
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall()


@app.get("/api/databases")
def databases(
    cluster_id: str | None = None,
):
    sql = """
    SELECT
        d.database_name
    FROM monitored_databases d
    JOIN monitored_clusters c USING (cluster_id)
    WHERE d.enabled = true
      AND c.enabled = true
      AND c.engine = 'postgresql'
      AND (
          %s::text IS NULL
          OR d.cluster_id = %s::text
      )
    ORDER BY d.database_name
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql,
                (
                    cluster_id,
                    cluster_id,
                ),
            )
            return cur.fetchall()


@app.get("/api/summary")
def summary(
    cluster_id: str | None = None,
    database: str | None = None,
):
    sql = """
    SELECT
        (
            SELECT count(*)
            FROM findings
            WHERE captured_at >= now() - interval '1 hour'
              AND (
                  %s::text IS NULL
                  OR cluster_id = %s::text
              )
              AND (
                  %s::text IS NULL
                  OR database_name = %s::text
              )
        ) AS findings_last_hour,

        (
            SELECT count(*)
            FROM findings
            WHERE severity = 'CRITICAL'
              AND captured_at >= now() - interval '1 hour'
              AND (
                  %s::text IS NULL
                  OR cluster_id = %s::text
              )
              AND (
                  %s::text IS NULL
                  OR database_name = %s::text
              )
        ) AS critical_last_hour,

        (
            SELECT count(DISTINCT database_name)
            FROM query_deltas
            WHERE captured_at >= now() - interval '1 hour'
              AND (
                  %s::text IS NULL
                  OR cluster_id = %s::text
              )
        ) AS databases_seen,

        (
            SELECT max(captured_at)
            FROM query_deltas
            WHERE (
                %s::text IS NULL
                OR cluster_id = %s::text
            )
            AND (
                %s::text IS NULL
                OR database_name = %s::text
            )
        ) AS last_collection
    """

    params = (
        cluster_id,
        cluster_id,
        database,
        database,
        cluster_id,
        cluster_id,
        database,
        database,
        cluster_id,
        cluster_id,
        cluster_id,
        cluster_id,
        database,
        database,
    )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()


@app.get("/api/findings")
def findings(
    cluster_id: str | None = None,
    database: str | None = None,
    limit: int = Query(
        default=50,
        ge=1,
        le=500,
    ),
):
    sql = """
    SELECT
        id,
        captured_at,
        cluster_id,
        cluster_name,
        severity,
        finding_type,
        database_name,
        queryid::text AS queryid,
        metric_value,
        threshold_value,
        message,
        recommendation,
        query_text
    FROM findings
    WHERE (
        %s::text IS NULL
        OR cluster_id = %s::text
    )
    AND (
        %s::text IS NULL
        OR database_name = %s::text
    )
    ORDER BY captured_at DESC, id DESC
    LIMIT %s
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql,
                (
                    cluster_id,
                    cluster_id,
                    database,
                    database,
                    limit,
                ),
            )
            return cur.fetchall()


@app.get("/api/top-queries")
def top_queries(
    cluster_id: str,
    database: str,
    minutes: int = Query(
        default=60,
        ge=1,
        le=10080,
    ),
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
):
    sql = """
    SELECT
        cluster_id,
        MAX(cluster_name) AS cluster_name,
        database_name,
        queryid::text AS queryid,

        SUM(calls_delta) AS calls,

        ROUND(
            SUM(exec_time_delta)::numeric,
            2
        ) AS total_exec_ms,

        ROUND(
            (
                SUM(exec_time_delta)
                /
                NULLIF(
                    SUM(calls_delta),
                    0
                )
            )::numeric,
            2
        ) AS avg_exec_ms,

        SUM(shared_reads_delta) AS shared_reads,

        ROUND(
            AVG(cache_hit_pct)::numeric,
            2
        ) AS avg_cache_hit_pct,

        SUM(temp_written_delta) AS temp_blocks,

        ROUND(
            (
                SUM(wal_bytes_delta)
                / 1024
                / 1024
            )::numeric,
            2
        ) AS wal_mb,

        MAX(query_text) AS query_text

    FROM query_deltas

    WHERE cluster_id = %s::text
      AND database_name = %s::text
      AND captured_at >=
          now() - (%s * interval '1 minute')

    GROUP BY
        cluster_id,
        database_name,
        queryid

    ORDER BY
        SUM(exec_time_delta) DESC

    LIMIT %s
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql,
                (
                    cluster_id,
                    database,
                    minutes,
                    limit,
                ),
            )
            return cur.fetchall()


@app.get("/api/query-history/{queryid}")
def query_history(
    queryid: int,
    cluster_id: str,
    database: str,
    minutes: int = Query(
        default=60,
        ge=1,
        le=10080,
    ),
):
    sql = """
    SELECT
        captured_at,
        cluster_id,
        cluster_name,
        database_name,
        calls_delta,
        exec_time_delta,
        avg_exec_ms,
        shared_reads_delta,
        cache_hit_pct,
        temp_written_delta,

        ROUND(
            (
                wal_bytes_delta
                / 1024
                / 1024
            )::numeric,
            2
        ) AS wal_mb,

        query_text

    FROM query_deltas

    WHERE queryid = %s
      AND cluster_id = %s::text
      AND database_name = %s::text
      AND captured_at >=
          now() - (%s * interval '1 minute')

    ORDER BY captured_at ASC
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql,
                (
                    queryid,
                    cluster_id,
                    database,
                    minutes,
                ),
            )
            return cur.fetchall()



@app.get("/api/query-details/{queryid}")
def query_details(
    queryid: int,
    cluster_id: str,
    database: str,
    minutes: int = Query(default=60, ge=1, le=10080),
):
    metrics_sql = """
    SELECT
        cluster_id,
        MAX(cluster_name) AS cluster_name,
        database_name,
        queryid::text AS queryid,
        SUM(calls_delta) AS calls,
        ROUND(SUM(exec_time_delta)::numeric, 2) AS total_exec_ms,
        ROUND(
            (SUM(exec_time_delta) / NULLIF(SUM(calls_delta), 0))::numeric,
            2
        ) AS avg_exec_ms,
        SUM(shared_reads_delta) AS shared_reads,
        ROUND(AVG(cache_hit_pct)::numeric, 2) AS avg_cache_hit_pct,
        SUM(temp_written_delta) AS temp_blocks,
        ROUND((SUM(wal_bytes_delta) / 1024 / 1024)::numeric, 2) AS wal_mb,
        MIN(captured_at) AS first_seen,
        MAX(captured_at) AS last_seen,
        MAX(query_text) AS query_text
    FROM query_deltas
    WHERE queryid = %s
      AND cluster_id = %s::text
      AND database_name = %s::text
      AND captured_at >= now() - (%s * interval '1 minute')
    GROUP BY cluster_id, database_name, queryid
    """

    findings_sql = """
    WITH ranked AS (
        SELECT
            captured_at,
            severity,
            finding_type,
            metric_value,
            threshold_value,
            message,
            recommendation,
            COUNT(*) OVER (
                PARTITION BY finding_type
            ) AS occurrences,
            ROW_NUMBER() OVER (
                PARTITION BY finding_type
                ORDER BY captured_at DESC, id DESC
            ) AS rn
        FROM findings
        WHERE queryid = %s
          AND cluster_id = %s::text
          AND database_name = %s::text
          AND captured_at >= now() - (%s * interval '1 minute')
    )
    SELECT
        captured_at,
        severity,
        finding_type,
        metric_value,
        threshold_value,
        message,
        recommendation,
        occurrences
    FROM ranked
    WHERE rn = 1
    ORDER BY captured_at DESC
    LIMIT 10
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                metrics_sql,
                (queryid, cluster_id, database, minutes),
            )
            metrics = cur.fetchone()

            if not metrics:
                raise HTTPException(
                    status_code=404,
                    detail="No query data found for the selected time range.",
                )

            cur.execute(
                findings_sql,
                (queryid, cluster_id, database, minutes),
            )
            related_findings = cur.fetchall()

    return {
        "query": metrics,
        "findings": related_findings,
    }


class ClusterTestRequest(BaseModel):
    host: str
    port: int = 5432
    username: str
    password: str
    database: str

class ClusterCreateRequest(BaseModel):
    cluster_id: str = Field(min_length=1, max_length=100)
    cluster_name: str = Field(min_length=1, max_length=200)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=5432, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=200)
    secret_name: str | None = None
    secret_key: str | None = None
    databases: list[str]

@app.post("/api/test-cluster")
def test_cluster(r: ClusterTestRequest):
    try:
        with psycopg.connect(host=r.host, port=r.port, dbname=r.database,
                             user=r.username, password=r.password,
                             connect_timeout=5, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT current_database() database_name,
                    current_setting('server_version') server_version,
                    pg_is_in_recovery() in_recovery""")
                row = cur.fetchone()
        return {"ok": True, **row}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Connection failed: {exc}")

@app.post("/api/configured-clusters")
def save_cluster(r: ClusterCreateRequest):
    dbs = sorted({x.strip() for x in r.databases if x.strip()})

    if not dbs:
        raise HTTPException(
            status_code=400,
            detail="At least one database is required.",
        )

    if not r.secret_name or not r.secret_name.strip():
        raise HTTPException(
            status_code=400,
            detail="Secret name is required.",
        )

    if not r.secret_key or not r.secret_key.strip():
        raise HTTPException(
            status_code=400,
            detail="Secret key is required.",
        )

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""INSERT INTO monitored_clusters
                    (cluster_id,cluster_name,host,port,username,secret_name,secret_key,enabled,engine,updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,true,'postgresql',now())
                    ON CONFLICT (cluster_id) DO UPDATE SET
                    cluster_name=EXCLUDED.cluster_name, host=EXCLUDED.host,
                    port=EXCLUDED.port, username=EXCLUDED.username,
                    secret_name=EXCLUDED.secret_name,
                    secret_key=EXCLUDED.secret_key,
                    enabled=true, engine='postgresql', updated_at=now()""",
                    (r.cluster_id.strip(), r.cluster_name.strip(), r.host.strip(),
                     r.port, r.username.strip(), r.secret_name, r.secret_key))
                for db in dbs:
                    cur.execute("""INSERT INTO monitored_databases
                        (cluster_id,database_name,enabled) VALUES (%s,%s,true)
                        ON CONFLICT (cluster_id,database_name)
                        DO UPDATE SET enabled=true""", (r.cluster_id.strip(), db))
            conn.commit()
        return {"ok": True, "cluster_id": r.cluster_id.strip(), "databases": dbs}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Unable to save cluster: {exc}")


class DatabaseCreateRequest(BaseModel):
    cluster_id: str
    database_name: str


@app.post("/api/configured-databases")
def save_database(r: DatabaseCreateRequest):
    cluster_id = r.cluster_id.strip()
    database_name = r.database_name.strip()

    if not cluster_id:
        raise HTTPException(status_code=400, detail="Cluster ID is required.")

    if not database_name:
        raise HTTPException(status_code=400, detail="Database name is required.")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM monitored_clusters
                WHERE cluster_id = %s
                  AND enabled = true
                  AND engine = 'postgresql'
                """,
                (cluster_id,),
            )

            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Cluster not found.")

            cur.execute(
                """
                INSERT INTO monitored_databases
                    (cluster_id, database_name, enabled)
                VALUES (%s, %s, true)
                ON CONFLICT (cluster_id, database_name)
                DO UPDATE SET enabled = true
                """,
                (cluster_id, database_name),
            )

        conn.commit()

    return {
        "ok": True,
        "cluster_id": cluster_id,
        "database_name": database_name,
    }


@app.post("/api/test-configured-database")
def test_configured_database(r: DatabaseCreateRequest):
    cluster_id = r.cluster_id.strip()
    database_name = r.database_name.strip()

    if not cluster_id or not database_name:
        raise HTTPException(
            status_code=400,
            detail="Cluster ID and database name are required.",
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    host,
                    port,
                    username,
                    secret_name,
                    secret_key
                FROM monitored_clusters
                WHERE cluster_id = %s
                  AND enabled = true
                  AND engine = 'postgresql'
                """,
                (cluster_id,),
            )
            cluster = cur.fetchone()

    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found.")

    try:
        password = read_secret_value(
            cluster["secret_name"],
            cluster["secret_key"],
        )

        with psycopg.connect(
            host=cluster["host"],
            port=cluster["port"],
            dbname=database_name,
            user=cluster["username"],
            password=password,
            connect_timeout=5,
            row_factory=dict_row,
        ) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        current_database() AS database_name,
                        current_setting('server_version') AS server_version,
                        pg_is_in_recovery() AS in_recovery
                    """
                )
                row = cur.fetchone()

        return {"ok": True, **row}

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Connection failed: {exc}",
        )


@app.delete("/api/configured-databases/{cluster_id}/{database_name}")
def disable_database(
    cluster_id: str,
    database_name: str,
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE monitored_databases d
                SET enabled = false
                FROM monitored_clusters c
                WHERE d.cluster_id = %s
                  AND d.database_name = %s
                  AND d.enabled = true
                  AND c.cluster_id = d.cluster_id
                  AND c.engine = 'postgresql'
                RETURNING d.database_name
                """,
                (cluster_id, database_name),
            )
            row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Enabled database not found.",
        )

    return {
        "ok": True,
        "cluster_id": cluster_id,
        "database_name": database_name,
        "enabled": False,
    }


@app.delete("/api/configured-clusters/{cluster_id}")
def disable_cluster(cluster_id: str):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE monitored_clusters
                SET enabled = false,
                    updated_at = now()
                WHERE cluster_id = %s
                  AND enabled = true
                  AND engine = 'postgresql'
                RETURNING cluster_id
                """,
                (cluster_id,),
            )
            row = cur.fetchone()

            if row:
                cur.execute(
                    """
                    UPDATE monitored_databases
                    SET enabled = false
                    WHERE cluster_id = %s
                    """,
                    (cluster_id,),
                )

        conn.commit()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Enabled cluster not found.",
        )

    return {
        "ok": True,
        "cluster_id": cluster_id,
        "enabled": False,
    }


class ExplainRequest(BaseModel):
    cluster_id: str
    database: str
    queryid: str
    parameters: list[str | None] = []


def latest_query_text(
    cluster_id: str,
    database: str,
    queryid: int,
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT query_text
                FROM query_snapshots
                WHERE cluster_id = %s
                  AND database_name = %s
                  AND queryid = %s
                ORDER BY captured_at DESC
                LIMIT 1
                """,
                (
                    cluster_id,
                    database,
                    queryid,
                ),
            )
            row = cur.fetchone()

    if not row:
        raise RuntimeError(
            "Query text was not found in PgScope history."
        )

    return row["query_text"]


def required_parameter_count(
    query_text: str,
):
    numbers = [
        int(value)
        for value in re.findall(
            r"\$(\d+)",
            query_text,
        )
    ]

    return max(numbers) if numbers else 0


def plan_summary(
    plan: dict,
):
    root = plan.get("Plan", {})

    nodes = []
    indexes = []
    seq_scans = []

    def walk(node):
        node_type = node.get(
            "Node Type",
            "Unknown",
        )

        relation = node.get(
            "Relation Name"
        )

        index_name = node.get(
            "Index Name"
        )

        nodes.append(node_type)

        if index_name:
            indexes.append(index_name)

        if (
            node_type == "Seq Scan"
            and relation
        ):
            seq_scans.append(relation)

        for child in node.get(
            "Plans",
            [],
        ):
            walk(child)

    walk(root)

    recommendations = []

    if seq_scans:
        recommendations.append(
            "Sequential scan detected on: "
            + ", ".join(
                sorted(set(seq_scans))
            )
            + ". Review selectivity and indexes."
        )

    if indexes:
        recommendations.append(
            "Indexes used: "
            + ", ".join(
                sorted(set(indexes))
            )
            + "."
        )

    if not recommendations:
        recommendations.append(
            "Review estimated rows, costs, joins and access paths."
        )

    return {
        "root_node":
            root.get("Node Type"),

        "startup_cost":
            root.get("Startup Cost"),

        "total_cost":
            root.get("Total Cost"),

        "plan_rows":
            root.get("Plan Rows"),

        "plan_width":
            root.get("Plan Width"),

        "node_types":
            nodes,

        "indexes":
            sorted(set(indexes)),

        "seq_scans":
            sorted(set(seq_scans)),

        "recommendations":
            recommendations,
    }


@app.post("/api/explain")
def explain_query(
    request: ExplainRequest,
):
    try:
        queryid = int(
            request.queryid
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid queryid.",
        )

    try:
        query_text = latest_query_text(
            request.cluster_id,
            request.database,
            queryid,
        )

        parameter_count = (
            required_parameter_count(
                query_text
            )
        )

        if (
            len(request.parameters)
            < parameter_count
        ):
            return {
                "ok": False,
                "needs_parameters": True,
                "parameter_count": parameter_count,
                "query_text": query_text,
                "message": (
                    f"This query needs "
                    f"{parameter_count} parameter value(s)."
                ),
            }

        with source_connection_for_cluster(
            request.cluster_id,
            request.database,
        ) as conn:
            with conn.cursor() as cur:

                if parameter_count == 0:
                    explain_sql = sql.SQL(
                        "EXPLAIN "
                        "(FORMAT JSON, COSTS TRUE, VERBOSE TRUE) "
                    ) + sql.SQL(query_text)

                    cur.execute(
                        explain_sql
                    )

                else:
                    statement_name = (
                        "pgscope_explain"
                    )

                    prepare_sql = (
                        sql.SQL(
                            "PREPARE {} AS "
                        ).format(
                            sql.Identifier(
                                statement_name
                            )
                        )
                        + sql.SQL(
                            query_text
                        )
                    )

                    cur.execute(
                        prepare_sql
                    )

                    values = []

                    for value in request.parameters[
                        :parameter_count
                    ]:
                        if value is None:
                            values.append(
                                sql.SQL("NULL")
                            )
                        else:
                            values.append(
                                sql.Literal(value)
                            )

                    execute_sql = (
                        sql.SQL(
                            "EXPLAIN "
                            "(FORMAT JSON, COSTS TRUE, VERBOSE TRUE) "
                            "EXECUTE {}("
                        ).format(
                            sql.Identifier(
                                statement_name
                            )
                        )
                        + sql.SQL(", ").join(
                            values
                        )
                        + sql.SQL(")")
                    )

                    cur.execute(
                        execute_sql
                    )

                row = cur.fetchone()

                try:
                    cur.execute(
                        "DEALLOCATE ALL"
                    )
                except Exception:
                    pass

        raw_plan = row[
            "QUERY PLAN"
        ]

        if isinstance(
            raw_plan,
            list,
        ):
            plan = raw_plan[0]
        else:
            plan = raw_plan

        summary = plan_summary(
            plan
        )

        plan_observation = record_plan_observation(
            get_connection,
            request.cluster_id,
            request.database,
            queryid,
            plan,
            summary,
        )

        return {
            "ok": True,
            "queryid": request.queryid,
            "query_fingerprint":
                plan_observation[
                    "query_fingerprint"
                ],
            "cluster_id": request.cluster_id,
            "database": request.database,
            "query_text": query_text,
            "parameter_count": parameter_count,
            "plan": plan,
            "summary": summary,
            "plan_history":
                plan_observation,
            "analyze": False,
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unable to generate EXPLAIN plan: "
                f"{exc}"
            ),
        )




@app.get("/api/plan-history")
def query_plan_history(
    cluster_id: str,
    database: str,
    queryid: str,
    limit: int = Query(
        default=20,
        ge=1,
        le=200,
    ),
):
    try:
        parsed_queryid = int(
            queryid
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid queryid.",
        )

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        id,
                        captured_at,
                        queryid::text
                            AS queryid,
                        plan_hash,
                        plan_structure,
                        root_node,
                        total_cost,
                        plan_rows,
                        calls_delta,
                        avg_exec_ms,
                        shared_reads_delta,
                        temp_written_delta,
                        wal_bytes_delta
                    FROM query_plan_history
                    WHERE cluster_id = %s
                      AND database_name = %s
                      AND queryid = %s
                    ORDER BY
                        captured_at DESC,
                        id DESC
                    LIMIT %s
                    """,
                    (
                        cluster_id,
                        database,
                        parsed_queryid,
                        limit,
                    ),
                )

                rows = cur.fetchall()

        return {
            "ok": True,
            "cluster_id":
                cluster_id,

            "database":
                database,

            "queryid":
                str(parsed_queryid),

            "query_fingerprint":
                str(parsed_queryid),

            "plans":
                rows,
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unable to load plan history: "
                f"{exc}"
            ),
        )




def _health_check(title, status, value, detail, recommendation=None):
    return {"title":title,"status":status,"value":value,"detail":detail,"recommendation":recommendation}

@app.get("/api/health-report")
def health_report(cluster_id: str, database: str, minutes: int = Query(default=1440, ge=15, le=10080)):
    checks=[]; metrics={}
    try:
        with source_connection_for_cluster(cluster_id,database) as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT current_setting('server_version') server_version,
                    pg_postmaster_start_time() started_at, now()-pg_postmaster_start_time() uptime,
                    pg_database_size(current_database()) database_bytes,
                    current_setting('max_connections')::int max_connections,
                    current_setting('shared_buffers') shared_buffers,
                    current_setting('work_mem') work_mem,
                    current_setting('effective_cache_size') effective_cache_size""")
                metrics["server"]=cur.fetchone()
                cur.execute("""SELECT count(*) connections,
                    count(*) FILTER (WHERE state='active') active,
                    count(*) FILTER (WHERE xact_start IS NOT NULL AND now()-xact_start>interval '5 minutes') long_transactions
                    FROM pg_stat_activity WHERE datname=current_database()""")
                metrics["connections"]=cur.fetchone()
                cur.execute("""SELECT blks_read,blks_hit,temp_files,temp_bytes,deadlocks
                    FROM pg_stat_database WHERE datname=current_database()""")
                metrics["db"]=cur.fetchone()
                cur.execute("""SELECT coalesce(sum(n_live_tup),0)::bigint live_tuples,
                    coalesce(sum(n_dead_tup),0)::bigint dead_tuples,
                    coalesce(sum(seq_scan),0)::bigint seq_scans,
                    coalesce(sum(idx_scan),0)::bigint index_scans,
                    coalesce(sum(autovacuum_count),0)::bigint autovacuums
                    FROM pg_stat_user_tables""")
                metrics["tables"]=cur.fetchone()
                cur.execute("""SELECT schemaname,relname,n_live_tup,n_dead_tup,
                    CASE WHEN n_live_tup+n_dead_tup=0 THEN 0 ELSE round(100.0*n_dead_tup/(n_live_tup+n_dead_tup),2) END dead_pct
                    FROM pg_stat_user_tables WHERE n_dead_tup>0 ORDER BY n_dead_tup DESC LIMIT 10""")
                metrics["dead_tuple_tables"]=cur.fetchall()
                cur.execute("""SELECT schemaname,relname,pg_total_relation_size(relid) total_bytes,seq_scan,idx_scan,n_live_tup
                    FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 10""")
                metrics["largest_tables"]=cur.fetchall()
                cur.execute("""SELECT schemaname,relname table_name,indexrelname index_name,idx_scan,
                    pg_relation_size(indexrelid) index_bytes FROM pg_stat_user_indexes
                    WHERE idx_scan=0 AND pg_relation_size(indexrelid)>=1024*1024
                    ORDER BY pg_relation_size(indexrelid) DESC LIMIT 10""")
                metrics["unused_indexes"]=cur.fetchall()

        s=metrics["server"]; c=metrics["connections"]; d=metrics["db"]; t=metrics["tables"]
        cp=round(100*c["connections"]/s["max_connections"],2) if s["max_connections"] else 0
        cs="CRITICAL" if cp>=90 else "WARNING" if cp>=75 else "OK"
        checks.append(_health_check("Connection utilization",cs,f'{c["connections"]}/{s["max_connections"]} ({cp}%)',
            "Connections compared with max_connections.","Review pooling and max_connections." if cs!="OK" else None))
        total=(d["blks_hit"] or 0)+(d["blks_read"] or 0)
        hp=round(100*(d["blks_hit"] or 0)/total,2) if total else None
        hs="INFO" if hp is None else "WARNING" if hp<90 else "OK"
        checks.append(_health_check("Cache hit ratio",hs,"-" if hp is None else f"{hp}%",
            "Cumulative PostgreSQL buffer-cache hit ratio.","Investigate memory sizing and high-read queries." if hs=="WARNING" else None))
        live=t["live_tuples"] or 0; dead=t["dead_tuples"] or 0
        dp=round(100*dead/(live+dead),2) if live+dead else 0
        ds="CRITICAL" if dp>=20 else "WARNING" if dp>=10 else "OK"
        checks.append(_health_check("Dead tuples",ds,f"{dead} ({dp}%)","Estimated dead tuples across user tables.",
            "Review autovacuum and high-churn tables." if ds!="OK" else None))
        lt=c["long_transactions"] or 0
        checks.append(_health_check("Long transactions","WARNING" if lt else "OK",str(lt),
            "Transactions open for more than five minutes.","Investigate long-running transactions." if lt else None))
        tm=round(float(d["temp_bytes"] or 0)/1024/1024,2)
        checks.append(_health_check("Temporary file usage","WARNING" if tm>=1024 else "OK",f"{tm} MB",
            "Cumulative temporary bytes.","Review work_mem and sort/hash workloads." if tm>=1024 else None))
        dl=d["deadlocks"] or 0
        checks.append(_health_check("Deadlocks","WARNING" if dl else "OK",str(dl),"Cumulative database deadlocks.",
            "Review transaction and lock ordering." if dl else None))
        ui=len(metrics["unused_indexes"])
        checks.append(_health_check("Large unused indexes","WARNING" if ui else "OK",str(ui),
            "Indexes >=1 MB with zero scans.","Validate workload before removing indexes." if ui else None))

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT count(*) FILTER(WHERE severity='CRITICAL') critical,
                    count(*) FILTER(WHERE severity='WARNING') warning FROM findings
                    WHERE cluster_id=%s AND database_name=%s
                    AND captured_at>=now()-(%s*interval '1 minute')""",(cluster_id,database,minutes))
                pf=cur.fetchone(); metrics["pgscope_findings"]=pf
                cur.execute("""SELECT queryid::text queryid,max(query_text) query_text,sum(calls_delta) calls,
                    round(sum(exec_time_delta)::numeric,2) total_exec_ms,
                    round((sum(exec_time_delta)/nullif(sum(calls_delta),0))::numeric,2) avg_exec_ms,
                    round((sum(wal_bytes_delta)/1024/1024)::numeric,2) wal_mb
                    FROM query_deltas WHERE cluster_id=%s AND database_name=%s
                    AND captured_at>=now()-(%s*interval '1 minute')
                    GROUP BY queryid ORDER BY sum(exec_time_delta) DESC LIMIT 10""",(cluster_id,database,minutes))
                metrics["top_queries"]=cur.fetchall()

                # Historical workload comparison:
                # selected period versus the immediately preceding period.
                cur.execute("""
                    WITH periods AS (
                        SELECT
                            queryid,
                            max(query_text) AS query_text,

                            sum(calls_delta) FILTER (
                                WHERE captured_at >= now() - (%s * interval '1 minute')
                            ) AS current_calls,

                            sum(exec_time_delta) FILTER (
                                WHERE captured_at >= now() - (%s * interval '1 minute')
                            ) AS current_exec_ms,

                            sum(calls_delta) FILTER (
                                WHERE captured_at < now() - (%s * interval '1 minute')
                                  AND captured_at >= now() - (%s * 2 * interval '1 minute')
                            ) AS previous_calls,

                            sum(exec_time_delta) FILTER (
                                WHERE captured_at < now() - (%s * interval '1 minute')
                                  AND captured_at >= now() - (%s * 2 * interval '1 minute')
                            ) AS previous_exec_ms

                        FROM query_deltas
                        WHERE cluster_id=%s
                          AND database_name=%s
                          AND captured_at >= now() - (%s * 2 * interval '1 minute')
                        GROUP BY queryid
                    )
                    SELECT
                        queryid::text AS queryid,
                        query_text,

                        coalesce(current_calls,0) AS current_calls,
                        round(coalesce(current_exec_ms,0)::numeric,2)
                            AS current_exec_ms,

                        round((
                            coalesce(current_exec_ms,0)
                            / nullif(current_calls,0)
                        )::numeric,3) AS current_avg_ms,

                        coalesce(previous_calls,0) AS previous_calls,
                        round(coalesce(previous_exec_ms,0)::numeric,2)
                            AS previous_exec_ms,

                        round((
                            coalesce(previous_exec_ms,0)
                            / nullif(previous_calls,0)
                        )::numeric,3) AS previous_avg_ms,

                        CASE
                            WHEN previous_calls > 0
                             AND current_calls > 0
                             AND previous_exec_ms > 0
                            THEN round(
                                100 * (
                                    (
                                        current_exec_ms
                                        / nullif(current_calls,0)
                                    )
                                    /
                                    (
                                        previous_exec_ms
                                        / nullif(previous_calls,0)
                                    )
                                    - 1
                                )::numeric,
                                1
                            )
                            ELSE NULL
                        END AS latency_change_pct

                    FROM periods
                    WHERE coalesce(current_calls,0) > 0
                       OR coalesce(previous_calls,0) > 0
                    ORDER BY coalesce(current_exec_ms,0) DESC
                    LIMIT 50
                """, (
                    minutes,
                    minutes,
                    minutes,
                    minutes,
                    minutes,
                    minutes,
                    cluster_id,
                    database,
                    minutes,
                ))

                comparison = cur.fetchall()
                metrics["query_comparison"] = comparison

                metrics["regressions"] = [
                    q for q in comparison
                    if q["latency_change_pct"] is not None
                    and q["current_calls"] >= 5
                    and q["previous_calls"] >= 5
                    and float(q["latency_change_pct"]) >= 25
                ][:10]

                metrics["improvements"] = [
                    q for q in comparison
                    if q["latency_change_pct"] is not None
                    and q["current_calls"] >= 5
                    and q["previous_calls"] >= 5
                    and float(q["latency_change_pct"]) <= -25
                ][:10]

                current_calls = sum(
                    int(q["current_calls"] or 0)
                    for q in comparison
                )
                previous_calls = sum(
                    int(q["previous_calls"] or 0)
                    for q in comparison
                )

                current_exec = sum(
                    float(q["current_exec_ms"] or 0)
                    for q in comparison
                )
                previous_exec = sum(
                    float(q["previous_exec_ms"] or 0)
                    for q in comparison
                )

                metrics["workload_comparison"] = {
                    "current_calls": current_calls,
                    "previous_calls": previous_calls,
                    "current_exec_ms": round(current_exec, 2),
                    "previous_exec_ms": round(previous_exec, 2),
                    "current_avg_ms": round(
                        current_exec / current_calls, 3
                    ) if current_calls else None,
                    "previous_avg_ms": round(
                        previous_exec / previous_calls, 3
                    ) if previous_calls else None,
                }

        fs="CRITICAL" if (pf["critical"] or 0)>0 else "WARNING" if (pf["warning"] or 0)>0 else "OK"
        checks.append(_health_check("PgScope findings",fs,f'{pf["critical"] or 0} critical / {pf["warning"] or 0} warning',
            "Findings in the selected report period.","Prioritize critical findings." if fs!="OK" else None))
        penalty=sum(20 if x["status"]=="CRITICAL" else 8 if x["status"]=="WARNING" else 0 for x in checks)
        score=max(0,100-penalty)
        status="CRITICAL" if score<60 else "NEEDS ATTENTION" if score<80 else "GOOD" if score<95 else "EXCELLENT"
        return {"ok":True,"version":VERSION,"cluster_id":cluster_id,"database":database,"period_minutes":minutes,
                "score":score,"status":status,"checks":checks,
                "recommendations":[x["recommendation"] for x in checks if x.get("recommendation")],"metrics":metrics}
    except Exception as exc:
        raise HTTPException(status_code=400,detail=f"Unable to generate health report: {exc}")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>PgScope</title>

<style>
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
    background: #0f172a;
    color: #e5e7eb;
    margin: 0;
    padding: 28px;
}

h1 {
    margin: 0;
    font-size: 32px;
}

.subtitle {
    color: #94a3b8;
    margin-top: 4px;
    margin-bottom: 25px;
}

.overview-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
    margin-bottom: 30px;
}

.cluster-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 18px;
    cursor: pointer;
}

.cluster-card:hover {
    border-color: #60a5fa;
}

.cluster-title {
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 10px;
}

.cluster-status {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    margin-bottom: 12px;
}

.status-HEALTHY,
.status-OK {
    color: #86efac;
    background: #14532d;
}

.status-WARNING {
    color: #fde68a;
    background: #713f12;
}

.status-CRITICAL {
    color: #fecaca;
    background: #7f1d1d;
}

.status-OFFLINE,
.status-UNKNOWN {
    color: #cbd5e1;
    background: #334155;
}

.status-row {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 12px;
}

.status-label {
    color: #94a3b8;
    font-size: 11px;
    margin-right: 4px;
}

.cluster-stats {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
    font-size: 13px;
}

.cluster-stat-label {
    color: #94a3b8;
}

.cluster-stat-value {
    font-weight: 700;
    margin-top: 3px;
}


.add-btn { background:#2563eb; border-color:#3b82f6; font-weight:700; float:right; margin-bottom:14px; }
.modal-bg { display:none; position:fixed; inset:0; background:rgba(2,6,23,.8); z-index:1000; align-items:center; justify-content:center; }
.modal { width:min(620px,calc(100vw - 40px)); background:#1e293b; border:1px solid #475569; border-radius:14px; padding:22px; }
.form-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
.form-field { display:flex; flex-direction:column; gap:5px; }
.form-field.full { grid-column:1/-1; }
.form-field input { background:#0f172a; color:#e5e7eb; border:1px solid #475569; padding:9px; border-radius:6px; }
.form-actions { display:flex; gap:10px; margin-top:18px; }
.form-status { margin-top:14px; color:#93c5fd; white-space:pre-wrap; }

.toolbar {
    background: #1e293b;
    padding: 15px;
    border-radius: 10px;
    margin-bottom: 25px;
    display: flex;
    gap: 15px;
    align-items: center;
}

.engine-tabs {
    display: flex;
    gap: 8px;
    margin: 0 0 16px;
    border-bottom: 1px solid #334155;
}

.platform-status-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
    margin: 22px 0 28px;
}

.platform-status-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 17px 19px;
    cursor: pointer;
}

.platform-status-card:hover {
    border-color: #64748b;
}

.platform-status-head,
.platform-status-metrics {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
}

.platform-status-title {
    font-size: 18px;
    font-weight: 700;
}

.platform-status-metrics {
    margin-top: 14px;
    color: #94a3b8;
    font-size: 13px;
}

.platform-status-metrics strong {
    color: #e5e7eb;
}

@media (max-width: 760px) {
    .platform-status-grid {
        grid-template-columns: 1fr;
    }
}

.engine-tab {
    border: 0;
    border-bottom: 3px solid transparent;
    border-radius: 8px 8px 0 0;
    padding: 11px 22px;
    color: #94a3b8;
    font-weight: 700;
}

.engine-tab.active {
    color: #f8fafc;
    background: #1e293b;
    border-bottom-color: #3b82f6;
}

select,
button {
    background: #0f172a;
    color: #e5e7eb;
    border: 1px solid #475569;
    padding: 8px 12px;
    border-radius: 6px;
}

button {
    cursor: pointer;
}

button:hover {
    background: #334155;
}

.cards {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
    margin-bottom: 30px;
}

.card {
    background: #1e293b;
    padding: 18px;
    border-radius: 10px;
}

.card-title {
    color: #94a3b8;
    font-size: 13px;
}

.card-value {
    font-size: 26px;
    font-weight: 700;
    margin-top: 7px;
}

.panel {
    background: #1e293b;
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 30px;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}

th,
td {
    text-align: left;
    padding: 10px;
    border-bottom: 1px solid #334155;
    vertical-align: top;
}

th {
    color: #94a3b8;
    font-weight: 600;
}

.query {
    font-family: Menlo, Monaco, monospace;
    font-size: 11px;
    max-width: 450px;
    white-space: pre-wrap;
}

.recommendation {
    color: #93c5fd;
    max-width: 400px;
}

.critical {
    color: #f87171;
    font-weight: bold;
}

.warning {
    color: #fbbf24;
    font-weight: bold;
}

.explain-button {
    color: #c084fc;
    border-color: #8b5cf6;
}

.danger-button {
    border-color: #7f1d1d;
    color: #fca5a5;
}

.danger-button:hover {
    background: rgba(127, 29, 29, 0.25);
    border-color: #ef4444;
}

.query-click {
    cursor: pointer;
    color: #60a5fa;
    transition: color 0.15s ease;
}

.query-click:hover {
    color: #93c5fd;
    text-decoration: underline;
}

.query-details-metrics {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px;
    margin: 16px 0 20px;
}

.query-detail-card {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 12px;
}

.query-detail-card .label {
    color: #94a3b8;
    font-size: 12px;
    margin-bottom: 5px;
}

.query-detail-card .value {
    font-size: 18px;
    font-weight: 700;
}

.severity-badge {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
}

.severity-critical {
    background: rgba(239, 68, 68, 0.15);
    color: #fca5a5;
}

.severity-warning {
    background: rgba(245, 158, 11, 0.15);
    color: #fcd34d;
}

.query-details-findings {
    width: 100%;
    margin-top: 10px;
}

.explain-modal-bg {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(2, 6, 23, 0.82);
    align-items: center;
    justify-content: center;
    z-index: 1100;
}

.explain-modal {
    width: min(980px, calc(100vw - 40px));
    max-height: calc(100vh - 50px);
    overflow: auto;
    background: #1e293b;
    border: 1px solid #475569;
    border-radius: 14px;
    padding: 22px;
}

.explain-plan {
    font-family: Menlo, Monaco, monospace;
    font-size: 12px;
    white-space: pre-wrap;
    background: #0f172a;
    padding: 14px;
    border-radius: 8px;
    overflow: auto;
}

.explain-summary {
    background: #0f172a;
    padding: 14px;
    border-radius: 8px;
    margin-bottom: 14px;
}

.explain-params {
    margin: 14px 0;
}

.explain-params input {
    width: 100%;
    box-sizing: border-box;
    background: #0f172a;
    color: #e5e7eb;
    border: 1px solid #475569;
    padding: 9px;
    border-radius: 6px;
}

.history-button {
    color: #60a5fa;
    border-color: #3b82f6;
}

.history-query {
    font-family: Menlo, Monaco, monospace;
    background: #0f172a;
    padding: 12px;
    border-radius: 6px;
    margin-bottom: 20px;
    white-space: pre-wrap;
}

.chart-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
}

.chart-container {
    background: #0f172a;
    padding: 15px;
    border-radius: 8px;
}

canvas {
    width: 100%;
    height: 220px;
    background: #0f172a;
}

.chart-label {
    font-size: 13px;
    color: #94a3b8;
    margin-bottom: 8px;
}

.status {
    font-size: 12px;
    color: #94a3b8;
    margin-left: auto;
}

.history-error {
    color: #f87171;
    font-weight: bold;
}

.report-button { color:#86efac; border-color:#22c55e; font-weight:700; }
.report-modal-bg { display:none; position:fixed; inset:0; background:rgba(2,6,23,.86); z-index:1200; align-items:center; justify-content:center; }
.report-modal { width:min(1100px,calc(100vw - 40px)); max-height:calc(100vh - 50px); overflow:auto; background:#1e293b; border:1px solid #475569; border-radius:14px; padding:22px; }
.report-score { font-size:42px; font-weight:800; margin:8px 0; }
.report-check { background:#0f172a; border:1px solid #334155; border-radius:8px; padding:12px; margin:8px 0; }
.report-check-detail { color:#94a3b8; margin-top:5px; }
.report-rec { color:#93c5fd; margin-top:5px; }

@media print {
    body * {
        visibility: hidden !important;
    }

    #report-modal,
    #report-modal * {
        visibility: visible !important;
    }

    #report-modal {
        position: static !important;
        display: block !important;
        background: white !important;
        color: black !important;
    }

    .report-modal {
        position: static !important;
        width: auto !important;
        max-height: none !important;
        overflow: visible !important;
        background: white !important;
        color: black !important;
        border: none !important;
        padding: 0 !important;
        box-shadow: none !important;
    }

    .report-modal h2,
    .report-modal h3,
    .report-modal div,
    .report-modal td,
    .report-modal th,
    .report-modal li {
        color: black !important;
    }

    .report-modal table {
        border-collapse: collapse !important;
        width: 100% !important;
    }

    .report-modal th,
    .report-modal td {
        border: 1px solid #999 !important;
        padding: 6px !important;
    }

    .report-check,
    .report-score,
    .report-check-detail,
    .report-rec,
    .subtitle {
        background: white !important;
        color: black !important;
        border-color: #bbb !important;
    }

    .form-actions,
    #report-status {
        display: none !important;
    }

    .cluster-status {
        background: white !important;
        color: black !important;
        border: 1px solid #666 !important;
    }
}

</style>
</head>

<body>

<h1>PgScope</h1>
<div class="subtitle">PostgreSQL &amp; Oracle Performance Advisor</div>


<button id="add-cluster-button" class="add-btn">+ Add Cluster / DB</button>
<a href="/logout" style="float:right;margin:8px 12px 0 0;color:#94a3b8;text-decoration:none">Logout</a>
<div style="clear:both"></div>

<div id="database-modal" class="modal-bg">
<div class="modal">
<h2 id="database-modal-title">Add Database</h2>

<div class="form-grid">
<div class="form-field full">
<label>Cluster</label>
<input id="database-cluster-name" readonly>
</div>

<div class="form-field full">
<label id="database-name-label">Database name</label>
<input id="new-database-name" placeholder="shopdemo">
<div class="form-help">
The database will use the existing cluster host, monitor user and Kubernetes Secret.
</div>
</div>
</div>

<div class="form-actions">
<button id="test-database-button">Test connection</button>
<button id="save-database-button" class="primary-button">Add database</button>
<button id="cancel-database-button">Cancel</button>
</div>

<div id="database-form-status" class="form-status"></div>
</div>
</div>

<div id="cluster-modal" class="modal-bg">
<div class="modal">
<h2 id="cluster-modal-title">Add Cluster / DB</h2>
<div class="form-grid">
<div class="form-field"><label>Cluster ID</label><input id="new-cluster-id" placeholder="prod-eu-1"></div>
<div class="form-field"><label>Name</label><input id="new-cluster-name" placeholder="Production EU"></div>
<div class="form-field"><label>Host</label><input id="new-host" placeholder="postgres-rw"></div>
<div class="form-field"><label>Port</label><input id="new-port" type="number" value="5432"></div>
<div class="form-field"><label>Username</label><input id="new-username" placeholder="pgscope_monitor"></div>
<div class="form-field"><label>Password (test only)</label><input id="new-password" type="password"></div>
<div class="form-field full"><label id="databases-label">Databases</label><input id="new-databases" placeholder="postgres, appdb"></div>
<div class="form-field"><label>Kubernetes secret name</label><input id="new-secret-name" placeholder="pgscope-db"></div>
<div class="form-field"><label>Secret key</label><input id="new-secret-key" placeholder="lab2-source-password"></div>
</div>
<div class="form-actions">
<button id="test-cluster-button">Test connection</button>
<button id="save-cluster-button" class="primary-button">Save cluster</button>
<button id="cancel-cluster-button">Cancel</button>
</div>
<div id="cluster-form-status" class="form-status"></div>
</div>
</div>


<div id="query-details-modal" class="explain-modal-bg">
<div class="explain-modal">
<h2>Query Details</h2>
<div id="query-details-status" class="form-status">Loading...</div>
<div id="query-details-content" style="display:none">
<div id="query-details-sql" class="history-query"></div>
<div id="query-details-metrics" class="query-details-metrics"></div>
<h3>Recent Findings</h3>
<div id="query-details-findings"></div>
<div class="modal-actions" style="margin-top:18px">
<button class="history-button" onclick="queryDetailsHistory()">History</button>
<button class="explain-button" onclick="queryDetailsExplain()">Explain</button>
<button onclick="hideQueryDetailsModal()">Close</button>
</div>
</div>
</div>
</div>

<div id="explain-modal" class="explain-modal-bg">
<div class="explain-modal">

<h2>Query Explain Plan</h2>

<div id="explain-sql" class="history-query"></div>

<div id="explain-parameter-area" class="explain-params" style="display:none">
<label id="explain-parameter-label">Parameters</label>
<input
    id="explain-parameters"
    placeholder="Example: 10, 500000">
<div class="form-help">
Enter values in $1, $2, ... order. PgScope uses EXPLAIN only — not EXPLAIN ANALYZE.
</div>
</div>

<div class="modal-actions">
<button id="generate-explain-button" class="primary-button">
Generate Plan
</button>

<button id="close-explain-button">
Close
</button>
</div>

<div id="explain-status" class="form-status"></div>

<div id="explain-result" style="display:none">
<h3>Summary</h3>
<div id="explain-summary" class="explain-summary"></div>

<h3>Plan JSON</h3>
<pre id="explain-plan" class="explain-plan"></pre>
</div>

</div>
</div>


<div id="report-modal" class="report-modal-bg"><div class="report-modal">
<h2 id="report-title">Database Health Report</h2>
<div class="form-grid" style="margin-bottom:14px">
<div class="form-field">
<label>Customer</label>
<input id="report-customer" placeholder="Customer AS">
</div>
<div class="form-field">
<label>Environment</label>
<input id="report-environment" placeholder="Production">
</div>
</div>
<div id="report-target" class="subtitle"></div>
<div id="report-status" class="form-status"></div><div id="report-content" style="display:none">
<div id="report-meta" class="report-check" style="margin-bottom:14px"></div>
<div id="report-score" class="report-score"></div><div id="report-grade" class="cluster-status"></div>
<h3>Health Checks</h3><div id="report-checks"></div><h3>Recommendations</h3><div id="report-recommendations"></div>
<h3>Top Queries</h3><table><thead><tr><th id="report-query-id-heading">Query ID</th><th id="report-calls-heading">Calls</th><th>Total ms</th><th>Avg ms</th><th id="report-io-heading">WAL MB</th><th>Query</th></tr></thead>
<tbody id="report-top-queries"></tbody></table></div>
<div class="form-actions"><button id="print-report-button" class="report-button">Print / Save PDF</button><button id="close-report-button">Close</button></div></div></div>

<div class="platform-status-grid" aria-label="Platform status">
<div class="platform-status-card" data-engine="postgresql">
<div class="platform-status-head">
<div class="platform-status-title">PostgreSQL</div>
<span id="postgresql-platform-status" class="cluster-status status-UNKNOWN">LOADING</span>
</div>
<div class="platform-status-metrics">
<span>Clusters <strong id="postgresql-platform-clusters">-</strong></span>
<span>Databases <strong id="postgresql-platform-databases">-</strong></span>
<span>Last collection <strong id="postgresql-platform-last">-</strong></span>
</div>
</div>
<div class="platform-status-card" data-engine="oracle">
<div class="platform-status-head">
<div class="platform-status-title">Oracle</div>
<span id="oracle-platform-status" class="cluster-status status-UNKNOWN">LOADING</span>
</div>
<div class="platform-status-metrics">
<span>Clusters <strong id="oracle-platform-clusters">-</strong></span>
<span>Databases <strong id="oracle-platform-databases">-</strong></span>
<span>Last collection <strong id="oracle-platform-last">-</strong></span>
</div>
</div>
</div>

<div id="pg-cluster-overview-section">
<h2>PostgreSQL Cluster Overview</h2>
<div id="cluster-overview" class="overview-grid"></div>
</div>

<div class="engine-tabs" role="tablist" aria-label="Database engine">
<button class="engine-tab active" type="button" role="tab" aria-selected="true" data-engine="postgresql">PostgreSQL</button>
<button class="engine-tab" type="button" role="tab" aria-selected="false" data-engine="oracle">Oracle</button>
</div>

<div class="toolbar">
<select id="engine-select" hidden aria-hidden="true">
<option value="postgresql">PostgreSQL</option>
<option value="oracle">Oracle</option>
</select>
<label>Cluster</label>
<select id="cluster-select"></select>

<label>Database</label>
<select id="database-select"></select>

<label>Time range</label>
<select id="minutes-select">
<option value="15">15 minutes</option>
<option value="60" selected>1 hour</option>
<option value="360">6 hours</option>
<option value="1440">24 hours</option>
<option value="4320">3 days</option>
<option value="10080">7 days</option>
</select>

<button id="refresh-button">Refresh</button>
<button id="add-database-button">+ Add database</button>
<button id="disable-database-button" class="danger-button">Disable database</button>
<button id="disable-cluster-button" class="danger-button">Disable cluster</button>
<button id="generate-report-button" class="report-button">Generate Report</button>
<div id="refresh-status" class="status">Ready</div>
</div>

<div class="cards" id="pg-summary-cards">
<div class="card">
<div class="card-title">Findings last hour</div>
<div id="findings-count" class="card-value">-</div>
</div>

<div class="card">
<div class="card-title">Critical findings</div>
<div id="critical-count" class="card-value">-</div>
</div>

<div class="card">
<div class="card-title">Databases seen</div>
<div id="database-count" class="card-value">-</div>
</div>

<div class="card">
<div class="card-title">Last collection</div>
<div id="last-collection" class="card-value" style="font-size:14px">-</div>
</div>
</div>

<div class="panel" id="pg-findings-panel">
<h2>Latest Findings</h2>

<table>
<thead>
<tr>
<th>Time</th>
<th>Severity</th>
<th>Type</th>
<th>Message</th>
<th>Recommendation</th>
<th>Query</th>
</tr>
</thead>
<tbody id="findings-table"></tbody>
</table>
</div>

<div class="panel" id="pg-top-queries-panel">
<h2>Top Queries</h2>

<table>
<thead>
<tr>
<th>Query ID</th>
<th>Calls</th>
<th>Total ms</th>
<th>Avg ms</th>
<th>Reads</th>
<th>Cache %</th>
<th>WAL MB</th>
<th>History</th>
<th>Explain</th>
<th>Query</th>
</tr>
</thead>
<tbody id="queries-table"></tbody>
</table>
</div>


<div id="oracle-dashboard" style="display:none">

<div class="panel">
<h2>Oracle Top SQL</h2>

<table>
<thead>
<tr>
<th>SQL ID</th>
<th>Plan Hash</th>
<th>Executions</th>
<th>Elapsed ms</th>
<th>CPU ms</th>
<th>Avg ms</th>
<th>Buffer Gets</th>
<th>Disk Reads</th>
<th>Rows</th>
<th>History / Plan</th>
<th>SQL</th>
</tr>
</thead>

<tbody id="oracle-top-sql-table"></tbody>
</table>
</div>


<div
    class="panel"
    id="oracle-sql-detail-panel"
    style="display:none"
>

<button
    class="oracle-close"
    onclick="hideOracleSqlDetails()"
>
Close
</button>

<h2>
Oracle SQL Details —
<span id="oracle-detail-sql-id"></span>
</h2>

<div
    id="oracle-detail-status"
    class="oracle-status"
></div>

<div
    id="oracle-detail-content"
    style="display:none"
>

<div
    id="oracle-detail-metrics"
    class="oracle-detail-grid"
></div>

<h3>SQL</h3>

<div
    id="oracle-detail-sql"
    class="oracle-sql-text"
></div>


<div class="oracle-detail-section">

<h3>History</h3>

<table>
<thead>
<tr>
<th>Time</th>
<th>Plan Hash</th>
<th>Executions</th>
<th>Elapsed ms</th>
<th>CPU ms</th>
<th>Avg ms</th>
<th>Buffer Gets</th>
<th>Disk Reads</th>
<th>Rows</th>
</tr>
</thead>

<tbody id="oracle-history-table"></tbody>
</table>

</div>


<div class="oracle-detail-section">

<h3>Sessions currently using this SQL</h3>

<table>
<thead>
<tr>
<th>Inst</th>
<th>SID</th>
<th>Serial#</th>
<th>User</th>
<th>Status</th>
<th>Event</th>
<th>Wait Class</th>
<th>Seconds Wait</th>
<th>Machine</th>
<th>Program</th>
</tr>
</thead>

<tbody id="oracle-query-sessions-table"></tbody>
</table>

</div>


<div class="oracle-detail-section">

<h3>Current Execution Plan</h3>

<div class="subtitle">
Reads the current shared-pool plan from V$SQL_PLAN.
No AWR/ASH or SQL Monitor is used.
The configured Kubernetes Secret is used automatically.
</div>

<div class="oracle-plan-form">
<input
    id="oracle-plan-child"
    type="number"
    placeholder="Child # optional"
>

</div>

<button
    onclick="loadOracleCurrentPlan()"
    class="primary-button"
>
Load Current Plan
</button>

<button
    onclick="explainOracleSql()"
    class="explain-button"
>
Explain SQL
</button>

<div
    id="oracle-plan-status"
    class="oracle-status"
></div>

<div
    id="oracle-plan-result"
    style="display:none"
>

<div
    id="oracle-plan-summary"
    class="oracle-detail-grid"
></div>

<table class="oracle-plan-table">

<thead>
<tr>
<th>Child</th>
<th>ID</th>
<th>Operation</th>
<th>Object</th>
<th>Rows</th>
<th>Cost</th>
<th>Access Predicates</th>
<th>Filter Predicates</th>
</tr>
</thead>

<tbody id="oracle-plan-table"></tbody>

</table>

</div>

<div id="oracle-explain-result" style="display:none">
<h3>Explain Plan</h3>
<pre id="oracle-explain-plan" class="explain-plan"></pre>
</div>

</div>

</div>

</div>


<div class="panel">

<h2>Oracle Sessions</h2>

<table>

<thead>
<tr>
<th>Inst</th>
<th>SID</th>
<th>Serial#</th>
<th>User</th>
<th>Status</th>
<th>SQL ID</th>
<th>Event</th>
<th>Wait Class</th>
<th>Machine</th>
<th>Program</th>
</tr>
</thead>

<tbody id="oracle-sessions-table"></tbody>

</table>

</div>


<div class="panel">

<h2>Blocking Sessions</h2>

<table>

<thead>
<tr>
<th>Blocked Inst</th>
<th>Blocked SID</th>
<th>User</th>
<th>SQL ID</th>
<th>Event</th>
<th>Wait Class</th>
<th>Seconds</th>
<th>Blocker Inst</th>
<th>Blocker SID</th>
<th>Blocker User</th>
<th>Blocker SQL</th>
<th>Blocker Program</th>
</tr>
</thead>

<tbody id="oracle-blocking-table"></tbody>

</table>

</div>


<div class="panel">

<h2>Wait Events</h2>

<table>

<thead>
<tr>
<th>Wait Class</th>
<th>Total Waits</th>
<th>Time Waited ms</th>
</tr>
</thead>

<tbody id="oracle-waits-table"></tbody>

</table>

</div>

</div>


<div class="panel" id="history-panel">
<h2>Query History</h2>

<div id="history-status">
Select History on a query above.
</div>

<div id="history-content" style="display:none">

<div id="history-query" class="history-query"></div>

<div class="chart-grid">

<div class="chart-container">
<div class="chart-label">Execution time per interval</div>
<canvas id="exec-chart" width="700" height="220"></canvas>
</div>

<div class="chart-container">
<div class="chart-label">Average latency</div>
<canvas id="latency-chart" width="700" height="220"></canvas>
</div>

<div class="chart-container">
<div class="chart-label">Calls</div>
<canvas id="calls-chart" width="700" height="220"></canvas>
</div>

<div class="chart-container">
<div class="chart-label">WAL generated</div>
<canvas id="wal-chart" width="700" height="220"></canvas>
</div>

</div>

<table style="margin-top:25px">
<thead>
<tr>
<th>Time</th>
<th>Calls</th>
<th>Exec ms</th>
<th>Avg ms</th>
<th>Reads</th>
<th>Cache %</th>
<th>WAL MB</th>
</tr>
</thead>
<tbody id="history-table"></tbody>
</table>

</div>
</div>

<script>

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

function currentEngine() {
    return document.getElementById("engine-select").value;
}

async function selectEngine(engine) {
    document.getElementById('engine-select').value = engine;

    document.querySelectorAll('.engine-tab').forEach(tab => {
        const active = tab.dataset.engine === engine;
        tab.classList.toggle('active', active);
        tab.setAttribute('aria-selected', active ? 'true' : 'false');
    });

    updateEnginePanels();

    const status = document.getElementById('refresh-status');
    status.innerText = 'Loading ' + (engine === 'oracle' ? 'Oracle' : 'PostgreSQL') + '...';

    try {
        await engineChanged();
        status.innerText = 'Updated ' + new Date().toLocaleTimeString();
    } catch (error) {
        console.error(error);
        status.innerText = 'Unable to load ' + (engine === 'oracle' ? 'Oracle' : 'PostgreSQL') + ': ' + error.message;
    }
}

function currentCluster() {
    return document.getElementById('cluster-select').value;
}

function currentDatabase() {
    return document.getElementById('database-select').value;
}

function currentMinutes() {
    return document.getElementById('minutes-select').value;
}

async function loadClusterOverview() {
    const response = await fetch('/api/cluster-overview');

    if (!response.ok) {
        throw new Error(
            'Cluster overview API failed: ' + response.status
        );
    }

    const rows = await response.json();
    const container = document.getElementById('cluster-overview');
    container.innerHTML = '';

    rows.forEach(cluster => {
        const card = document.createElement('div');
        card.className = 'cluster-card';
        card.dataset.clusterid = cluster.cluster_id;

        const seconds = cluster.seconds_since_collection;

        let lastSeen = '-';

        if (seconds !== null && seconds !== undefined) {
            if (seconds < 60) {
                lastSeen = seconds + ' sec ago';
            } else {
                lastSeen = Math.floor(seconds / 60) + ' min ago';
            }
        }

        card.innerHTML = `
<div class="cluster-title">
${escapeHtml(cluster.cluster_name || cluster.cluster_id)}
</div>

<div class="status-row">
<div>
<span class="status-label">Health</span>
<span class="cluster-status status-${cluster.health_status}">
${cluster.health_status}
</span>
</div>

<div>
<span class="status-label">Performance</span>
<span class="cluster-status status-${cluster.performance_status}">
${cluster.performance_status}
</span>
</div>
</div>

<div class="cluster-stats">

<div>
<div class="cluster-stat-label">Databases</div>
<div class="cluster-stat-value">${cluster.database_count}</div>
</div>

<div>
<div class="cluster-stat-label">Critical</div>
<div class="cluster-stat-value">${cluster.critical_count}</div>
</div>

<div>
<div class="cluster-stat-label">Warnings</div>
<div class="cluster-stat-value">${cluster.warning_count}</div>
</div>

<div>
<div class="cluster-stat-label">Last collection</div>
<div class="cluster-stat-value">${lastSeen}</div>
</div>

</div>
`;

        container.appendChild(card);
    });
}

function collectionAge(value) {
    if (!value) return '-';
    const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
    if (seconds < 60) return seconds + ' sec ago';
    if (seconds < 3600) return Math.floor(seconds / 60) + ' min ago';
    return Math.floor(seconds / 3600) + ' hr ago';
}

function setPlatformStatus(engine, status, clusters, databases, lastCollection) {
    const badge = document.getElementById(engine + '-platform-status');
    badge.innerText = status;
    badge.className = 'cluster-status status-' + status;
    document.getElementById(engine + '-platform-clusters').innerText = clusters;
    document.getElementById(engine + '-platform-databases').innerText = databases;
    document.getElementById(engine + '-platform-last').innerText = collectionAge(lastCollection);
}

async function loadPlatformStatus() {
    const [postgresResponse, oracleResponse] = await Promise.all([
        fetch('/api/cluster-overview'),
        fetch('/api/oracle/databases')
    ]);

    if (!postgresResponse.ok || !oracleResponse.ok) {
        throw new Error('Platform status API failed.');
    }

    const postgres = await postgresResponse.json();
    const oracle = await oracleResponse.json();
    const postgresLast = postgres.reduce((latest, row) => {
        if (row.seconds_since_collection === null || row.seconds_since_collection === undefined) return latest;
        const captured = new Date(Date.now() - Number(row.seconds_since_collection) * 1000).toISOString();
        return !latest || captured > latest ? captured : latest;
    }, null);
    const postgresStatus = postgres.some(row => row.health_status === 'OFFLINE')
        ? 'OFFLINE'
        : postgres.length ? 'HEALTHY' : 'UNKNOWN';
    setPlatformStatus(
        'postgresql', postgresStatus, postgres.length,
        postgres.reduce((total, row) => total + Number(row.database_count || 0), 0),
        postgresLast
    );

    const oracleClusters = new Set(oracle.map(row => row.cluster_id)).size;
    const oracleLast = oracle.reduce((latest, row) => {
        if (!row.last_collection) return latest;
        return !latest || row.last_collection > latest ? row.last_collection : latest;
    }, null);
    const oracleAge = oracleLast ? (Date.now() - new Date(oracleLast).getTime()) / 1000 : null;
    const oracleConfigured = oracle.some(row => row.configured === true);
    const oracleStatus = !oracleConfigured || oracleAge === null
        ? 'UNKNOWN'
        : oracleAge > 120 ? 'OFFLINE' : 'HEALTHY';
    setPlatformStatus('oracle', oracleStatus, oracleClusters, oracle.length, oracleLast);
}

async function loadClusters() {
    const engine = currentEngine();

    const response = await fetch(
        engine === 'oracle'
            ? '/api/oracle/databases'
            : '/api/clusters'
    );

    if (!response.ok) {
        throw new Error(
            'Clusters API failed: ' + response.status
        );
    }

    const rows = await response.json();
    const select = document.getElementById('cluster-select');
    const previous = select.value;

    select.innerHTML = '';

    const seen = new Set();

    rows.forEach(row => {
        if (seen.has(row.cluster_id)) {
            return;
        }

        seen.add(row.cluster_id);

        const option = document.createElement('option');
        option.value = row.cluster_id;
        option.textContent = row.cluster_name || row.cluster_id;

        if (row.cluster_id === previous) {
            option.selected = true;
        }

        select.appendChild(option);
    });
}

async function loadDatabases() {
    const engine = currentEngine();
    const cluster = currentCluster();

    const response = await fetch(
        engine === 'oracle'
            ? '/api/oracle/databases'
            : '/api/databases?cluster_id=' + encodeURIComponent(cluster)
    );

    if (!response.ok) {
        throw new Error(
            'Databases API failed: ' + response.status
        );
    }

    const rows = await response.json();

    const databaseRows = engine === 'oracle'
        ? rows.filter(row => row.cluster_id === cluster)
        : rows;

    const select = document.getElementById('database-select');
    const previous = select.value;

    select.innerHTML = '';

    databaseRows.forEach(row => {
        const option = document.createElement('option');
        option.value = row.database_name;
        option.textContent = row.database_name;

        if (
            row.database_name === previous
            ||
            (
                !previous
                && engine === 'postgresql'
                && row.database_name === 'bench'
            )
        ) {
            option.selected = true;
        }

        select.appendChild(option);
    });
}

async function loadSummary() {
    const cluster = currentCluster();
    const database = currentDatabase();

    const response = await fetch(
        '/api/summary'
        + '?cluster_id=' + encodeURIComponent(cluster)
        + '&database=' + encodeURIComponent(database)
    );

    if (!response.ok) {
        throw new Error(
            'Summary API failed: ' + response.status
        );
    }

    const data = await response.json();

    document.getElementById('findings-count').innerText =
        data.findings_last_hour;

    document.getElementById('critical-count').innerText =
        data.critical_last_hour;

    document.getElementById('database-count').innerText =
        data.databases_seen;

    document.getElementById('last-collection').innerText =
        data.last_collection || '-';
}

async function loadFindings() {
    const cluster = currentCluster();
    const database = currentDatabase();

    const response = await fetch(
        '/api/findings'
        + '?cluster_id=' + encodeURIComponent(cluster)
        + '&database=' + encodeURIComponent(database)
        + '&limit=20'
    );

    if (!response.ok) {
        throw new Error(
            'Findings API failed: ' + response.status
        );
    }

    const findings = await response.json();
    const table = document.getElementById('findings-table');

    table.innerHTML = '';

    findings.forEach(f => {
        const row = document.createElement('tr');

        const severityClass =
            f.severity === 'CRITICAL'
            ? 'critical'
            : 'warning';

        row.innerHTML = `
<td>${new Date(f.captured_at).toLocaleTimeString()}</td>
<td class="${severityClass}">${f.severity}</td>
<td>${f.finding_type}</td>
<td>${escapeHtml(f.message)}</td>
<td class="recommendation">${escapeHtml(f.recommendation)}</td>
<td class="query">${escapeHtml(f.query_text)}</td>
`;

        table.appendChild(row);
    });
}

async function loadQueries() {
    const cluster = currentCluster();
    const database = currentDatabase();
    const minutes = currentMinutes();

    const response = await fetch(
        (cluster.startsWith('oracle-') ? '/api/oracle/top-sql' : '/api/top-queries')
        + '?cluster_id=' + encodeURIComponent(cluster)
        + '&database=' + encodeURIComponent(database)
        + '&minutes=' + minutes
        + '&limit=20'
    );

    if (!response.ok) {
        throw new Error(
            'Top queries API failed: ' + response.status
        );
    }

    const queries = await response.json();
    if (cluster.startsWith("oracle-")) {
        queries.forEach(q => {
            q.queryid = q.sql_id;
            q.calls = q.executions;
            q.total_exec_ms = q.elapsed_ms;
            q.shared_reads = q.disk_reads;
            q.avg_cache_hit_pct = "-";
            q.wal_mb = "-";
        });
    }
    const table = document.getElementById('queries-table');

    table.innerHTML = '';

    queries.forEach(q => {
        const row = document.createElement('tr');

        row.innerHTML = `
<td>${q.queryid}</td>
<td>${q.calls}</td>
<td>${q.total_exec_ms}</td>
<td>${q.avg_exec_ms}</td>
<td>${q.shared_reads}</td>
<td>${q.avg_cache_hit_pct}</td>
<td>${q.wal_mb}</td>

<td>
<button
class="history-button"
data-queryid="${q.queryid}">
History
</button>
</td>

<td>
<button
class="explain-button"
data-queryid="${q.queryid}">
Explain
</button>
</td>

<td
class="query query-click"
data-queryid="${q.queryid}">
${escapeHtml(q.query_text)}
</td>
`;

        table.appendChild(row);
    });
}

async function loadHistory(queryid) {
    const cluster = currentCluster();
    const database = currentDatabase();
    const minutes = currentMinutes();

    const status = document.getElementById('history-status');
    const content = document.getElementById('history-content');

    status.className = '';
    status.innerText = 'Loading history...';
    content.style.display = 'none';

    try {
        const response = await fetch(
            '/api/query-history/'
            + encodeURIComponent(queryid)
            + '?cluster_id=' + encodeURIComponent(cluster)
            + '&database=' + encodeURIComponent(database)
            + '&minutes=' + minutes
        );

        if (!response.ok) {
            throw new Error(
                'History API returned ' + response.status
            );
        }

        const rows = await response.json();

        if (!rows.length) {
            status.innerText = 'No history available.';
            return;
        }

        status.innerText =
            'Loaded ' + rows.length + ' history points.';

        content.style.display = 'block';

        document.getElementById('history-query').innerText =
            rows[0].query_text || ('Query ' + queryid);

        drawChart('exec-chart', rows, 'exec_time_delta');
        drawChart('latency-chart', rows, 'avg_exec_ms');
        drawChart('calls-chart', rows, 'calls_delta');
        drawChart('wal-chart', rows, 'wal_mb');

        const table = document.getElementById('history-table');
        table.innerHTML = '';

        rows.slice().reverse().forEach(r => {
            const row = document.createElement('tr');

            row.innerHTML = `
<td>${new Date(r.captured_at).toLocaleTimeString()}</td>
<td>${r.calls_delta}</td>
<td>${Number(r.exec_time_delta).toFixed(2)}</td>
<td>${Number(r.avg_exec_ms).toFixed(2)}</td>
<td>${r.shared_reads_delta}</td>
<td>${Number(r.cache_hit_pct).toFixed(2)}</td>
<td>${r.wal_mb}</td>
`;

            table.appendChild(row);
        });

        document.getElementById('history-panel').scrollIntoView({
            behavior: 'smooth'
        });

    } catch (error) {
        console.error(error);
        status.className = 'history-error';
        status.innerText =
            'History failed: ' + error.message;
    }
}

function drawChart(canvasId, rows, field) {
    const canvas = document.getElementById(canvasId);
    const ctx = canvas.getContext('2d');

    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);

    const values =
        rows.map(r => Number(r[field] || 0));

    const max =
        Math.max(...values, 1);

    const padding = 30;

    const chartWidth =
        width - padding * 2;

    const chartHeight =
        height - padding * 2;

    ctx.strokeStyle = '#334155';
    ctx.lineWidth = 1;

    ctx.beginPath();
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, height - padding);
    ctx.lineTo(width - padding, height - padding);
    ctx.stroke();

    ctx.strokeStyle = '#60a5fa';
    ctx.lineWidth = 2;

    ctx.beginPath();

    values.forEach((value, index) => {
        const x =
            padding
            +
            (
                index
                /
                Math.max(
                    values.length - 1,
                    1
                )
            )
            * chartWidth;

        const y =
            height
            - padding
            -
            (
                value
                / max
            )
            * chartHeight;

        if (index === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
    });

    ctx.stroke();

    ctx.fillStyle = '#94a3b8';
    ctx.font = '12px Arial';

    ctx.fillText(
        max.toFixed(2),
        4,
        padding
    );

    ctx.fillText(
        '0',
        10,
        height - padding
    );
}


let currentOracleSqlId = null;


function oracleDetailCard(
    label,
    value
) {
    const shown =
        value === null
        || value === undefined
        || value === ''
            ? '-'
            : value;

    return `
<div class="oracle-detail-card">
<div class="label">${escapeHtml(label)}</div>
<div class="value">${escapeHtml(String(shown))}</div>
</div>
`;
}


function formatOracleNumber(
    value,
    decimals = 0
) {
    if (
        value === null
        || value === undefined
    ) {
        return '-';
    }

    const number = Number(value);

    if (!Number.isFinite(number)) {
        return value;
    }

    return number.toLocaleString(
        'en-US',
        {
            minimumFractionDigits: decimals,
            maximumFractionDigits: decimals
        }
    );
}


function hideOracleSqlDetails() {
    document.getElementById(
        'oracle-sql-detail-panel'
    ).style.display = 'none';

    currentOracleSqlId = null;
}


async function showOracleSqlDetails(
    sqlId
) {
    currentOracleSqlId = sqlId;

    const cluster = currentCluster();
    const database = currentDatabase();
    const minutes = currentMinutes();

    const panel =
        document.getElementById(
            'oracle-sql-detail-panel'
        );

    const status =
        document.getElementById(
            'oracle-detail-status'
        );

    const content =
        document.getElementById(
            'oracle-detail-content'
        );

    panel.style.display = 'block';

    requestAnimationFrame(() => {
        panel.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    });

    content.style.display = 'none';

    status.className =
        'oracle-status';

    status.innerText =
        'Loading Oracle SQL details...';

    document.getElementById(
        'oracle-detail-sql-id'
    ).innerText = sqlId;

    document.getElementById(
        'oracle-plan-result'
    ).style.display = 'none';

    document.getElementById(
        'oracle-explain-result'
    ).style.display = 'none';

    document.getElementById(
        'oracle-plan-status'
    ).innerText = '';

    try {
        const base =
            '?cluster_id='
            + encodeURIComponent(cluster)
            + '&database='
            + encodeURIComponent(database);

        const [
            summaryRes,
            historyRes,
            sessionsRes
        ] = await Promise.all([
            fetch(
                '/api/oracle/query-summary/'
                + encodeURIComponent(sqlId)
                + base
                + '&minutes='
                + minutes
            ),

            fetch(
                '/api/oracle/query-history/'
                + encodeURIComponent(sqlId)
                + base
                + '&minutes='
                + minutes
            ),

            fetch(
                '/api/oracle/query-sessions/'
                + encodeURIComponent(sqlId)
                + base
            )
        ]);

        if (!summaryRes.ok) {
            throw new Error(
                'Summary API returned '
                + summaryRes.status
            );
        }

        if (!historyRes.ok) {
            throw new Error(
                'History API returned '
                + historyRes.status
            );
        }

        if (!sessionsRes.ok) {
            throw new Error(
                'Sessions API returned '
                + sessionsRes.status
            );
        }

        const summary =
            await summaryRes.json();

        const history =
            await historyRes.json();

        const sessions =
            await sessionsRes.json();

        const metrics =
            document.getElementById(
                'oracle-detail-metrics'
            );

        metrics.innerHTML =
            oracleDetailCard(
                'Plan Hash',
                summary.plan_hash_value
            )
            + oracleDetailCard(
                'Parsing Schema',
                summary.parsing_schema
            )
            + oracleDetailCard(
                'Instance',
                summary.instance_number
            )
            + oracleDetailCard(
                'Executions',
                formatOracleNumber(
                    summary.executions
                )
            )
            + oracleDetailCard(
                'Elapsed',
                formatOracleNumber(
                    summary.elapsed_ms,
                    2
                ) + ' ms'
            )
            + oracleDetailCard(
                'CPU',
                formatOracleNumber(
                    summary.cpu_ms,
                    2
                ) + ' ms'
            )
            + oracleDetailCard(
                'Avg',
                formatOracleNumber(
                    summary.avg_exec_ms,
                    2
                ) + ' ms'
            )
            + oracleDetailCard(
                'Buffer Gets',
                formatOracleNumber(
                    summary.buffer_gets
                )
            )
            + oracleDetailCard(
                'Disk Reads',
                formatOracleNumber(
                    summary.disk_reads
                )
            )
            + oracleDetailCard(
                'Rows',
                formatOracleNumber(
                    summary.rows_processed
                )
            )
            + oracleDetailCard(
                'Last Active',
                summary.last_active_time
                    ? new Date(
                        summary.last_active_time
                    ).toLocaleString()
                    : '-'
            );

        document.getElementById(
            'oracle-detail-sql'
        ).innerText =
            summary.query_text || '';

        const historyTable =
            document.getElementById(
                'oracle-history-table'
            );

        historyTable.innerHTML = '';

        history
            .slice()
            .reverse()
            .forEach(row => {
                const tr =
                    document.createElement(
                        'tr'
                    );

                tr.innerHTML = `
<td>${
    new Date(
        row.captured_at
    ).toLocaleTimeString()
}</td>

<td>${row.plan_hash_value ?? '-'}</td>

<td>${
    formatOracleNumber(
        row.executions_delta
    )
}</td>

<td>${
    formatOracleNumber(
        row.elapsed_ms_delta,
        2
    )
}</td>

<td>${
    formatOracleNumber(
        row.cpu_ms_delta,
        2
    )
}</td>

<td>${
    formatOracleNumber(
        row.avg_exec_ms,
        2
    )
}</td>

<td>${
    formatOracleNumber(
        row.buffer_gets_delta
    )
}</td>

<td>${
    formatOracleNumber(
        row.disk_reads_delta
    )
}</td>

<td>${
    formatOracleNumber(
        row.rows_delta
    )
}</td>
`;

                historyTable.appendChild(
                    tr
                );
            });

        const sessionsTable =
            document.getElementById(
                'oracle-query-sessions-table'
            );

        sessionsTable.innerHTML = '';

        if (!sessions.length) {
            const tr =
                document.createElement(
                    'tr'
                );

            tr.innerHTML =
                '<td colspan="10">'
                + 'No session is currently '
                + 'using this SQL ID.'
                + '</td>';

            sessionsTable.appendChild(
                tr
            );

        } else {
            sessions.forEach(s => {
                const tr =
                    document.createElement(
                        'tr'
                    );

                tr.innerHTML = `
<td>${s.instance_id ?? '-'}</td>
<td>${s.sid ?? '-'}</td>
<td>${s.serial_number ?? '-'}</td>
<td>${escapeHtml(s.username || '')}</td>
<td>${escapeHtml(s.status || '')}</td>
<td>${escapeHtml(s.event || '')}</td>
<td>${escapeHtml(s.wait_class || '')}</td>
<td>${s.seconds_in_wait ?? '-'}</td>
<td>${escapeHtml(s.machine || '')}</td>
<td>${escapeHtml(s.program || '')}</td>
`;

                sessionsTable.appendChild(
                    tr
                );
            });
        }

        status.innerText =
            'Loaded '
            + history.length
            + ' history points.';

        content.style.display =
            'block';

        panel.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });

    } catch (error) {
        console.error(error);

        status.className =
            'oracle-status oracle-error';

        status.innerText =
            'Oracle SQL details failed: '
            + error.message;
    }
}


async function loadOracleCurrentPlan() {
    if (!currentOracleSqlId) {
        return;
    }

    const status =
        document.getElementById(
            'oracle-plan-status'
        );

    const result =
        document.getElementById(
            'oracle-plan-result'
        );

    status.className =
        'oracle-status';

    status.innerText =
        'Loading current plan...';

    result.style.display =
        'none';

    const childValue =
        document.getElementById(
            'oracle-plan-child'
        ).value.trim();

    const payload = {
        cluster_id: currentCluster(),
        database: currentDatabase(),
        sql_id:
            currentOracleSqlId,

        child_number:
            childValue
                ? Number(childValue)
                : null
    };

    try {
        const response =
            await fetch(
                '/api/oracle/configured-current-plan',
                {
                    method: 'POST',

                    headers: {
                        'Content-Type':
                            'application/json'
                    },

                    body:
                        JSON.stringify(
                            payload
                        )
                }
            );

        const data =
            await response.json();

        if (!response.ok) {
            throw new Error(
                data.detail
                || (
                    'Plan API returned '
                    + response.status
                )
            );
        }

        const summary =
            document.getElementById(
                'oracle-plan-summary'
            );

        summary.innerHTML =
            oracleDetailCard(
                'SQL ID',
                data.sql_id
            )
            + oracleDetailCard(
                'Children',
                (
                    data.children
                    || []
                ).join(', ')
            )
            + oracleDetailCard(
                'Plan Hash',
                (
                    data.plan_hash_values
                    || []
                ).join(', ')
            );

        const table =
            document.getElementById(
                'oracle-plan-table'
            );

        table.innerHTML = '';

        data.plan.forEach(p => {
            const tr =
                document.createElement(
                    'tr'
                );

            const operation =
                [
                    p.operation,
                    p.options
                ]
                .filter(Boolean)
                .join(' ');

            const objectName =
                [
                    p.object_owner,
                    p.object_name
                ]
                .filter(Boolean)
                .join('.');

            tr.innerHTML = `
<td>${p.child_number ?? '-'}</td>

<td>${p.id ?? '-'}</td>

<td class="oracle-plan-operation">${
    escapeHtml(
        operation
    )
}</td>

<td>${
    escapeHtml(
        objectName
    )
}</td>

<td>${
    formatOracleNumber(
        p.cardinality
    )
}</td>

<td>${
    formatOracleNumber(
        p.cost
    )
}</td>

<td class="oracle-plan-predicate">${
    escapeHtml(
        p.access_predicates
        || ''
    )
}</td>

<td class="oracle-plan-predicate">${
    escapeHtml(
        p.filter_predicates
        || ''
    )
}</td>
`;

            table.appendChild(
                tr
            );
        });

        status.innerText =
            'Loaded '
            + data.plan.length
            + ' plan rows.';

        result.style.display =
            'block';

    } catch (error) {
        console.error(error);

        status.className =
            'oracle-status oracle-error';

        status.innerText =
            'Current plan failed: '
            + error.message;
    }
}


async function explainOracleSql() {
    if (!currentOracleSqlId) return;

    const status = document.getElementById('oracle-plan-status');
    const result = document.getElementById('oracle-explain-result');
    const plan = document.getElementById('oracle-explain-plan');

    status.className = 'oracle-status';
    status.innerText = 'Generating Oracle Explain Plan...';
    result.style.display = 'none';

    try {
        const response = await fetch('/api/oracle/configured-explain', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                cluster_id: currentCluster(),
                database: currentDatabase(),
                sql_id: currentOracleSqlId,
                child_number: null
            })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Explain API failed');

        plan.innerText = (data.plan || []).join('\\n');
        result.style.display = 'block';
        status.innerText = 'Explain Plan generated without executing the SQL.';
    } catch (error) {
        status.className = 'oracle-status oracle-error';
        status.innerText = 'Explain Plan failed: ' + error.message;
    }
}


async function loadOracleDashboard() {
    const cluster = currentCluster();
    const database = currentDatabase();
    const minutes = currentMinutes();

    const [
        topSqlRes,
        sessionsRes,
        blockingRes,
        waitsRes
    ] = await Promise.all([

        fetch(
            '/api/oracle/top-sql'
            + '?cluster_id='
            + encodeURIComponent(cluster)
            + '&database='
            + encodeURIComponent(database)
            + '&minutes='
            + minutes
            + '&limit=20'
        ),

        fetch(
            '/api/oracle/sessions'
            + '?cluster_id='
            + encodeURIComponent(cluster)
            + '&database='
            + encodeURIComponent(database)
        ),

        fetch(
            '/api/oracle/blocking'
            + '?cluster_id='
            + encodeURIComponent(cluster)
            + '&database='
            + encodeURIComponent(database)
        ),

        fetch(
            '/api/oracle/waits'
            + '?cluster_id='
            + encodeURIComponent(cluster)
            + '&database='
            + encodeURIComponent(database)
        )
    ]);

    if (!topSqlRes.ok) {
        throw new Error(
            'Oracle Top SQL API failed: '
            + topSqlRes.status
        );
    }

    if (!sessionsRes.ok) {
        throw new Error(
            'Oracle Sessions API failed: '
            + sessionsRes.status
        );
    }

    if (!blockingRes.ok) {
        throw new Error(
            'Oracle Blocking API failed: '
            + blockingRes.status
        );
    }

    if (!waitsRes.ok) {
        throw new Error(
            'Oracle Waits API failed: '
            + waitsRes.status
        );
    }

    const topSql =
        await topSqlRes.json();

    const sessions =
        await sessionsRes.json();

    const blocking =
        await blockingRes.json();

    const waits =
        await waitsRes.json();


    const topSqlTable =
        document.getElementById(
            'oracle-top-sql-table'
        );

    topSqlTable.innerHTML = '';

    topSql.forEach(q => {
        const row =
            document.createElement(
                'tr'
            );

        row.className = 'oracle-clickable-row';
        row.title = 'Open SQL history and execution plan';

        row.innerHTML = `
<td>
<span
    class="oracle-sql-link"
    data-sql-id="${escapeHtml(q.sql_id)}"
>
${escapeHtml(q.sql_id)}
</span>
</td>

<td>${q.plan_hash_value ?? '-'}</td>
<td>${formatOracleNumber(q.executions)}</td>
<td>${formatOracleNumber(q.elapsed_ms, 2)}</td>
<td>${formatOracleNumber(q.cpu_ms, 2)}</td>
<td>${formatOracleNumber(q.avg_exec_ms, 2)}</td>
<td>${formatOracleNumber(q.buffer_gets)}</td>
<td>${formatOracleNumber(q.disk_reads)}</td>
<td>${formatOracleNumber(q.rows)}</td>
<td>
<button
    type="button"
    class="history-button oracle-details-button"
    data-sql-id="${escapeHtml(q.sql_id)}"
>
History / Plan
</button>
</td>
<td class="query">${escapeHtml(q.query_text)}</td>
`;

        topSqlTable.appendChild(
            row
        );

        row.addEventListener('click', event => {
            if (event.target.closest('.oracle-sql-link, .oracle-details-button')) return;
            showOracleSqlDetails(q.sql_id);
        });
    });

    topSqlTable
        .querySelectorAll('.oracle-sql-link, .oracle-details-button')
        .forEach(link => {
            link.addEventListener(
                'click',
                () => {
                    showOracleSqlDetails(
                        link.dataset.sqlId
                    );
                }
            );
        });


    const sessionsTable =
        document.getElementById(
            'oracle-sessions-table'
        );

    sessionsTable.innerHTML = '';

    sessions.forEach(s => {
        const row =
            document.createElement(
                'tr'
            );

        row.innerHTML = `
<td>${s.instance_id ?? '-'}</td>
<td>${s.sid ?? '-'}</td>
<td>${s.serial_number ?? '-'}</td>
<td>${escapeHtml(s.username || '')}</td>
<td>${escapeHtml(s.status || '')}</td>

<td>${
    s.sql_id
        ? `
<span
    class="oracle-sql-link"
    data-sql-id="${escapeHtml(s.sql_id)}"
>
${escapeHtml(s.sql_id)}
</span>
`
        : ''
}</td>

<td>${escapeHtml(s.event || '')}</td>
<td>${escapeHtml(s.wait_class || '')}</td>
<td>${escapeHtml(s.machine || '')}</td>
<td>${escapeHtml(s.program || '')}</td>
`;

        sessionsTable.appendChild(
            row
        );
    });

    sessionsTable
        .querySelectorAll(
            '.oracle-sql-link'
        )
        .forEach(link => {
            link.addEventListener(
                'click',
                () => {
                    showOracleSqlDetails(
                        link.dataset.sqlId
                    );
                }
            );
        });


    const blockingTable =
        document.getElementById(
            'oracle-blocking-table'
        );

    blockingTable.innerHTML = '';

    if (!blocking.length) {
        const row =
            document.createElement(
                'tr'
            );

        row.innerHTML =
            '<td colspan="12">'
            + 'No blocking sessions.'
            + '</td>';

        blockingTable.appendChild(
            row
        );

    } else {
        blocking.forEach(s => {
            const row =
                document.createElement(
                    'tr'
                );

            row.innerHTML = `
<td>${s.instance_id ?? '-'}</td>
<td>${s.sid ?? '-'}</td>
<td>${escapeHtml(s.username || '')}</td>

<td>${
    s.sql_id
        ? `
<span
    class="oracle-sql-link"
    data-sql-id="${escapeHtml(s.sql_id)}"
>
${escapeHtml(s.sql_id)}
</span>
`
        : ''
}</td>

<td>${escapeHtml(s.event || '')}</td>
<td>${escapeHtml(s.wait_class || '')}</td>
<td>${s.seconds_in_wait ?? '-'}</td>
<td>${s.blocking_instance ?? '-'}</td>
<td>${s.blocking_session ?? '-'}</td>
<td>${escapeHtml(s.blocker_username || '')}</td>

<td>${
    s.blocker_sql_id
        ? `
<span
    class="oracle-sql-link"
    data-sql-id="${escapeHtml(s.blocker_sql_id)}"
>
${escapeHtml(s.blocker_sql_id)}
</span>
`
        : ''
}</td>

<td>${escapeHtml(s.blocker_program || '')}</td>
`;

            blockingTable.appendChild(
                row
            );
        });
    }

    blockingTable
        .querySelectorAll(
            '.oracle-sql-link'
        )
        .forEach(link => {
            link.addEventListener(
                'click',
                () => {
                    showOracleSqlDetails(
                        link.dataset.sqlId
                    );
                }
            );
        });


    const waitsTable =
        document.getElementById(
            'oracle-waits-table'
        );

    waitsTable.innerHTML = '';

    waits.forEach(w => {
        const row =
            document.createElement(
                'tr'
            );

        row.innerHTML = `
<td>${escapeHtml(w.wait_class || '')}</td>
<td>${formatOracleNumber(w.total_waits)}</td>
<td>${formatOracleNumber(w.time_waited_ms, 2)}</td>
`;

        waitsTable.appendChild(
            row
        );
    });
}



function updateEnginePanels() {
    const oracle = currentEngine() === 'oracle';

    document.getElementById('pg-summary-cards').style.display =
        oracle ? 'none' : '';

    document.getElementById('pg-findings-panel').style.display =
        oracle ? 'none' : '';

    document.getElementById('pg-top-queries-panel').style.display =
        oracle ? 'none' : '';

    document.getElementById('history-panel').style.display =
        oracle ? 'none' : '';

    document.getElementById('oracle-dashboard').style.display =
        oracle ? 'block' : 'none';

    document.getElementById('generate-report-button').style.display = '';

    document.getElementById('pg-cluster-overview-section').style.display =
        oracle ? 'none' : '';

    document.getElementById('add-cluster-button').innerText =
        oracle ? '+ Add Oracle Cluster / DB' : '+ Add Cluster / DB';
}

async function refreshDetail() {
    const engine = currentEngine();

    updateEnginePanels();

    if (engine === 'oracle') {
        await loadOracleDashboard();
        return;
    }

    await loadSummary();
    await loadFindings();
    await loadQueries();
}

async function refreshAll() {
    const status =
        document.getElementById('refresh-status');

    status.innerText = 'Refreshing...';

    try {
        await loadPlatformStatus();
        await loadClusterOverview();
        await refreshDetail();

        status.innerText =
            'Updated '
            + new Date().toLocaleTimeString();

    } catch (error) {
        console.error(error);
        status.innerText = error.message;
    }
}

async function engineChanged() {
    await loadClusters();
    await loadDatabases();
    await refreshDetail();
}


async function clusterChanged() {
    await loadDatabases();
    await refreshDetail();
}

async function selectCluster(clusterId) {
    const select =
        document.getElementById('cluster-select');

    select.value = clusterId;

    await loadDatabases();
    await refreshDetail();

    document.querySelector('.toolbar').scrollIntoView({
        behavior: 'smooth'
    });
}



async function generateHealthReport(){
 const cluster=currentCluster(),database=currentDatabase(),minutes=currentMinutes();
 const oracle=currentEngine()==='oracle';
 const modal=document.getElementById('report-modal'),status=document.getElementById('report-status'),content=document.getElementById('report-content');
 modal.style.display='flex'; content.style.display='none'; status.innerText='Analyzing '+(oracle?'Oracle':'PostgreSQL')+'...';
 document.getElementById('report-title').innerText=(oracle?'Oracle':'PostgreSQL')+' Health Report';
 document.getElementById('report-query-id-heading').innerText=oracle?'SQL ID':'Query ID';
 document.getElementById('report-calls-heading').innerText=oracle?'Executions':'Calls';
 document.getElementById('report-io-heading').innerText=oracle?'Disk Reads':'WAL MB';
 document.getElementById('report-target').innerText=cluster+' / '+database+' — last '+minutes+' minutes';
 const customer=document.getElementById('report-customer').value.trim()||'-';
 const environment=document.getElementById('report-environment').value.trim()||'-';
 const generated=new Date().toLocaleString();
 document.getElementById('report-meta').innerHTML=
  '<b>Customer:</b> '+escapeHtml(customer)+'<br>'+
  '<b>Environment:</b> '+escapeHtml(environment)+'<br>'+
  '<b>Cluster:</b> '+escapeHtml(cluster)+'<br>'+
  '<b>Database:</b> '+escapeHtml(database)+'<br>'+
  '<b>Report period:</b> last '+escapeHtml(String(minutes))+' minutes<br>'+
  '<b>Generated:</b> '+escapeHtml(generated);
 try{
  const endpoint=oracle?'/api/oracle/health-report':'/api/health-report';
  const res=await fetch(endpoint+'?cluster_id='+encodeURIComponent(cluster)+'&database='+encodeURIComponent(database)+'&minutes='+minutes);
  const d=await res.json(); if(!res.ok) throw new Error(d.detail||'Report failed');
  status.innerText=''; content.style.display='block';
  document.getElementById('report-score').innerText=d.score+'/100';
  const grade=document.getElementById('report-grade'); grade.innerText=d.status;
  grade.className='cluster-status '+(d.score<60?'status-CRITICAL':d.score<80?'status-WARNING':'status-OK');
  const checks=document.getElementById('report-checks'); checks.innerHTML='';
  d.checks.forEach(c=>{const el=document.createElement('div');el.className='report-check';
   el.innerHTML='<b>'+escapeHtml(c.title)+' — '+escapeHtml(c.status)+' — '+escapeHtml(String(c.value??'-'))+'</b><div class="report-check-detail">'+escapeHtml(c.detail||'')+'</div>'+(c.recommendation?'<div class="report-rec">'+escapeHtml(c.recommendation)+'</div>':'');checks.appendChild(el);});
  document.getElementById('report-recommendations').innerHTML=d.recommendations.length?'<ol>'+d.recommendations.map(x=>'<li>'+escapeHtml(x)+'</li>').join('')+'</ol>':'No immediate recommendations.';
  const tq=document.getElementById('report-top-queries'); tq.innerHTML='';
  (d.metrics.top_queries||[]).forEach(q=>{const r=document.createElement('tr');r.innerHTML='<td>'+escapeHtml(oracle?q.sql_id:q.queryid)+'</td><td>'+(oracle?q.executions:q.calls)+'</td><td>'+(oracle?q.elapsed_ms:q.total_exec_ms)+'</td><td>'+q.avg_exec_ms+'</td><td>'+(oracle?q.disk_reads:q.wal_mb)+'</td><td class="query">'+escapeHtml(q.query_text)+'</td>';tq.appendChild(r);});
 }catch(e){status.innerText='Health report failed: '+e.message;}
}
function printHealthReport(){
    window.print();
}
function hideHealthReport(){document.getElementById('report-modal').style.display='none';}

function showAddDatabase() {
    const cluster = currentCluster();
    const status = document.getElementById('database-form-status');

    if (!cluster) {
        alert('Select a cluster first.');
        return;
    }

    document.getElementById('database-cluster-name').value = cluster;
    document.getElementById('new-database-name').value = '';
    document.getElementById('database-modal-title').innerText =
        currentEngine() === 'oracle' ? 'Add Oracle Database' : 'Add Database';
    document.getElementById('database-name-label').innerText =
        currentEngine() === 'oracle' ? 'Service / database name' : 'Database name';
    status.innerText = '';
    document.getElementById('database-modal').style.display = 'flex';
}

function hideAddDatabase() {
    document.getElementById('database-modal').style.display = 'none';
}

function databaseFormValues() {
    return {
        cluster_id: currentCluster(),
        database_name: document.getElementById('new-database-name').value.trim()
    };
}

async function testAddDatabase() {
    const v = databaseFormValues();
    const status = document.getElementById('database-form-status');

    if (!v.cluster_id || !v.database_name) {
        status.innerText = 'Cluster and database name are required.';
        return;
    }

    status.innerText = 'Testing connection...';

    const response = await fetch(
        currentEngine() === 'oracle'
            ? '/api/oracle/test-configured-database'
            : '/api/test-configured-database',
        {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(v)
        }
    );

    const data = await response.json();

    status.innerText = response.ok
        ? `Connection OK - ${currentEngine() === 'oracle' ? '' : 'PostgreSQL '}${data.server_version}, ${data.database_name}${data.in_recovery ? ' (replica)' : ''}`
        : (data.detail || 'Connection test failed.');
}

async function saveAddDatabase() {
    const v = databaseFormValues();
    const status = document.getElementById('database-form-status');

    if (!v.cluster_id || !v.database_name) {
        status.innerText = 'Cluster and database name are required.';
        return;
    }

    status.innerText = 'Adding database...';

    const response = await fetch(
        currentEngine() === 'oracle'
            ? '/api/oracle/configured-databases'
            : '/api/configured-databases',
        {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(v)
        }
    );

    const data = await response.json();

    if (!response.ok) {
        status.innerText = data.detail || 'Unable to add database.';
        return;
    }

    hideAddDatabase();
    await loadDatabases();

    const dbSelect = document.getElementById('database-select');
    dbSelect.value = v.database_name;

    await loadClusterOverview();
    await refreshDetail();
}

async function disableCurrentDatabase() {
    const cluster = currentCluster();
    const database = currentDatabase();

    if (!cluster || !database) {
        alert('Select a cluster and database first.');
        return;
    }

    if (!confirm(
        `Disable database "${database}" on cluster "${cluster}"?\n\nHistorical PgScope data will be kept.`
    )) {
        return;
    }

    const response = await fetch(
        (currentEngine() === 'oracle'
            ? '/api/oracle/configured-databases/'
            : '/api/configured-databases/')
        + encodeURIComponent(cluster)
        + '/'
        + encodeURIComponent(database),
        {method: 'DELETE'}
    );

    const data = await response.json();

    if (!response.ok) {
        alert(data.detail || 'Unable to disable database.');
        return;
    }

    await loadDatabases();
    await loadClusterOverview();

    if (currentDatabase()) {
        await refreshDetail();
    }
}

async function disableCurrentCluster() {
    const cluster = currentCluster();

    if (!cluster) {
        alert('Select a cluster first.');
        return;
    }

    if (!confirm(
        `Disable cluster "${cluster}" and all its monitored databases?\n\nHistorical PgScope data will be kept.`
    )) {
        return;
    }

    const response = await fetch(
        (currentEngine() === 'oracle'
            ? '/api/oracle/configured-clusters/'
            : '/api/configured-clusters/') + encodeURIComponent(cluster),
        {method: 'DELETE'}
    );

    const data = await response.json();

    if (!response.ok) {
        alert(data.detail || 'Unable to disable cluster.');
        return;
    }

    await loadClusters();

    if (currentCluster()) {
        await loadDatabases();
        await loadClusterOverview();

        if (currentDatabase()) {
            await refreshDetail();
        }
    } else {
        document.getElementById('database-select').innerHTML = '';
        document.getElementById('cluster-overview').innerHTML = '';
    }
}

function formValues() {
    return {
        cluster_id: document.getElementById('new-cluster-id').value.trim(),
        cluster_name: document.getElementById('new-cluster-name').value.trim(),
        host: document.getElementById('new-host').value.trim(),
        port: Number(document.getElementById('new-port').value || 5432),
        username: document.getElementById('new-username').value.trim(),
        password: document.getElementById('new-password').value,
        secret_name: document.getElementById('new-secret-name').value.trim() || null,
        secret_key: document.getElementById('new-secret-key').value.trim() || null,
        databases: document.getElementById('new-databases').value.split(',').map(x => x.trim()).filter(Boolean)
    };
}
function showAddCluster(){
    const oracle = currentEngine() === 'oracle';
    document.getElementById('cluster-modal-title').innerText =
        oracle ? 'Add Oracle Cluster / DB' : 'Add Cluster / DB';
    document.getElementById('databases-label').innerText =
        oracle ? 'Services / databases' : 'Databases';
    document.getElementById('new-port').value = oracle ? '1521' : '5432';
    document.getElementById('new-host').placeholder = oracle ? 'oracle-scan' : 'postgres-rw';
    document.getElementById('new-databases').placeholder = oracle ? 'ORCLPDB1, APPPDB' : 'postgres, appdb';
    document.getElementById('cluster-modal').style.display='flex';
}
function hideAddCluster(){ document.getElementById('cluster-modal').style.display='none'; }

async function testAddCluster() {
    const v=formValues(), st=document.getElementById('cluster-form-status');
    if(!v.host || !v.username || !v.password || !v.databases.length){ st.innerText='Host, username, password and database are required.'; return; }
    st.innerText='Testing connection...';
    const res=await fetch(currentEngine() === 'oracle' ? '/api/oracle/test-cluster' : '/api/test-cluster',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({host:v.host,port:v.port,username:v.username,password:v.password,database:v.databases[0]})});
    const d=await res.json();
    st.innerText=res.ok ? `Connection OK — ${currentEngine() === 'oracle' ? '' : 'PostgreSQL '}${d.server_version}, ${d.database_name}${d.in_recovery?' (replica)':''}` : (d.detail || 'Test failed');
}

async function saveAddCluster() {
    const v = formValues();
    const st =
        document.getElementById(
            'cluster-form-status'
        );

    if (
        !v.cluster_id
        || !v.cluster_name
        || !v.host
        || !v.username
        || !v.secret_name
        || !v.secret_key
        || !v.databases.length
    ) {
        st.innerText =
            'Fill in cluster ID, name, host, username, secret name, secret key and database.';
        return;
    }

    st.innerText = 'Saving...';

    const res = await fetch(
        currentEngine() === 'oracle'
            ? '/api/oracle/configured-clusters'
            : '/api/configured-clusters',
        {
            method: 'POST',
            headers: {
                'Content-Type':
                    'application/json'
            },
            body: JSON.stringify({
                cluster_id:
                    v.cluster_id,

                cluster_name:
                    v.cluster_name,

                host:
                    v.host,

                port:
                    v.port,

                username:
                    v.username,

                secret_name:
                    v.secret_name,

                secret_key:
                    v.secret_key,

                databases:
                    v.databases
            })
        }
    );

    const d = await res.json();

    if (res.ok) {
        st.innerText =
            `Saved ${d.cluster_id}. Password was not stored.`;

        hideAddCluster();

        await loadClusterOverview();
        await loadClusters();
        await loadDatabases();
        await refreshDetail();
    } else {
        st.innerText =
            d.detail || 'Save failed';
    }
}


let queryDetailsQueryId = null;

function hideQueryDetailsModal() {
    document.getElementById('query-details-modal').style.display = 'none';
}

function queryDetailsHistory() {
    if (!queryDetailsQueryId) return;
    hideQueryDetailsModal();
    loadHistory(queryDetailsQueryId);
}

function queryDetailsExplain() {
    if (!queryDetailsQueryId) return;
    hideQueryDetailsModal();
    showExplainModal(queryDetailsQueryId);
}

function formatCount(value) {
    if (value === null || value === undefined) return '-';
    return Number(value).toLocaleString('en-US');
}

function formatDurationMs(value) {
    if (value === null || value === undefined) return '-';
    const n = Number(value);

    if (n >= 1000) {
        return (n / 1000).toFixed(2) + ' s';
    }

    return n.toFixed(2) + ' ms';
}

function findingTypeLabel(value) {
    return String(value || '')
        .toLowerCase()
        .replaceAll('_', ' ')
        .replace(/^./, c => c.toUpperCase());
}

function severityBadge(value) {
    const severity = String(value || '').toUpperCase();
    const cssClass =
        severity === 'CRITICAL'
            ? 'severity-critical'
            : severity === 'WARNING'
                ? 'severity-warning'
                : '';

    return `<span class="severity-badge ${cssClass}">${escapeHtml(severity)}</span>`;
}

function queryDetailValue(label, value, suffix = '') {
    const shown = (value === null || value === undefined || value === '') ? '-' : value;
    return `
<div class="query-detail-card">
  <div class="label">${escapeHtml(label)}</div>
  <div class="value">${escapeHtml(String(shown))}${suffix}</div>
</div>`;
}

async function showQueryDetailsModal(queryid) {
    queryDetailsQueryId = queryid;

    const modal = document.getElementById('query-details-modal');
    const status = document.getElementById('query-details-status');
    const content = document.getElementById('query-details-content');

    modal.style.display = 'flex';
    status.innerText = 'Loading query details...';
    content.style.display = 'none';

    const cluster = currentCluster();
    const database = currentDatabase();
    const minutes = currentMinutes();

    try {
        const response = await fetch(
            '/api/query-details/' + encodeURIComponent(queryid)
            + '?cluster_id=' + encodeURIComponent(cluster)
            + '&database=' + encodeURIComponent(database)
            + '&minutes=' + minutes
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || ('Query details API returned ' + response.status));
        }

        const q = data.query;
        document.getElementById('query-details-sql').innerText =
            q.query_text || ('Query ' + queryid);

        document.getElementById('query-details-metrics').innerHTML =
            queryDetailValue('Calls', formatCount(q.calls))
            + queryDetailValue('Total execution', formatDurationMs(q.total_exec_ms))
            + queryDetailValue('Average latency', formatDurationMs(q.avg_exec_ms))
            + queryDetailValue('Shared reads', q.shared_reads)
            + queryDetailValue('Cache hit', q.avg_cache_hit_pct, '%')
            + queryDetailValue('Temp blocks', q.temp_blocks)
            + queryDetailValue('WAL', q.wal_mb, ' MB')
            + queryDetailValue('Last seen', q.last_seen ? new Date(q.last_seen).toLocaleString() : '-');

        const findings = data.findings || [];
        const findingsBox = document.getElementById('query-details-findings');

        if (!findings.length) {
            findingsBox.innerHTML = '<div class="form-help">No findings for this query in the selected time range.</div>';
        } else {
            findingsBox.innerHTML = `
<table class="query-details-findings">
<thead>
<tr>
<th>Last seen</th>
<th>Severity</th>
<th>Type</th>
<th>Occurrences</th>
<th>Message</th>
<th>Recommendation</th>
</tr>
</thead>
<tbody>${findings.map(f => `
<tr>
<td>${new Date(f.captured_at).toLocaleTimeString()}</td>
<td>${severityBadge(f.severity)}</td>
<td>${escapeHtml(findingTypeLabel(f.finding_type))}</td>
<td>${escapeHtml(String(f.occurrences ?? 1))}</td>
<td>${escapeHtml(f.message || '')}</td>
<td class="recommendation">${escapeHtml(f.recommendation || '')}</td>
</tr>`).join('')}</tbody>
</table>`;
        }

        status.innerText =
            'Query ' + queryid + ' · ' + cluster + ' / ' + database + ' · last ' + minutes + ' min';
        content.style.display = 'block';
    } catch (error) {
        status.innerText = 'Unable to load query details: ' + error.message;
    }
}

let explainQueryId = null;
let explainRequiredParameters = 0;

function showExplainModal(
    queryid
) {
    explainQueryId = queryid;

    document.getElementById(
        'explain-modal'
    ).style.display = 'flex';

    document.getElementById(
        'explain-status'
    ).innerText =
        'Ready to generate estimated plan.';

    document.getElementById(
        'explain-result'
    ).style.display = 'none';

    document.getElementById(
        'explain-parameter-area'
    ).style.display = 'none';

    document.getElementById(
        'explain-parameters'
    ).value = '';

    generateExplain();
}

function hideExplainModal() {
    document.getElementById(
        'explain-modal'
    ).style.display = 'none';
}

function explainParameterValues() {
    const raw =
        document.getElementById(
            'explain-parameters'
        ).value.trim();

    if (!raw) {
        return [];
    }

    return raw
        .split(',')
        .map(value => {
            const v = value.trim();

            if (
                v.toUpperCase()
                === 'NULL'
            ) {
                return null;
            }

            return v;
        });
}

async function generateExplain() {
    if (!explainQueryId) {
        return;
    }

    const status =
        document.getElementById(
            'explain-status'
        );

    const result =
        document.getElementById(
            'explain-result'
        );

    status.innerText =
        'Generating EXPLAIN plan...';

    result.style.display =
        'none';

    const response = await fetch(
        '/api/explain',
        {
            method: 'POST',
            headers: {
                'Content-Type':
                    'application/json'
            },
            body: JSON.stringify({
                cluster_id:
                    currentCluster(),

                database:
                    currentDatabase(),

                queryid:
                    explainQueryId,

                parameters:
                    explainParameterValues()
            })
        }
    );

    const data =
        await response.json();

    if (!response.ok) {
        status.innerText =
            data.detail
            || 'Explain failed.';
        return;
    }

    document.getElementById(
        'explain-sql'
    ).innerText =
        data.query_text || '';

    if (
        data.needs_parameters
    ) {
        explainRequiredParameters =
            data.parameter_count;

        document.getElementById(
            'explain-parameter-area'
        ).style.display =
            'block';

        document.getElementById(
            'explain-parameter-label'
        ).innerText =
            'Parameters — '
            + explainRequiredParameters
            + ' required';

        status.innerText =
            data.message
            + ' Enter comma-separated values and click Generate Plan.';

        return;
    }

    const summary =
        data.summary || {};

    const recommendations =
        (
            summary.recommendations
            || []
        )
        .map(
            item =>
                '<div>• '
                + escapeHtml(item)
                + '</div>'
        )
        .join('');

    document.getElementById(
        'explain-summary'
    ).innerHTML = `
<div><strong>Root node:</strong> ${escapeHtml(summary.root_node || '-')}</div>
<div><strong>Total cost:</strong> ${summary.total_cost ?? '-'}</div>
<div><strong>Estimated rows:</strong> ${summary.plan_rows ?? '-'}</div>
<div><strong>Indexes:</strong> ${escapeHtml((summary.indexes || []).join(', ') || 'None')}</div>
<div><strong>Sequential scans:</strong> ${escapeHtml((summary.seq_scans || []).join(', ') || 'None')}</div>
<div style="margin-top:10px"><strong>PgScope:</strong></div>
${recommendations}
`;

    document.getElementById(
        'explain-plan'
    ).innerText =
        JSON.stringify(
            data.plan,
            null,
            2
        );

    document.getElementById(
        'explain-parameter-area'
    ).style.display =
        data.parameter_count > 0
        ? 'block'
        : 'none';

    status.innerText =
        'Estimated plan generated. EXPLAIN ANALYZE was not used.';

    result.style.display =
        'block';
}

async function start() {
    try {
        await loadClusters();
        await loadDatabases();
        await refreshAll();
    } catch (error) {
        console.error(error);
        document.getElementById('refresh-status').innerText =
            'Dashboard startup failed: ' + error.message;
    }
}

document.querySelectorAll('.engine-tab').forEach(tab => {
    tab.addEventListener('click', () => selectEngine(tab.dataset.engine));
});

document.querySelectorAll('.platform-status-card').forEach(card => {
    card.addEventListener('click', () => selectEngine(card.dataset.engine));
});

document.getElementById(
    'refresh-button'
).addEventListener(
    'click',
    refreshAll
);

document.getElementById(
    'cluster-select'
).addEventListener(
    'change',
    clusterChanged
);

document.getElementById(
    'database-select'
).addEventListener(
    'change',
    refreshDetail
);

document.getElementById(
    'minutes-select'
).addEventListener(
    'change',
    refreshDetail
);

document.getElementById(
    'queries-table'
).addEventListener(
    'click',
    function(event) {

        const historyButton =
            event.target.closest(
                '.history-button'
            );

        if (historyButton) {
            const queryid =
                historyButton.dataset.queryid;

            if (queryid) {
                loadHistory(
                    queryid
                );
            }

            return;
        }

        const explainButton =
            event.target.closest(
                '.explain-button'
            );

        if (explainButton) {
            const queryid =
                explainButton.dataset.queryid;

            if (queryid) {
                showExplainModal(
                    queryid
                );
            }

            return;
        }

        const queryCell =
            event.target.closest(
                '.query-click'
            );

        if (queryCell) {
            const queryid =
                queryCell.dataset.queryid;

            if (queryid) {
                showQueryDetailsModal(
                    queryid
                );
            }
        }
    }
);

document.getElementById(
    'cluster-overview'
).addEventListener(
    'click',
    function(event) {
        const card =
            event.target.closest(
                '.cluster-card'
            );

        if (!card) {
            return;
        }

        const clusterId =
            card.dataset.clusterid;

        if (!clusterId) {
            return;
        }

        selectCluster(clusterId);
    }
);


document.getElementById('add-database-button').addEventListener('click', showAddDatabase);
document.getElementById('cancel-database-button').addEventListener('click', hideAddDatabase);
document.getElementById('test-database-button').addEventListener('click', testAddDatabase);
document.getElementById('save-database-button').addEventListener('click', saveAddDatabase);
document.getElementById('disable-database-button').addEventListener('click', disableCurrentDatabase);
document.getElementById('disable-cluster-button').addEventListener('click', disableCurrentCluster);

document.getElementById('database-modal').addEventListener(
    'click',
    function(event) {
        if (event.target.id === 'database-modal') {
            hideAddDatabase();
        }
    }
);

document.getElementById('add-cluster-button').addEventListener('click',showAddCluster);
document.getElementById('cancel-cluster-button').addEventListener('click',hideAddCluster);
document.getElementById('test-cluster-button').addEventListener('click',testAddCluster);
document.getElementById('save-cluster-button').addEventListener('click',saveAddCluster);

document.getElementById(
    'generate-explain-button'
).addEventListener(
    'click',
    generateExplain
);

document.getElementById(
    'close-explain-button'
).addEventListener(
    'click',
    hideExplainModal
);

document.getElementById(
    'explain-modal'
).addEventListener(
    'click',
    function(event) {
        if (
            event.target.id
            === 'explain-modal'
        ) {
            hideExplainModal();
        }
    }
);

start();

setInterval(
    refreshAll,
    30000
);


document.getElementById('generate-report-button').addEventListener('click',generateHealthReport);
document.getElementById('print-report-button').addEventListener('click',printHealthReport);
document.getElementById('close-report-button').addEventListener('click',hideHealthReport);
document.getElementById('report-modal').addEventListener('click',function(e){if(e.target===this)hideHealthReport();});
</script>


<footer style="margin-top:32px;padding:20px 0;text-align:center;opacity:.6;font-size:12px;">
PGSCOPE · Copyright © 2026 Alexander Schou. All rights reserved.
</footer>
</body>
</html>
"""
