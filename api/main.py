import os
import re
import base64
import hashlib
import urllib.parse
import secrets

import psycopg
from psycopg.rows import dict_row
from psycopg import sql

from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel, Field

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config


VERSION = "1.4.0"

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
    error_html = (
        f'<div class="error">{error}</div>'
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
</style>
</head>
<body>
<div class="login-card">
<h1>PgScope</h1>
<div class="subtitle">PostgreSQL Performance Advisor</div>
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
    error_html = (
        f'<div class="error">{error}</div>'
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
<div>User: <strong>{username}</strong></div>
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


@app.get("/health")
def health():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT now() AS database_time")
            row = cur.fetchone()

    return {
        "status": "ok",
        "version": VERSION,
        "database_time": row["database_time"],
    }


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
    WHERE enabled = true
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
        database_name
    FROM monitored_databases
    WHERE enabled = true
      AND (
          %s::text IS NULL
          OR cluster_id = %s::text
      )
    ORDER BY database_name
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
        le=1440,
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
        le=1440,
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
        raise HTTPException(status_code=400, detail="At least one database is required.")
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""INSERT INTO monitored_clusters
                    (cluster_id,cluster_name,host,port,username,secret_name,secret_key,enabled,updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,true,now())
                    ON CONFLICT (cluster_id) DO UPDATE SET
                    cluster_name=EXCLUDED.cluster_name, host=EXCLUDED.host,
                    port=EXCLUDED.port, username=EXCLUDED.username,
                    secret_name=EXCLUDED.secret_name,
                    secret_key=EXCLUDED.secret_key,
                    enabled=true, updated_at=now()""",
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

        return {
            "ok": True,
            "queryid": request.queryid,
            "cluster_id": request.cluster_id,
            "database": request.database,
            "query_text": query_text,
            "parameter_count": parameter_count,
            "plan": plan,
            "summary": plan_summary(
                plan
            ),
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

.query-click {
    cursor: pointer;
}

.query-click:hover {
    color: #93c5fd;
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
<div class="subtitle">PostgreSQL Performance Advisor</div>


<button id="add-cluster-button" class="add-btn">+ Add Cluster / DB</button>
<a href="/logout" style="float:right;margin:8px 12px 0 0;color:#94a3b8;text-decoration:none">Logout</a>
<div style="clear:both"></div>

<div id="cluster-modal" class="modal-bg">
<div class="modal">
<h2>Add Cluster / DB</h2>
<div class="form-grid">
<div class="form-field"><label>Cluster ID</label><input id="new-cluster-id" placeholder="prod-eu-1"></div>
<div class="form-field"><label>Name</label><input id="new-cluster-name" placeholder="Production EU"></div>
<div class="form-field"><label>Host</label><input id="new-host" placeholder="postgres-rw"></div>
<div class="form-field"><label>Port</label><input id="new-port" type="number" value="5432"></div>
<div class="form-field"><label>Username</label><input id="new-username" placeholder="pgscope_monitor"></div>
<div class="form-field"><label>Password (test only)</label><input id="new-password" type="password"></div>
<div class="form-field full"><label>Databases</label><input id="new-databases" placeholder="postgres, appdb"></div>
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
<h2>PostgreSQL Health Report</h2>
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
<h3>Top Queries</h3><table><thead><tr><th>Query ID</th><th>Calls</th><th>Total ms</th><th>Avg ms</th><th>WAL MB</th><th>Query</th></tr></thead>
<tbody id="report-top-queries"></tbody></table></div>
<div class="form-actions"><button id="print-report-button" class="report-button">Print / Save PDF</button><button id="close-report-button">Close</button></div></div></div>
<h2>Cluster Overview</h2>
<div id="cluster-overview" class="overview-grid"></div>

<div class="toolbar">
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
</select>

<button id="refresh-button">Refresh</button>
<button id="generate-report-button" class="report-button">Generate Report</button>
<div id="refresh-status" class="status">Ready</div>
</div>

<div class="cards">
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

<div class="panel">
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

<div class="panel">
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

async function loadClusters() {
    const response = await fetch('/api/clusters');

    if (!response.ok) {
        throw new Error(
            'Clusters API failed: ' + response.status
        );
    }

    const rows = await response.json();
    const select = document.getElementById('cluster-select');
    const previous = select.value;

    select.innerHTML = '';

    rows.forEach(row => {
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
    const cluster = currentCluster();

    const response = await fetch(
        '/api/databases?cluster_id=' + encodeURIComponent(cluster)
    );

    if (!response.ok) {
        throw new Error(
            'Databases API failed: ' + response.status
        );
    }

    const rows = await response.json();
    const select = document.getElementById('database-select');
    const previous = select.value;

    select.innerHTML = '';

    rows.forEach(row => {
        const option = document.createElement('option');

        option.value = row.database_name;
        option.textContent = row.database_name;

        if (
            row.database_name === previous
            ||
            (
                !previous
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
        '/api/top-queries'
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

async function refreshDetail() {
    await loadSummary();
    await loadFindings();
    await loadQueries();
}

async function refreshAll() {
    const status =
        document.getElementById('refresh-status');

    status.innerText = 'Refreshing...';

    try {
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
 const modal=document.getElementById('report-modal'),status=document.getElementById('report-status'),content=document.getElementById('report-content');
 modal.style.display='flex'; content.style.display='none'; status.innerText='Analyzing PostgreSQL...';
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
  const res=await fetch('/api/health-report?cluster_id='+encodeURIComponent(cluster)+'&database='+encodeURIComponent(database)+'&minutes='+minutes);
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
  (d.metrics.top_queries||[]).forEach(q=>{const r=document.createElement('tr');r.innerHTML='<td>'+escapeHtml(q.queryid)+'</td><td>'+q.calls+'</td><td>'+q.total_exec_ms+'</td><td>'+q.avg_exec_ms+'</td><td>'+q.wal_mb+'</td><td class="query">'+escapeHtml(q.query_text)+'</td>';tq.appendChild(r);});
 }catch(e){status.innerText='Health report failed: '+e.message;}
}
function printHealthReport(){
    window.print();
}
function hideHealthReport(){document.getElementById('report-modal').style.display='none';}

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
function showAddCluster(){ document.getElementById('cluster-modal').style.display='flex'; }
function hideAddCluster(){ document.getElementById('cluster-modal').style.display='none'; }

async function testAddCluster() {
    const v=formValues(), st=document.getElementById('cluster-form-status');
    if(!v.host || !v.username || !v.password || !v.databases.length){ st.innerText='Host, username, password and database are required.'; return; }
    st.innerText='Testing connection...';
    const res=await fetch('/api/test-cluster',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({host:v.host,port:v.port,username:v.username,password:v.password,database:v.databases[0]})});
    const d=await res.json();
    st.innerText=res.ok ? `Connection OK — PostgreSQL ${d.server_version}, ${d.database_name}${d.in_recovery?' (replica)':' (primary)'}` : (d.detail || 'Test failed');
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
        || !v.databases.length
    ) {
        st.innerText =
            'Fill in cluster ID, name, host, username and database.';
        return;
    }

    st.innerText = 'Saving...';

    const res = await fetch(
        '/api/configured-clusters',
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
    await loadClusters();
    await loadDatabases();
    await refreshAll();
}

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
                showExplainModal(
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

</body>
</html>
"""
