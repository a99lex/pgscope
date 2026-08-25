#!/usr/bin/env python3
from pathlib import Path
import shutil
import sys

target = Path(sys.argv[1] if len(sys.argv) > 1 else "api/main.py")
if not target.exists():
    raise SystemExit(f"File not found: {target}")

text = target.read_text()
backup = target.with_suffix(target.suffix + ".before-cluster-management")
shutil.copy2(target, backup)

backend_marker = "\n\nclass ExplainRequest(BaseModel):"

backend_code = r'''

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
                UPDATE monitored_databases
                SET enabled = false
                WHERE cluster_id = %s
                  AND database_name = %s
                  AND enabled = true
                RETURNING database_name
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
'''

if '@app.post("/api/configured-databases")' not in text:
    if backend_marker not in text:
        raise SystemExit("Could not find backend insertion marker.")
    text = text.replace(backend_marker, backend_code + backend_marker, 1)

toolbar_marker = '<button id="refresh-button">Refresh</button>'

toolbar_code = '''<button id="refresh-button">Refresh</button>
<button id="add-database-button">+ Add database</button>
<button id="disable-database-button" class="danger-button">Disable database</button>
<button id="disable-cluster-button" class="danger-button">Disable cluster</button>'''

if 'id="add-database-button"' not in text:
    if toolbar_marker not in text:
        raise SystemExit("Could not find toolbar marker.")
    text = text.replace(toolbar_marker, toolbar_code, 1)

modal_marker = '<div id="cluster-modal" class="modal-bg">'

db_modal = '''<div id="database-modal" class="modal-bg">
<div class="modal">
<h2>Add Database</h2>

<div class="form-grid">
<div class="form-field full">
<label>Cluster</label>
<input id="database-cluster-name" readonly>
</div>

<div class="form-field full">
<label>Database name</label>
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

'''

if 'id="database-modal"' not in text:
    if modal_marker not in text:
        raise SystemExit("Could not find modal insertion marker.")
    text = text.replace(modal_marker, db_modal + modal_marker, 1)

css_marker = ".query-click {"

danger_css = '''.danger-button {
    border-color: #7f1d1d;
    color: #fca5a5;
}

.danger-button:hover {
    background: rgba(127, 29, 29, 0.25);
    border-color: #ef4444;
}

'''

if ".danger-button {" not in text:
    if css_marker in text:
        text = text.replace(css_marker, danger_css + css_marker, 1)
    else:
        text = text.replace("</style>", danger_css + "</style>", 1)

js_marker = "function formValues() {"

js_code = r'''function showAddDatabase() {
    const cluster = currentCluster();
    const status = document.getElementById('database-form-status');

    if (!cluster) {
        alert('Select a cluster first.');
        return;
    }

    document.getElementById('database-cluster-name').value = cluster;
    document.getElementById('new-database-name').value = '';
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
        '/api/test-configured-database',
        {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(v)
        }
    );

    const data = await response.json();

    status.innerText = response.ok
        ? `Connection OK - PostgreSQL ${data.server_version}, ${data.database_name}${data.in_recovery ? ' (replica)' : ' (primary)'}`
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
        '/api/configured-databases',
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
        '/api/configured-databases/'
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
        '/api/configured-clusters/' + encodeURIComponent(cluster),
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

'''

if "async function saveAddDatabase()" not in text:
    if js_marker not in text:
        raise SystemExit("Could not find JS insertion marker.")
    text = text.replace(js_marker, js_code + js_marker, 1)

event_marker = "document.getElementById('add-cluster-button').addEventListener('click',showAddCluster);"

event_code = r'''document.getElementById('add-database-button').addEventListener('click', showAddDatabase);
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

'''

if "disable-database-button').addEventListener" not in text:
    if event_marker not in text:
        raise SystemExit("Could not find event-handler insertion marker.")
    text = text.replace(event_marker, event_code + event_marker, 1)

target.write_text(text)

print(f"Updated: {target}")
print(f"Backup:  {backup}")
print("Added database/cluster management endpoints and UI.")
