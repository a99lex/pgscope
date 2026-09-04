from oracle_collector import (
    INSTANCE, OS_STATS, PGA_STATS, RESOURCE_LIMITS, SESSIONS,
    SGA_STATS, TOP_SQL, WAITS, assert_basic_sql, clean_nul, load_targets,
    snapshot_database_name,
)


def test_basic_queries_allowed():
    for sql in (TOP_SQL, SESSIONS, WAITS, INSTANCE, OS_STATS, SGA_STATS, PGA_STATS, RESOURCE_LIMITS):
        assert_basic_sql(sql)


def test_ash_is_rejected():
    try:
        assert_basic_sql("select * from v$active_session_history")
    except RuntimeError as exc:
        assert "Forbidden" in str(exc)
    else:
        raise AssertionError("ASH should have been rejected")


def test_awr_is_rejected():
    try:
        assert_basic_sql("select * from dba_hist_sqlstat")
    except RuntimeError as exc:
        assert "Forbidden" in str(exc)
    else:
        raise AssertionError("AWR should have been rejected")


def test_clean_nul_recursively_sanitizes_collector_payload():
    value = {"query_text": "select\x00 1", "sessions": [{"program": "app\x00"}]}
    assert clean_nul(value) == {
        "query_text": "select 1",
        "sessions": [{"program": "app"}],
    }


def test_snapshot_database_name_uses_configured_service_name():
    payload = {"database_name": "FREE"}
    target = {"database_name": "freepdb1"}

    assert snapshot_database_name(payload, target) == "freepdb1"


def test_load_targets_only_selects_enabled_oracle_databases(monkeypatch):
    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql):
            normalized = " ".join(sql.split()).lower()
            assert "c.engine = 'oracle'" in normalized
            assert "c.enabled = true" in normalized
            assert "d.enabled = true" in normalized

        def fetchall(self):
            return [{"cluster_id": "oracle-1", "database_name": "FREEPDB1"}]

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(
        "oracle_collector.store_connection",
        lambda: Connection(),
    )

    assert load_targets() == [
        {"cluster_id": "oracle-1", "database_name": "FREEPDB1"}
    ]
