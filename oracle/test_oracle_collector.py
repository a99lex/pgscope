from oracle_collector import assert_basic_sql, clean_nul, TOP_SQL, SESSIONS, WAITS, INSTANCE


def test_basic_queries_allowed():
    for sql in (TOP_SQL, SESSIONS, WAITS, INSTANCE):
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
