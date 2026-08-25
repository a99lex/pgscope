from oracle_collector import assert_basic_sql, TOP_SQL, SESSIONS, WAITS, INSTANCE


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
