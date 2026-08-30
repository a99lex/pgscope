from fastapi.testclient import TestClient

import main


def test_password_hash_round_trip():
    stored = main.password_hash("correct horse battery staple")

    assert main.password_matches("correct horse battery staple", stored)
    assert not main.password_matches("wrong password", stored)


def test_login_and_password_pages_escape_dynamic_content():
    payload = '<script>alert("x")</script>'

    assert payload not in main.login_html(payload)
    assert payload not in main.change_password_html(payload, payload)
    assert "&lt;script&gt;" in main.login_html(payload)


def test_liveness_is_public_and_has_security_headers():
    response = TestClient(main.app).get(
        "/health/live",
        headers={"x-forwarded-proto": "https"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "version": main.VERSION,
    }
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "max-age=31536000" in response.headers["strict-transport-security"]


def test_readiness_returns_503_without_storage(monkeypatch):
    def unavailable_connection():
        raise RuntimeError("database details must not leak")

    monkeypatch.setattr(main, "get_connection", unavailable_connection)
    response = TestClient(main.app).get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "PgScope storage database is unavailable."
    }


def test_api_requires_authentication_and_keeps_security_headers():
    response = TestClient(main.app).get("/api/clusters")

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}
    assert response.headers["x-frame-options"] == "DENY"
