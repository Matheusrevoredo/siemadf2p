from app import app


def test_health():
    client = app.test_client()
    response = client.get("/api/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"


def test_login_fails_closed_without_ad_configuration(monkeypatch):
    monkeypatch.setitem(app.config, "SECRET_KEY", "test-secret-that-is-long-enough-for-signing")
    monkeypatch.delenv("AD_LDAPS_URL", raising=False)
    client = app.test_client()
    response = client.post(
        "/api/login",
        json={"domain": "corp.example", "username": "administrator", "password": "not-a-real-password"},
    )
    assert response.status_code == 503
    assert "incomplete" in response.get_json()["error"].lower()


def test_dashboard_requires_token():
    client = app.test_client()
    response = client.get("/api/dashboard")
    assert response.status_code == 401


def test_scan_requires_token():
    client = app.test_client()
    response = client.post("/api/scan", json={"computer": "unknown-host"})
    assert response.status_code == 401


def test_unsigned_token_is_rejected():
    client = app.test_client()
    response = client.get("/api/dashboard", headers={"Authorization": "Bearer unsigned-token"})
    assert response.status_code == 401
