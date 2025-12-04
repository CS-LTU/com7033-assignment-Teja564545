import os
import sys
import pytest

# Make sure Python can find app.py
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app


@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False
    })
    # ❗ No database setup here – we avoid touching DB in tests
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_home_redirects_to_login(client):
    """Homepage should redirect unauthenticated users to /login."""
    res = client.get("/", follow_redirects=False)
    assert res.status_code in (301, 302)
    assert "/login" in (res.headers.get("Location") or "")


def test_register_page_loads(client):
    """Register page should load."""
    res = client.get("/register")
    assert res.status_code == 200


def test_login_page_loads(client):
    """Login page should load."""
    res = client.get("/login")
    assert res.status_code == 200
