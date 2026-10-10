import json

import pytest

import config
import database
from analyzers import ai_service, git_analyzer


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "app.db"))
    monkeypatch.setattr(config, "AI_ENABLED", False)
    database.init_db()
    from app import app, limiter

    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = False
    monkeypatch.setattr(limiter, "enabled", False)
    return app.test_client()


def test_protected_pages_and_apis_require_login(client):
    assert client.get("/").status_code == 302
    assert client.get("/workspace").status_code == 302
    response = client.get("/api/stats")
    assert response.status_code == 401
    assert response.json["error"] == "Authentication required."


def test_account_recovery_page_is_public_and_points_to_local_reset(client):
    response = client.get("/recover")

    assert response.status_code == 200
    assert b"reset-account-password" in response.data
    assert b"Back to sign in" in response.data


def test_login_csrf_and_cross_account_history_access(client):
    owner = database.create_owner("owner@example.com", "correct horse battery staple")
    login = client.post("/api/auth/login", json={
        "email": "owner@example.com",
        "password": "correct horse battery staple",
    })
    assert login.status_code == 200
    csrf = login.json["csrf_token"]
    welcome = client.get("/")
    workspace = client.get("/workspace")
    assert b"Find clarity in the complicated parts." in welcome.data
    assert b"/workspace" in welcome.data
    assert b"id=\"code-files\"" not in welcome.data
    assert b"id=\"code-files\"" in workspace.data
    assert b"id=\"nav\"" in workspace.data
    assert b'id="guided-start"' in workspace.data
    assert b'id="guided-tour" class="guided-tour" hidden' in workspace.data
    assert b'id="ai-search-form"' in workspace.data
    assert b'id="ai-cluster-button"' in workspace.data

    missing_csrf = client.post("/api/error", json={"text": "ValueError: example"})
    assert missing_csrf.status_code == 400

    analysis = client.post("/api/error", json={"text": "ValueError: example"},
                           headers={"X-CSRF-Token": csrf})
    assert analysis.status_code == 200
    analysis_id = analysis.json["id"]
    json_export = client.get(f"/api/history/{analysis_id}/export.json")
    assert json_export.status_code == 200
    assert json.loads(json_export.data)["id"] == analysis_id
    pdf_export = client.get(f"/api/history/{analysis_id}/export.pdf")
    assert pdf_export.status_code == 200
    assert pdf_export.data.startswith(b"%PDF-")

    invite = database.issue_invite(owner["id"])
    database.create_invited_user("member@example.com", "another secure password", invite)
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    member_login = client.post("/api/auth/login", json={
        "email": "member@example.com",
        "password": "another secure password",
    })
    assert member_login.status_code == 200
    assert client.get(f"/api/history/{analysis_id}").status_code == 404
    assert client.get(f"/api/history/{analysis_id}/export.json").status_code == 404


def test_guided_sample_demo_saves_real_analysis_results(client):
    database.create_owner("owner@example.com", "correct horse battery staple")
    login = client.post("/api/auth/login", json={
        "email": "owner@example.com",
        "password": "correct horse battery staple",
    })
    response = client.post("/api/demo/sample-project",
                           headers={"X-CSRF-Token": login.json["csrf_token"]})

    assert response.status_code == 200
    assert response.json["code"]["summary"]["files"] == 2
    assert response.json["security"]["files_scanned"] == 4
    assert response.json["security"]["counts"]["high"] > 0
    assert {item["kind"] for item in database.list_all(login.json["user"]["id"])} == {"code", "security"}


def test_sample_project_browser_returns_readable_allowlisted_files(client):
    database.create_owner("owner@example.com", "correct horse battery staple")
    client.post("/api/auth/login", json={
        "email": "owner@example.com",
        "password": "correct horse battery staple",
    })

    response = client.get("/api/demo/sample-project/files")

    assert response.status_code == 200
    files = {item["name"]: item for item in response.json["files"]}
    assert set(files) == {"app.py", "helpers.py", "requirements.txt", "Dockerfile"}
    assert "eval(" in files["app.py"]["content"]
    assert "FROM python:latest" in files["Dockerfile"]["content"]
    assert all(item["description"] for item in files.values())


def test_git_api_routes_public_github_url_to_remote_analyzer(client, monkeypatch):
    owner = database.create_owner("owner@example.com", "correct horse battery staple")
    login = client.post("/api/auth/login", json={
        "email": owner["email"],
        "password": "correct horse battery staple",
    })
    expected_url = "https://github.com/owner/repository.git"
    monkeypatch.setattr(git_analyzer, "analyze_github", lambda url, *args: {
        "repo": git_analyzer.normalize_github_url(url), "source": "GitHub public repository", "commits": [], "diff": None,
        "suspects": [], "blame": [], "files": [{"path": "app.py", "purpose": "Likely the app entry point."}],
        "files_truncated": False, "note": "not executed",
    })

    response = client.post("/api/git", json={"repo_url": "https://github.com/owner/repository"},
                           headers={"X-CSRF-Token": login.json["csrf_token"]})

    assert response.status_code == 200
    assert response.json["repo"] == expected_url
    assert response.json["files"][0]["purpose"] == "Likely the app entry point."
    assert database.list_all(owner["id"])[0]["title"] == "Git analysis: repository"

    pasted_url = client.post("/api/git", json={"repo_path": "https://github.com/owner/repository"},
                             headers={"X-CSRF-Token": login.json["csrf_token"]})
    assert pasted_url.status_code == 200
    assert pasted_url.json["repo"] == expected_url


def test_ai_search_reports_disabled_without_breaking_existing_analysis(client):
    database.create_owner("owner@example.com", "correct horse battery staple")
    login = client.post("/api/auth/login", json={
        "email": "owner@example.com", "password": "correct horse battery staple",
    })
    status = client.get("/api/ai/status")
    assert status.json["enabled"] is False

    response = client.post("/api/ai/search", json={"query": "empty input division"},
                           headers={"X-CSRF-Token": login.json["csrf_token"]})

    assert response.status_code == 503
    assert "disabled" in response.json["error"].lower()


def test_semantic_search_and_error_clusters_are_scoped_to_current_user(client, monkeypatch):
    owner = database.create_owner("owner@example.com", "correct horse battery staple")
    invite = database.issue_invite(owner["id"])
    member = database.create_invited_user("member@example.com", "another secure password", invite)
    owner_first = database.save(owner["id"], "error", "Empty input division", "division by zero", {"message": "empty list"})
    owner_second = database.save(owner["id"], "error", "No items to divide", "zero divisor", {"message": "no rows"})
    member_item = database.save(member["id"], "error", "Empty input division", "division by zero", {"message": "private"})
    for analysis_id in (owner_first, owner_second):
        database.save_embedding(owner["id"], analysis_id, config.OLLAMA_EMBED_MODEL, [1.0, 0.0])
    database.save_embedding(member["id"], member_item, config.OLLAMA_EMBED_MODEL, [1.0, 0.0])
    monkeypatch.setattr(ai_service.config, "AI_ENABLED", True)
    monkeypatch.setattr(ai_service, "embed_text", lambda _text: [1.0, 0.0])

    login = client.post("/api/auth/login", json={
        "email": owner["email"], "password": "correct horse battery staple",
    })
    headers = {"X-CSRF-Token": login.json["csrf_token"]}
    search = client.post("/api/ai/search", json={"query": "why does division fail on empty input"}, headers=headers)
    clusters = client.get("/api/ai/error-clusters")

    assert search.status_code == 200
    assert {item["id"] for item in search.json["results"]} == {owner_first, owner_second}
    assert clusters.status_code == 200
    assert clusters.json["clusters"][0]["count"] == 2
    assert {item["id"] for item in clusters.json["clusters"][0]["analyses"]} == {owner_first, owner_second}


def test_error_analysis_uses_local_embedding_when_enabled(client, monkeypatch):
    owner = database.create_owner("owner@example.com", "correct horse battery staple")
    previous = database.save(owner["id"], "error", "ZeroDivisionError", "division by zero",
                             {"error_type": "ZeroDivisionError", "message": "empty list"}, norm="zero division")
    database.save_embedding(owner["id"], previous, config.OLLAMA_EMBED_MODEL, [1.0, 0.0])
    monkeypatch.setattr(ai_service.config, "AI_ENABLED", True)
    monkeypatch.setattr(ai_service, "embed_text", lambda _text: [1.0, 0.0])
    login = client.post("/api/auth/login", json={
        "email": owner["email"], "password": "correct horse battery staple",
    })

    response = client.post("/api/error", json={"text": "ZeroDivisionError: division by zero"},
                           headers={"X-CSRF-Token": login.json["csrf_token"]})

    assert response.status_code == 200
    assert response.json["error_type"] == "ZeroDivisionError"
    assert response.json["similar"][0]["id"] == previous
    assert len(database.embedding_rows(owner["id"], config.OLLAMA_EMBED_MODEL)) == 2


def test_ai_explanation_requires_analysis_ownership(client, monkeypatch):
    owner = database.create_owner("owner@example.com", "correct horse battery staple")
    invite = database.issue_invite(owner["id"])
    member = database.create_invited_user("member@example.com", "another secure password", invite)
    owner_item = database.save(owner["id"], "error", "Owner error", "summary", {"message": "private owner details"})
    member_item = database.save(member["id"], "error", "Member error", "summary", {"message": "private member details"})
    monkeypatch.setattr(ai_service, "explain_analysis", lambda item: {
        "explanation": f"Explanation for {item['title']}", "verified_facts": [], "possible_causes": [],
        "suggested_checks": [], "disclaimer": "Suggestions, not guarantees.",
    })
    login = client.post("/api/auth/login", json={
        "email": owner["email"], "password": "correct horse battery staple",
    })
    headers = {"X-CSRF-Token": login.json["csrf_token"]}

    own = client.post(f"/api/history/{owner_item}/explain", headers=headers)
    other = client.post(f"/api/history/{member_item}/explain", headers=headers)

    assert own.status_code == 200
    assert "Owner error" in own.json["explanation"]["explanation"]
    assert other.status_code == 404