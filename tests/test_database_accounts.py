import pytest

import config
import database


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    database.init_db()


def test_analysis_history_is_isolated_by_user(isolated_db):
    owner = database.create_owner("owner@example.com", "correct horse battery staple")
    invite = database.issue_invite(owner["id"])
    member = database.create_invited_user("member@example.com", "another secure password", invite)
    owner_item = database.save(owner["id"], "error", "owner error", "", {"private": "owner"})
    member_item = database.save(member["id"], "error", "member error", "", {"private": "member"})

    assert [item["title"] for item in database.list_all(owner["id"])] == ["owner error"]
    assert database.get(member["id"], owner_item) is None
    assert database.get(owner["id"], member_item) is None
    database.delete(member["id"], owner_item)
    assert database.get(owner["id"], owner_item) is not None


def test_invitation_is_single_use(isolated_db):
    owner = database.create_owner("owner@example.com", "correct horse battery staple")
    invite = database.issue_invite(owner["id"])

    database.create_invited_user("member@example.com", "another secure password", invite)
    with pytest.raises(ValueError, match="invalid, expired, or already used"):
        database.create_invited_user("second@example.com", "another secure password", invite)


def test_owner_password_can_be_reset(isolated_db):
    database.create_owner("owner@example.com", "original secure password")

    owner = database.reset_owner_password("replacement secure password")

    assert owner["email"] == "owner@example.com"
    assert database.authenticate_user(owner["email"], "replacement secure password") == owner
    assert database.authenticate_user(owner["email"], "original secure password") is None


def test_analysis_embeddings_are_user_scoped_and_deleted_with_analysis(isolated_db):
    owner = database.create_owner("owner@example.com", "correct horse battery staple")
    invite = database.issue_invite(owner["id"])
    member = database.create_invited_user("member@example.com", "another secure password", invite)
    owner_analysis = database.save(owner["id"], "error", "owner error", "", {})
    member_analysis = database.save(member["id"], "error", "member error", "", {})

    assert database.save_embedding(owner["id"], owner_analysis, "local-v1", [1.0, 0.0])
    assert database.save_embedding(member["id"], owner_analysis, "local-v1", [0.0, 1.0]) is False
    assert database.save_embedding(member["id"], member_analysis, "local-v1", [0.0, 1.0])
    assert [row["id"] for row in database.embedding_rows(owner["id"], "local-v1")] == [owner_analysis]
    assert [row["id"] for row in database.embedding_rows(member["id"], "local-v1")] == [member_analysis]

    database.delete(owner["id"], owner_analysis)

    assert database.embedding_rows(owner["id"], "local-v1") == []