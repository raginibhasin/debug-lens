import pytest

from analyzers import git_analyzer


def test_git_analysis_rejects_repository_outside_allowed_roots(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    monkeypatch.setattr(git_analyzer.config, "GIT_ALLOWED_ROOTS", [str(allowed)])

    with pytest.raises(git_analyzer.GitError, match="outside the configured"):
        git_analyzer.analyze(str(outside))


def test_git_analysis_accepts_repository_inside_allowed_root(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    repo = allowed / "repo"
    repo.mkdir(parents=True)
    monkeypatch.setattr(git_analyzer.config, "GIT_ALLOWED_ROOTS", [str(allowed)])
    monkeypatch.setattr(git_analyzer, "_git", lambda *_args, **_kwargs: "")

    result = git_analyzer.analyze(str(repo))

    assert result["repo"] == str(repo.resolve())


@pytest.mark.parametrize("url", [
    "https://github.com/owner/repository",
    "https://github.com/owner/repository.git",
])
def test_normalize_public_github_repository_url(url):
    assert git_analyzer.normalize_github_url(url) == "https://github.com/owner/repository.git"


@pytest.mark.parametrize("url", [
    "http://github.com/owner/repository",
    "https://github.com.evil.example/owner/repository",
    "https://github.com/owner/repository/tree/main",
    "https://user:password@github.com/owner/repository",
    "https://github.com:invalid/owner/repository",
])
def test_normalize_github_url_rejects_unsafe_or_non_repository_urls(url):
    with pytest.raises(git_analyzer.GitError):
        git_analyzer.normalize_github_url(url)


def test_repository_file_inventory_lists_purpose_and_skips_generated_folders(tmp_path):
    repository = tmp_path / "repo"
    source = repository / "src"
    generated = repository / ".git"
    source.mkdir(parents=True)
    generated.mkdir()
    (repository / "README.md").write_text("# Demo", encoding="utf-8")
    (source / "app.py").write_text("def run_app():\n    pass\n", encoding="utf-8")
    (repository / "dataset.csv").write_text("score,label\n1,yes\n", encoding="utf-8")
    (generated / "config").write_text("internal", encoding="utf-8")

    files, truncated = git_analyzer._repository_file_inventory(str(repository))

    assert not truncated
    assert [item["path"] for item in files] == ["dataset.csv", "README.md", "src/app.py"]
    assert "Tabular" in files[0]["purpose"]
    assert "Project overview" in files[1]["purpose"]
    assert "application entry point" in files[2]["purpose"]


def test_repository_file_inventory_respects_configured_file_limit(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("A", encoding="utf-8")
    (tmp_path / "b.txt").write_text("B", encoding="utf-8")
    monkeypatch.setattr(git_analyzer.config, "MAX_FILES", 1)

    files, truncated = git_analyzer._repository_file_inventory(str(tmp_path))

    assert len(files) == 1
    assert truncated