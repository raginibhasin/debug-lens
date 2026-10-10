"""Git change analysis via the local `git` executable (no code from the repo is executed)."""
import os
import posixpath
import re
import subprocess
import tempfile
from urllib.parse import urlsplit

import config

from . import error_analyzer


class GitError(Exception):
    pass


TEXT_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".css", ".go", ".h", ".html", ".java", ".js", ".jsx",
    ".json", ".md", ".mjs", ".php", ".py", ".rb", ".rs", ".scss", ".sh", ".sql", ".toml",
    ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml", ".ini", ".cfg", ".tf", ".vue", ".svelte",
}


def describe_file_purpose(path, content=""):
    normalized = path.replace("\\", "/").lower()
    name = posixpath.basename(normalized)
    if name in {"readme", "readme.md", "readme.rst", "readme.txt"}:
        return "Project overview and setup guide. Usually explains what the repository does and how to run or contribute to it."
    if name in {"package.json", "pyproject.toml", "setup.py", "setup.cfg", "cargo.toml", "go.mod", "pom.xml", "build.gradle", "requirements.txt", "poetry.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
        return "Project manifest or dependency lockfile. Defines packages, build metadata, scripts, or exact dependency versions."
    if name in {"dockerfile", "docker-compose.yml", "compose.yml", "docker-compose.yaml", "compose.yaml"}:
        return "Container setup instructions. Describes how the app image is built or how local services fit together."
    if name in {"makefile", "justfile", "taskfile.yml"}:
        return "Developer task shortcuts. Common commands include tests, formatting, builds, and local development."
    if name in {"license", "license.md", "license.txt", "copying"}:
        return "Repository license terms. Describes how the project may be used, modified, or redistributed."
    if name.startswith(".env"):
        return "Environment variable template or configuration. May list settings the app expects; check carefully before sharing real values."
    if "/.github/workflows/" in f"/{normalized}":
        return "GitHub Actions workflow. Defines automated checks or deployment jobs that run for repository events."
    if "/tests/" in f"/{normalized}" or "/test/" in f"/{normalized}" or name.startswith(("test_", "spec_")):
        return "Automated test file. Exercises project behavior and helps catch regressions when code changes."
    if name == "__init__.py":
        return "Python package initializer. Marks this folder as a package and may expose shared imports or setup."
    if name in {"app.py", "main.py", "server.py", "manage.py", "index.js", "index.ts", "main.js", "main.ts"}:
        return "Likely an application entry point. Often wires the app together and starts the server, command, or main workflow."
    if name in {"config.py", "settings.py", "config.js", "settings.js"}:
        return "Application configuration. Typically gathers environment settings, feature flags, or service options."

    symbols = re.findall(r"^\s*(?:async\s+)?(?:def|class|function|interface|type|enum)\s+([A-Za-z_$][\w$]*)", content, re.MULTILINE)
    if symbols:
        names = ", ".join(symbols[:3])
        return f"Defines {names}. These declarations are a useful starting point for understanding this module's responsibilities."

    extension = posixpath.splitext(name)[1]
    if extension in {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".cs", ".go", ".rs", ".rb", ".php"}:
        language = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript UI", ".ts": "TypeScript",
                    ".tsx": "TypeScript UI", ".java": "Java", ".cs": "C#", ".go": "Go", ".rs": "Rust",
                    ".rb": "Ruby", ".php": "PHP"}.get(extension, "Source")
        return f"{language} source module. Its path and declarations can help identify which part of the application it implements."
    if extension in {".yml", ".yaml", ".toml", ".ini", ".cfg", ".json", ".xml", ".tf"}:
        return "Structured project configuration. Check the filename and consuming tool to see which settings it controls."
    if extension in {".png", ".jpg", ".jpeg", ".svg", ".webp", ".ico", ".woff", ".woff2"}:
        return "Static visual or font asset. Usually included in the app's interface or generated output."
    if extension in {".csv", ".tsv", ".parquet", ".jsonl"}:
        return "Tabular or line-oriented data file. It may provide examples, training data, or records consumed by the application."
    if extension in {".pkl", ".pickle", ".joblib", ".onnx", ".pt", ".pth", ".h5"}:
        return "Serialized model or data artifact. It may be loaded by application code; DebugLens lists it but does not open or execute it."
    if extension:
        return f"{extension[1:].upper()} project file. Its role is not obvious from its name alone; inspect its references in the codebase."
    return "Project support file. The filename does not reveal a specific role; inspect nearby documentation or references."


def _repository_file_inventory(repo):
    files = []
    truncated = False
    for root, directories, filenames in os.walk(repo, followlinks=False):
        directories[:] = sorted((directory for directory in directories
                                 if directory not in config.SKIP_DIRS and
                                 not os.path.islink(os.path.join(root, directory))), key=str.casefold)
        for filename in sorted(filenames, key=str.casefold):
            full_path = os.path.join(root, filename)
            if os.path.islink(full_path):
                continue
            relative_path = os.path.relpath(full_path, repo).replace(os.sep, "/")
            if len(files) >= config.MAX_FILES:
                truncated = True
                break
            content = ""
            extension = posixpath.splitext(filename.lower())[1]
            if (extension in TEXT_EXTENSIONS or filename.lower() in {"dockerfile", "makefile", "justfile"}) \
                    and os.path.getsize(full_path) <= 64_000:
                try:
                    with open(full_path, "r", encoding="utf-8", errors="replace") as source_file:
                        content = source_file.read(8_192)
                except OSError:
                    content = ""
            files.append({"path": relative_path, "purpose": describe_file_purpose(relative_path, content)})
        if truncated:
            break
    return files, truncated


def normalize_github_url(url):
    try:
        parsed = urlsplit((url or "").strip())
        port = parsed.port
    except ValueError as exc:
        raise GitError("The GitHub repository URL is malformed.") from exc
    if parsed.scheme.lower() != "https" or (parsed.hostname or "").lower() != "github.com" \
            or parsed.username or parsed.password or port or parsed.query or parsed.fragment:
        raise GitError("Enter a public GitHub repository URL such as https://github.com/owner/repository.")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        raise GitError("Use the repository's main GitHub URL, not a file, branch, or folder link.")
    owner, name = parts
    if name.endswith(".git"):
        name = name[:-4]
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner) \
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in (".", ".."):
        raise GitError("The GitHub repository URL has an invalid owner or repository name.")
    return f"https://github.com/{owner}/{name}.git"


def _git(repo, *args, timeout=20):
    try:
        p = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise GitError("Git is not installed or not on PATH (https://git-scm.com/download/win).")
    except subprocess.TimeoutExpired:
        raise GitError("Git command timed out.")
    if p.returncode != 0:
        raise GitError((p.stderr or p.stdout).strip()[:300] or "git command failed")
    return p.stdout


def _safe_ref(ref):
    if ref and not re.match(r"^[\w./~^@{}\-]+$", ref):
        raise GitError(f"Invalid revision: {ref!r}")
    return ref


def _is_allowed_repo(repo):
    for root in config.GIT_ALLOWED_ROOTS:
        try:
            common = os.path.commonpath((repo, os.path.realpath(root)))
            if os.path.normcase(common) == os.path.normcase(os.path.realpath(root)):
                return True
        except ValueError:
            continue
    return False


def analyze(repo_path, error_text="", base="", head="HEAD", limit=15,
            enforce_allowed_root=True, display_repo=None):
    repo = os.path.realpath(os.path.abspath(os.path.expanduser((repo_path or "").strip().strip('"'))))
    if enforce_allowed_root and not _is_allowed_repo(repo):
        raise GitError("Repository is outside the configured Git analysis folders.")
    if not os.path.isdir(repo):
        raise GitError(f"Folder not found: {repo}")
    _git(repo, "rev-parse", "--is-inside-work-tree")
    base, head = _safe_ref(base.strip()), _safe_ref(head.strip() or "HEAD")
    limit = max(1, min(int(limit or 15), 50))

    raw = _git(repo, "log", f"-n{limit}", "--date=iso", "--name-status", "--pretty=format:@@%h\x1f%an\x1f%ad\x1f%s")
    commits, cur = [], None
    for line in raw.split("\n"):
        if line.startswith("@@"):
            h, a, d, s = line[2:].split("\x1f", 3)
            cur = {"hash": h, "author": a, "date": d, "subject": s, "files": []}
            commits.append(cur)
        elif line.strip() and cur is not None:
            parts = line.split("\t")
            cur["files"].append({"status": parts[0], "path": parts[-1]})

    result = {"repo": display_repo or repo, "commits": commits, "diff": None, "suspects": [], "blame": []}

    if base:
        names = _git(repo, "diff", "--name-status", f"{base}..{head}").strip().split("\n")
        stat = _git(repo, "diff", "--stat", f"{base}..{head}").strip().split("\n")
        result["diff"] = {"base": base, "head": head,
                          "files": [dict(zip(("status", "path"), (n.split("\t")[0], n.split("\t")[-1]))) for n in names if n],
                          "stat": stat[-1] if stat else ""}

    if error_text.strip():
        parsed = error_analyzer.parse(error_text)
        tracked = [f for f in _git(repo, "ls-files").split("\n") if f]
        frames = [f for f in parsed["frames"] if not error_analyzer._is_library(f["file"], parsed["language"])][:6]
        changed = {}
        for c in commits:
            for f in c["files"]:
                changed.setdefault(f["path"], []).append(c)
        if result["diff"]:
            for f in result["diff"]["files"]:
                changed.setdefault(f["path"], [])
        for fr in frames:
            want = fr["file"].replace("\\", "/")
            base_name = posixpath.basename(want)
            tracked_path = next((t for t in tracked if want.endswith(t) or t.endswith(want)), None) or \
                next((t for t in tracked if posixpath.basename(t) == base_name), None)
            if not tracked_path:
                continue
            for c in changed.get(tracked_path, []):
                result["suspects"].append({"file": tracked_path, "commit": c["hash"], "author": c["author"],
                                           "date": c["date"], "subject": c["subject"],
                                           "reason": "File named in the error was modified in this recent commit"})
            try:
                out = _git(repo, "blame", "-L", f"{fr['line']},{fr['line']}", "--porcelain", tracked_path)
                head_line = out.split("\n")[0].split()
                meta = dict(l.split(" ", 1) for l in out.split("\n")[1:12] if " " in l and not l.startswith("\t"))
                result["blame"].append({"file": tracked_path, "line": fr["line"], "commit": head_line[0][:8],
                                        "author": meta.get("author", ""), "summary": meta.get("summary", ""),
                                        "code": next((l[1:] for l in out.split("\n") if l.startswith("\t")), "").strip()})
            except GitError:
                pass
    result["note"] = ("A suspect commit is a lead to investigate (the file changed recently), "
                      "not proof that the change caused the error.")
    return result


def analyze_github(repo_url, error_text="", base="", head="HEAD", limit=15):
    normalized_url = normalize_github_url(repo_url)
    environment = os.environ.copy()
    environment.update({
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_TERMINAL_PROMPT": "0",
    })
    with tempfile.TemporaryDirectory(prefix="debuglens-github-") as temp_root:
        destination = os.path.join(temp_root, "repository")
        try:
            clone = subprocess.run(
                ["git", "clone", "--depth", "20", "--single-branch", "--no-tags",
                 "--no-recurse-submodules", "--filter=blob:none", normalized_url, destination],
                capture_output=True, text=True, timeout=90, encoding="utf-8", errors="replace",
                env=environment)
        except FileNotFoundError as exc:
            raise GitError("Git is not installed or not on PATH.") from exc
        except subprocess.TimeoutExpired as exc:
            raise GitError("GitHub clone timed out. Try again or clone the repository locally.") from exc
        if clone.returncode != 0:
            detail = (clone.stderr or clone.stdout).strip()
            if "repository not found" in detail.lower() or "authentication failed" in detail.lower():
                raise GitError("Could not access that public GitHub repository. Check the URL and repository visibility.")
            raise GitError((detail[:300] if detail else "GitHub clone failed.") +
                           " Ensure this is a public repository URL and try again.")
        result = analyze(destination, error_text, base, head, limit,
                         enforce_allowed_root=False, display_repo=normalized_url)
        result["files"], result["files_truncated"] = _repository_file_inventory(destination)
        result["source"] = "GitHub public repository"
        result["note"] += " The repository was shallow-cloned to temporary storage and was not executed."
        return result
