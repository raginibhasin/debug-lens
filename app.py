"""DebugLens - Flask backend. Run:  python app.py   then open http://127.0.0.1:5000

Safety: uploaded files are only READ as text in memory (never executed, never written to disk)."""
import io
import getpass
import hmac
import json
import os
import posixpath
import re
import secrets
import zipfile
from html import escape

import click
from flask import Flask, Response, g, jsonify, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer

import config
import database
from analyzers import (ai_service, code_analyzer, dependency_checker, error_analyzer, git_analyzer,
                       log_analyzer, security_scanner, similarity)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.SECRET_KEY or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("DEBUGLENS_COOKIE_SECURE", "").lower() in ("1", "true", "yes"),
)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_MB * 1024 * 1024
limiter = Limiter(key_func=get_remote_address, app=app,
                  storage_uri=config.RATELIMIT_STORAGE_URI,
                  default_limits=["200 per day", "50 per hour"])
database.init_db()

PUBLIC_ENDPOINTS = {"login_page", "register_page", "recovery_page", "auth_session", "auth_login",
                    "auth_register", "health", "static"}


@app.before_request
def require_authenticated_session():
    g.user = database.get_user(session.get("user_id"))
    if request.endpoint in PUBLIC_ENDPOINTS:
        return
    if not g.user:
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify(error="Authentication required."), 401
        return redirect(url_for("login_page"))
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        supplied = request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(supplied, expected):
            return jsonify(error="Invalid or missing CSRF token."), 400


@app.errorhandler(429)
def rate_limit_exceeded(_error):
    return jsonify(error="Too many requests. Please try again shortly."), 429


@app.cli.command("create-owner")
def create_owner_command():
    """Create the first owner account interactively."""
    email = click.prompt("Owner email")
    password = getpass.getpass("Password (minimum 12 characters): ")
    if len(password) < 12:
        raise click.ClickException("Password must be at least 12 characters.")
    try:
        user = database.create_owner(email, password)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Created owner account for {user['email']}.")


@app.cli.command("reset-owner-password")
def reset_owner_password_command():
    """Reset the existing owner password from the local machine."""
    password = click.prompt("New password (minimum 12 characters)", hide_input=True,
                            confirmation_prompt=True)
    if len(password) < 12:
        raise click.ClickException("Password must be at least 12 characters.")
    try:
        user = database.reset_owner_password(password)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Password reset for owner account: {user['email']}")


@app.cli.command("reset-account-password")
def reset_account_password_command():
    """Reset an account password locally by email."""
    email = click.prompt("Account email")
    password = click.prompt("New password (minimum 12 characters)", hide_input=True,
                            confirmation_prompt=True)
    if len(password) < 12:
        raise click.ClickException("Password must be at least 12 characters.")
    try:
        user = database.reset_user_password(email, password)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Password reset for account: {user['email']}")


@app.get("/login")
def login_page():
    return render_template("auth.html", mode="login")


@app.get("/recover")
def recovery_page():
    return render_template("recovery.html")


@app.get("/register")
def register_page():
    return render_template("auth.html", mode="register")


@app.get("/api/auth/session")
def auth_session():
    if not g.user:
        return jsonify(authenticated=False)
    if not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify(authenticated=True, user=g.user, csrf_token=session["csrf_token"])


@app.post("/api/auth/login")
@limiter.limit("5 per minute")
def auth_login():
    data = request.get_json(silent=True) or {}
    email, password = data.get("email", ""), data.get("password", "")
    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify(error="Enter a valid email and password."), 400
    user = database.authenticate_user(email, password)
    if not user:
        return jsonify(error="Email or password is incorrect."), 401
    session.clear()
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify(user=user, csrf_token=session["csrf_token"])


@app.post("/api/auth/register")
@limiter.limit("5 per minute")
def auth_register():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")
    invite = data.get("invite", "")
    if not all(isinstance(value, str) for value in (email, password, invite)):
        return jsonify(error="Enter an email, password, and invitation token."), 400
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email.strip()):
        return jsonify(error="Enter a valid email address."), 400
    if len(password) < 12:
        return jsonify(error="Use a password with at least 12 characters."), 400
    try:
        user = database.create_invited_user(email, password, invite)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    session.clear()
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify(user=user, csrf_token=session["csrf_token"]), 201


@app.post("/api/auth/logout")
def auth_logout():
    session.clear()
    return jsonify(ok=True)


@app.post("/api/auth/invites")
@limiter.limit("10 per day")
def auth_invite():
    if g.user["role"] != "owner":
        return jsonify(error="Only the owner can invite users."), 403
    return jsonify(token=database.issue_invite(g.user["id"]), expires_in_days=7)


# ---------------------------------------------------------------- helpers
def field(name, default=""):
    v = request.form.get(name)
    if v is None:
        v = (request.get_json(silent=True) or {}).get(name)
    return default if v is None else v


def _clean_path(p):
    p = posixpath.normpath(p.replace("\\", "/")).lstrip("/")
    return None if p.startswith("..") or "/../" in p or p in (".", "") else p


def _allowed(path):
    parts = path.split("/")
    if any(x in config.SKIP_DIRS for x in parts[:-1]):
        return False
    name = parts[-1].lower()
    ext = posixpath.splitext(name)[1]
    return (ext in config.ALLOWED_EXT or name.startswith("dockerfile") or name.endswith(".dockerfile")
            or name == ".env" or name.startswith(".env."))


def collect_sources(file_list):
    """Read uploads (plain files and .zip archives) into {relative_path: text}. Nothing touches disk."""
    sources, total, skipped = {}, 0, 0

    def add(path, data):
        nonlocal total, skipped
        path = _clean_path(path)
        if not path or not _allowed(path) or len(data) > config.MAX_FILE_BYTES \
                or len(sources) >= config.MAX_FILES or total + len(data) > config.MAX_TOTAL_BYTES:
            skipped += 1
            return
        total += len(data)
        sources[path] = data.decode("utf-8", errors="replace")

    for f in file_list:
        name = f.filename or "file"
        if name.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(f.read())) as z:
                    for info in z.infolist():
                        if info.is_dir() or info.file_size > config.MAX_FILE_BYTES:
                            skipped += info.file_size > config.MAX_FILE_BYTES
                            continue
                        if total + info.file_size > config.MAX_TOTAL_BYTES:
                            skipped += 1
                            continue
                        add(info.filename, z.read(info))
            except zipfile.BadZipFile:
                skipped += 1
        else:
            add(name, f.read())
    return sources, skipped


def _need_sources():
    sources, skipped = collect_sources(request.files.getlist("files"))
    if not sources:
        return None, None, (jsonify(error="No supported files received. Upload .py/.js/.java/.cs, config, "
                                          "Dockerfile, requirements.txt, package.json or a .zip of your project."), 400)
    return sources, skipped, None


def _ensure_ai_embeddings(user_id, kind=None):
    if not ai_service.enabled():
        raise ai_service.AIUnavailable("Local AI is disabled. Configure Ollama and restart DebugLens to enable it.")
    model_name = config.OLLAMA_EMBED_MODEL
    candidates = database.search_candidates(user_id, kind=kind, limit=200)
    existing = database.embedding_rows(user_id, model_name, kind=kind, limit=200)
    existing_ids = {row["id"] for row in existing}
    missing = [candidate for candidate in candidates if candidate["id"] not in existing_ids]
    for offset in range(0, len(missing), 24):
        batch = missing[offset:offset + 24]
        vectors = ai_service.embed_texts([ai_service.analysis_text(item) for item in batch])
        for item, vector in zip(batch, vectors):
            database.save_embedding(user_id, item["id"], model_name, vector)
    return database.embedding_rows(user_id, model_name, kind=kind, limit=200)


def _store_analysis_embedding(user_id, analysis_id, kind, title, summary, result):
    if not ai_service.enabled():
        return
    try:
        item = {"kind": kind, "title": title, "summary": summary, "result": result}
        vector = ai_service.embed_text(ai_service.analysis_text(item))
        database.save_embedding(user_id, analysis_id, config.OLLAMA_EMBED_MODEL, vector)
    except ai_service.AIUnavailable:
        return


# ---------------------------------------------------------------- pages
@app.get("/")
def index():
    if not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_urlsafe(32)
    return render_template("welcome.html", csrf_token=session["csrf_token"], user=g.user)


@app.get("/workspace")
def workspace():
    if not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_urlsafe(32)
    return render_template("index.html", csrf_token=session["csrf_token"])


@app.get("/api/health")
def health():
    return jsonify(status="ok")


@app.get("/api/ai/status")
def api_ai_status():
    return jsonify(ai_service.model_status())


@app.post("/api/ai/search")
@limiter.limit("15 per minute")
def api_ai_search():
    payload = request.get_json(silent=True) or {}
    query = payload.get("query", "")
    kind = payload.get("kind")
    if not isinstance(query, str) or not query.strip():
        return jsonify(error="Enter a phrase to search your analyses."), 400
    if len(query) > 500:
        return jsonify(error="Search text must be 500 characters or fewer."), 400
    if kind not in (None, "error", "code", "security", "logs", "git"):
        return jsonify(error="Unknown analysis type."), 400
    try:
        rows = _ensure_ai_embeddings(g.user["id"], kind=kind)
        query_vector = ai_service.embed_text(query.strip())
    except ai_service.AIUnavailable as exc:
        return jsonify(error=str(exc)), 503
    return jsonify(results=ai_service.rank_vectors(query_vector, rows, limit=10, threshold=0.18))


@app.get("/api/ai/error-clusters")
@limiter.limit("5 per minute")
def api_ai_error_clusters():
    try:
        rows = _ensure_ai_embeddings(g.user["id"], kind="error")
    except ai_service.AIUnavailable as exc:
        return jsonify(error=str(exc)), 503
    return jsonify(clusters=ai_service.cluster_vectors(rows, threshold=0.82))


@app.post("/api/history/<int:aid>/explain")
@limiter.limit("10 per minute")
def api_ai_explain_analysis(aid):
    item = database.get(g.user["id"], aid)
    if not item:
        return jsonify(error="Not found"), 404
    try:
        explanation = ai_service.explain_analysis(item)
    except ai_service.AIUnavailable as exc:
        return jsonify(error=str(exc)), 503
    return jsonify(explanation=explanation, generated_by="local Ollama",
                   disclaimer="AI-generated suggestions can be incorrect. Verify all findings and fixes yourself.")


# ---------------------------------------------------------------- analyses
@app.post("/api/error")
def api_error():
    text = field("text").strip()
    if not text:
        return jsonify(error="Paste an error message or stack trace first."), 400
    sources, _ = collect_sources(request.files.getlist("files"))
    result = error_analyzer.analyze(text, sources)
    norm = similarity.normalize(f"{result['error_type'] or ''} {result['message'] or ''}")
    result["similar"] = similarity.find_similar(norm, database.error_norms(g.user["id"])) if norm else []
    vector = None
    if ai_service.enabled():
        try:
            existing = _ensure_ai_embeddings(g.user["id"], kind="error")
            vector = ai_service.embed_text(ai_service.analysis_text({
                "kind": "error", "title": result["error_type"], "summary": result["message"], "result": result,
            }))
            semantic_matches = ai_service.rank_vectors(vector, existing, limit=3, threshold=0.4)
            if semantic_matches:
                result["similar"] = semantic_matches
        except ai_service.AIUnavailable as exc:
            result["ai_notice"] = str(exc)
    title = f"{result['error_type'] or 'Unknown error'}: {(result['message'] or '')[:80]}"
    result["id"] = database.save(g.user["id"], "error", title, result["explanation"], result,
                                 similarity.fingerprint(norm) if norm else None, norm)
    if vector:
        database.save_embedding(g.user["id"], result["id"], config.OLLAMA_EMBED_MODEL, vector)
    return jsonify(result)


@app.post("/api/code")
def api_code():
    sources, skipped, err = _need_sources()
    if err:
        return err
    result = code_analyzer.analyze(sources)
    result["skipped_files"] = skipped
    s = result["summary"]
    summary = f"{s['lines']} lines, {s['functions']} functions, {s['issues']} issues"
    result["id"] = database.save(g.user["id"], "code", f"Code analysis ({s['files']} files)", summary, result)
    _store_analysis_embedding(g.user["id"], result["id"], "code", f"Code analysis ({s['files']} files)", summary, result)
    return jsonify(result)


@app.post("/api/security")
def api_security():
    sources, skipped, err = _need_sources()
    if err:
        return err
    online = str(field("online")).lower() in ("1", "true", "on", "yes")
    result = security_scanner.scan(sources)
    result["dependencies"] = dependency_checker.analyze(sources, online=online)
    result["skipped_files"], result["files_scanned"] = skipped, len(sources)
    c = result["counts"]
    summary = (f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low; "
               f"{result['dependencies']['vulnerable']} vulnerable dependencies")
    title = f"Security scan ({len(sources)} files)"
    result["id"] = database.save(g.user["id"], "security", title, summary, result)
    _store_analysis_embedding(g.user["id"], result["id"], "security", title, summary, result)
    return jsonify(result)


SAMPLE_PROJECT_FILES = {
    "app.py": "The main Flask app. It reads a user ID, builds a SQL query, evaluates an expression, and starts a development server. Several patterns are intentionally unsafe for the scanner demo.",
    "helpers.py": "A tiny helper that trims text. Its mutable default and bare except show two Python quality issues.",
    "requirements.txt": "Python dependencies. Flask is pinned to an old version, requests is unpinned, and PyYAML allows a broad range.",
    "Dockerfile": "Container build instructions. It uses a floating base image, includes a fake hard-coded token, exposes SSH, and runs the sample app.",
}


def _sample_project_sources():
    sample_root = os.path.join(config.BASE_DIR, "sample_data", "vulnerable_app")
    sources = {}
    total_bytes = 0
    for filename in SAMPLE_PROJECT_FILES:
        path = os.path.join(sample_root, filename)
        if not os.path.isfile(path) or os.path.islink(path):
            continue
        with open(path, "rb") as sample_file:
            content = sample_file.read(config.MAX_FILE_BYTES + 1)
        if len(content) > config.MAX_FILE_BYTES or total_bytes + len(content) > config.MAX_TOTAL_BYTES:
            return {}
        sources[filename] = content.decode("utf-8", errors="replace")
        total_bytes += len(content)
    return sources


@app.get("/api/demo/sample-project/files")
def api_demo_sample_project_files():
    sources = _sample_project_sources()
    if not sources:
        return jsonify(error="The bundled sample project is unavailable."), 503
    return jsonify(
        name="Intentionally vulnerable Flask demo",
        note="Read these files as text. The sample app is never executed.",
        files=[{"name": name, "description": SAMPLE_PROJECT_FILES[name], "content": content}
               for name, content in sources.items()])


@app.post("/api/demo/sample-project")
def api_demo_sample_project():
    sources = _sample_project_sources()
    if not sources:
        return jsonify(error="The bundled sample project is unavailable."), 503

    code = code_analyzer.analyze(sources)
    code["skipped_files"] = 0
    code_summary = code["summary"]
    code_title = "Guided demo: project structure"
    code_summary_text = f"{code_summary['files']} files, {code_summary['issues']} quality issues"
    code_id = database.save(g.user["id"], "code", code_title, code_summary_text, code)
    _store_analysis_embedding(g.user["id"], code_id, "code", code_title, code_summary_text, code)
    code["id"] = code_id

    security = security_scanner.scan(sources)
    security["dependencies"] = dependency_checker.analyze(sources, online=False)
    security["skipped_files"], security["files_scanned"] = 0, len(sources)
    counts = security["counts"]
    security_title = "Guided demo: security review"
    security_summary = (f"{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
                        f"{counts['low']} low; {security['dependencies']['vulnerable']} vulnerable dependencies")
    security_id = database.save(g.user["id"], "security", security_title, security_summary, security)
    _store_analysis_embedding(g.user["id"], security_id, "security", security_title, security_summary, security)
    security["id"] = security_id
    return jsonify(code=code, security=security)


@app.post("/api/logs")
def api_logs():
    text = field("text")
    for f in request.files.getlist("files")[:1]:
        text = f.read().decode("utf-8", errors="replace")
    if not text.strip():
        return jsonify(error="Paste log text or upload a log file."), 400
    result = log_analyzer.analyze(text)
    title = f"Log analysis ({result['total_lines']} lines)"
    summary = f"{result['error_total']} errors in {result['distinct_errors']} patterns"
    result["id"] = database.save(g.user["id"], "logs", title, summary, result)
    _store_analysis_embedding(g.user["id"], result["id"], "logs", title, summary, result)
    return jsonify(result)


@app.post("/api/git")
@limiter.limit("5 per minute")
def api_git():
    repo_path = field("repo_path").strip()
    repo_url = field("repo_url").strip()
    if not repo_url and re.match(r"^https?://github\.com/", repo_path, re.IGNORECASE):
        repo_url, repo_path = repo_path, ""
    if repo_path and repo_url:
        return jsonify(error="Enter either a local repository folder or a public GitHub URL, not both."), 400
    if not repo_path and not repo_url:
        return jsonify(error="Enter a local repository folder or a public GitHub repository URL."), 400
    try:
        analyze = git_analyzer.analyze_github if repo_url else git_analyzer.analyze
        result = analyze(repo_url or repo_path, field("error_text"), field("base"), field("head", "HEAD"))
    except git_analyzer.GitError as e:
        return jsonify(error=str(e)), 400
    repo_label = result.get("source") and result["repo"].removesuffix(".git").rsplit("/", 1)[-1] or \
        result["repo"].split(chr(92))[-1].split("/")[-1]
    title = f"Git analysis: {repo_label}"
    summary = f"{len(result['commits'])} commits, {len(result['suspects'])} suspect(s)"
    result["id"] = database.save(g.user["id"], "git", title, summary, result)
    _store_analysis_embedding(g.user["id"], result["id"], "git", title, summary, result)
    return jsonify(result)


# ---------------------------------------------------------------- history
@app.get("/api/history")
def api_history():
    user_id = g.user["id"]
    return jsonify(items=database.list_all(user_id, request.args.get("kind")), recurring=database.recurring(user_id))


@app.get("/api/history/<int:aid>")
def api_history_item(aid):
    item = database.get(g.user["id"], aid)
    return (jsonify(item), 200) if item else (jsonify(error="Not found"), 404)


def _report_payload(item):
    return {key: item[key] for key in ("id", "kind", "title", "summary", "created_at", "result")}


@app.get("/api/history/<int:aid>/export.json")
def api_history_export_json(aid):
    item = database.get(g.user["id"], aid)
    if not item:
        return jsonify(error="Not found"), 404
    response = Response(json.dumps(_report_payload(item), indent=2), mimetype="application/json")
    response.headers["Content-Disposition"] = f"attachment; filename=debuglens-report-{aid}.json"
    return response


@app.get("/api/history/<int:aid>/export.pdf")
def api_history_export_pdf(aid):
    item = database.get(g.user["id"], aid)
    if not item:
        return jsonify(error="Not found"), 404
    payload = _report_payload(item)
    report_json = json.dumps(payload, indent=2)
    buffer = io.BytesIO()
    styles = getSampleStyleSheet()
    code_style = styles["Code"]
    code_style.fontSize = 7
    code_style.leading = 9
    doc = SimpleDocTemplate(buffer, pagesize=letter, title=item["title"][:200])
    doc.build([
        Paragraph(escape(item["title"]), styles["Title"]),
        Paragraph(f"{escape(item['kind'])} analysis | {escape(item['created_at'])}", styles["Normal"]),
        Spacer(1, 14),
        Preformatted(escape(report_json), code_style, maxLineLength=105),
    ])
    response = Response(buffer.getvalue(), mimetype="application/pdf")
    response.headers["Content-Disposition"] = f"attachment; filename=debuglens-report-{aid}.pdf"
    return response


@app.delete("/api/history/<int:aid>")
def api_history_delete(aid):
    database.delete(g.user["id"], aid)
    return jsonify(ok=True)


@app.get("/api/stats")
def api_stats():
    user_id = g.user["id"]
    return jsonify(counts=database.counts(user_id), recent=database.list_all(user_id, limit=6),
                   recurring=database.recurring(user_id))


if __name__ == "__main__":
    # debug=False on purpose: the Werkzeug debugger allows code execution.
    app.run(host="127.0.0.1", port=5000, debug=False)
