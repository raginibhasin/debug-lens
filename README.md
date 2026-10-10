# DebugLens (Phase 1-3 build)

Run on Windows: double-click `run.bat`, or in the VS Code terminal:

    py -m venv .venv
    .venv\Scripts\Activate.ps1      (PowerShell)   |   .venv\Scripts\activate.bat (cmd)
    pip install -r requirements.txt
    python app.py

Open http://127.0.0.1:5000. After sign-in, `/` is a short welcome page and
`/workspace` contains the analysis tools. Use **Browse sample project** in the
workspace to inspect the bundled `sample_data/vulnerable_app` files one by one,
read a plain-language description of each, then choose **Analyze sample**.
DebugLens reads those files as text, runs the code and security analyzers, and
saves the results in your account. The sample is intentionally vulnerable and
is never executed.

Create the first owner account once, from the project folder:

    python -m flask --app app create-owner

If you forget the owner password, recover it locally with:

    python -m flask --app app reset-owner-password

To reset any account from the local machine, use `python -m flask --app app
reset-account-password` and enter the account email when prompted. Email-based
password resets are not enabled because no mail delivery service is configured.

The owner can issue seven-day, single-use invitations from the dashboard. Invite
tokens are shown once; send them to teammates through a trusted channel. Passwords
are hashed, sessions are HTTP-only and SameSite=Lax, and analysis history is
isolated per account. Existing history is assigned to the first owner at setup.

For a persistent deployment, set `DEBUGLENS_SECRET_KEY` through the platform's
secret manager and enable `DEBUGLENS_COOKIE_SECURE=true` behind HTTPS. The default
rate-limit store is in-memory for local use; multi-worker deployments should set
`DEBUGLENS_RATELIMIT_STORAGE_URI` to a shared Redis URL. Do not expose the app
publicly until these settings and a production WSGI server are configured.

Git analysis is restricted to the project folder by default. To allow other
repository locations, set `DEBUGLENS_GIT_ALLOWED_ROOTS` to a list of folders
separated by the platform path separator (semicolon on Windows, colon on Linux/macOS)
before starting the app. Treat this as an explicit local access grant.

Git & Change Analysis accepts local folders and public HTTPS GitHub repository
URLs. Public links are cloned shallowly (up to 20 commits) into temporary storage;
submodules are not fetched and repository code is never executed. Private GitHub
repositories are not supported by this unauthenticated fetch path; use a local
clone inside an allowed folder until GitHub App access is configured.
GitHub results also include a bounded file list with short, heuristic purpose
notes based on common filenames, paths, and source declarations. Treat these as
orientation; inspect each file before relying on a description.

### Optional local AI

AI features are off by default and do not use a hosted provider. Install Ollama
locally, then pull the default embedding and chat models:

    ollama pull nomic-embed-text
    ollama pull qwen2.5:3b

In PowerShell, enable the features before starting DebugLens:

    $env:DEBUGLENS_AI_ENABLED = "true"
    $env:DEBUGLENS_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
    $env:DEBUGLENS_OLLAMA_EMBED_MODEL = "nomic-embed-text"
    $env:DEBUGLENS_OLLAMA_CHAT_MODEL = "qwen2.5:3b"
    python app.py

Then use **History** for meaning-based search and recurring error groups, or
open a saved analysis and choose **Explain locally**. Existing analyses are
embedded lazily, with a per-request backfill limit. The model receives bounded
analysis summaries rather than full source files; simple secret redaction is
best-effort, so do not treat it as a substitute for reviewing sensitive data.
All vectors remain in the per-user SQLite database. Explanations separate
reported facts from hypotheses, and suggested checks are not guaranteed fixes.

For Docker Compose, set `DEBUGLENS_AI_ENABLED=true` and use
`http://host.docker.internal:11434` as the Ollama URL. Ensure the host Ollama
service is reachable from Docker before enabling it. AI remains optional; all
existing rule-based analysis works when it is off or Ollama is unavailable.

Run the focused test suite with `pip install -r requirements-dev.txt` and
`python -m pytest`.

### Docker self-hosting

Docker Compose binds the web app to localhost, runs it as a non-root user,
persists SQLite under a named volume, keeps Redis private for shared rate limits,
and mounts the selected Git folder read-only. In PowerShell, set the deployment
values before starting:

    $env:DEBUGLENS_SECRET_KEY = (python -c "import secrets; print(secrets.token_urlsafe(48))")
    $env:DEBUGLENS_GIT_ROOT = "C:/path/to/a/repository-folder"
    docker compose up --build -d
    docker compose exec web flask --app app create-owner

Open http://127.0.0.1:8000. Keep the bind address local unless the service is
placed behind HTTPS and configured with secure cookies. Back up the
`debuglens-data` volume; it contains account and analysis data.

Modules: analyzers/error_analyzer.py, code_analyzer.py, security_scanner.py, dependency_checker.py,
git_analyzer.py, log_analyzer.py, similarity.py. History is stored in debuglens.db (SQLite).
Try the files in sample_data/ (vulnerable_app/ can be zipped and uploaded to Code and Security tabs).
