import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DEBUGLENS_DB_PATH", os.path.join(BASE_DIR, "debuglens.db"))
SECRET_KEY = os.environ.get("DEBUGLENS_SECRET_KEY")
RATELIMIT_STORAGE_URI = os.environ.get("DEBUGLENS_RATELIMIT_STORAGE_URI", "memory://")
AI_ENABLED = os.environ.get("DEBUGLENS_AI_ENABLED", "false").lower() in ("1", "true", "yes", "on")
OLLAMA_BASE_URL = os.environ.get("DEBUGLENS_OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_EMBED_MODEL = os.environ.get("DEBUGLENS_OLLAMA_EMBED_MODEL", "nomic-embed-text")
OLLAMA_CHAT_MODEL = os.environ.get("DEBUGLENS_OLLAMA_CHAT_MODEL", "qwen2.5:3b")
AI_REQUEST_TIMEOUT = int(os.environ.get("DEBUGLENS_AI_REQUEST_TIMEOUT", "45"))
GIT_ALLOWED_ROOTS = [
    os.path.realpath(path.strip())
    for path in os.environ.get("DEBUGLENS_GIT_ALLOWED_ROOTS", BASE_DIR).split(os.pathsep)
    if path.strip()
]

MAX_UPLOAD_MB = 20            # per request
MAX_FILES = 500               # files analysed per request
MAX_FILE_BYTES = 1_000_000    # per file
MAX_TOTAL_BYTES = 30_000_000  # total uncompressed (zip-bomb guard)

ALLOWED_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".java", ".cs",
    ".json", ".yml", ".yaml", ".tf", ".txt", ".ini", ".cfg", ".toml",
    ".conf", ".properties", ".env",
}
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "bin", "obj",
             "dist", "build", ".idea", ".vscode", "site-packages"}
