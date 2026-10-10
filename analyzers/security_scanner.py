"""Rule-based defensive security scanner for source, config, Docker and IaC files.
Findings are *indicators* to review - not confirmed vulnerabilities."""
import posixpath
import re

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
PLACEHOLDER = re.compile(r"(?i)changeme|example|your[_-]|<.+>|\$\{|xxx|dummy|placeholder|os\.environ|getenv|process\.env|\*\*\*")


def R(rid, title, sev, pattern, tags, why, fix, conf="possible", mask=False, flags=0):
    return dict(id=rid, title=title, severity=sev, rx=re.compile(pattern, flags), tags=set(tags.split()),
                why=why, fix=fix, conf=conf, mask=mask)


CODE = "py js java cs"
RULES = [
    R("SEC001", "Possible hard-coded credential", "high",
      r"""(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["'][^"'\s]{6,}["']""",
      "any", "Secrets committed to source control can be read by anyone with repository access and are hard to rotate.",
      "Load secrets from environment variables or a secret manager and rotate the exposed value.", "likely", True),
    R("SEC002", "AWS access key ID pattern", "critical", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "any",
      "Matches the format of an AWS access key ID.", "Revoke the key in IAM, create a new one and store it outside the code.", "likely", True),
    R("SEC003", "Private key material in file", "critical", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "any",
      "Private keys must never be stored in a repository.", "Remove the key, rotate it and add the file to .gitignore.", "likely", True),
    R("SEC010", "SQL built with string formatting/concatenation", "high",
      r"""(?i)\.execute\w*\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\+|\.format))""", "py",
      "Building SQL from variables allows SQL injection when any value is user-controlled.",
      "Use parameterised queries: cursor.execute('... WHERE id = ?', (value,))."),
    R("SEC011", "SQL string assembled with variables", "high",
      r"""(?i)\bf["'](?:select|insert|update|delete)\b[^"']*\{|["'](?:select|insert|update|delete)\b[^"']*["']\s*\+\s*\w""", "py js java cs",
      "Query text appears to include variable data directly.", "Use prepared statements / parameter binding."),
    R("SEC020", "Dynamic code execution (eval/exec)", "high", r"\b(?:eval|exec)\s*\(", "py js",
      "Executing dynamic strings can run attacker-supplied code.", "Avoid eval/exec; use ast.literal_eval or JSON parsing."),
    R("SEC021", "Shell command execution", "high", r"shell\s*=\s*True|\bos\.system\(|\bRuntime\.getRuntime\(\)\.exec\(|child_process", "py java js",
      "Shell invocation with untrusted input enables command injection.", "Pass an argument list without a shell and validate input."),
    R("SEC022", "Unsafe deserialisation", "high", r"\bpickle\.loads?\(|\bmarshal\.loads?\(|\byaml\.load\((?![^)]*Loader)|ObjectInputStream", "py java",
      "Deserialising untrusted data can execute code.", "Use json or yaml.safe_load; never unpickle untrusted data."),
    R("SEC030", "Debug mode enabled", "medium", r"app\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True", "py config",
      "Debug servers expose stack traces and may allow code execution.", "Disable debug in production via configuration."),
    R("SEC031", "TLS certificate verification disabled", "high", r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify|ServerCertificateValidationCallback", "py js java cs",
      "Disabling verification allows man-in-the-middle attacks.", "Remove the override and trust the proper CA bundle."),
    R("SEC032", "Weak hash algorithm", "medium", r"hashlib\.(?:md5|sha1)\(|MessageDigest\.getInstance\(\"(?:MD5|SHA-?1)\"\)|MD5\.Create\(|SHA1\.Create\(", "py java cs",
      "MD5/SHA-1 are broken for security purposes (passwords, signatures).", "Use SHA-256+ for integrity and bcrypt/argon2 for passwords."),
    R("SEC033", "Potential DOM XSS sink", "medium", r"\.innerHTML\s*=|document\.write\(|dangerouslySetInnerHTML", "js",
      "Writing untrusted data into HTML can execute scripts in the user's browser.", "Use textContent or sanitise with a vetted library."),
    R("SEC034", "File upload saved without sanitising filename", "medium", r"\.save\([^)]*\.filename(?![^)]*secure_filename)", "py",
      "Client-supplied filenames can contain path traversal sequences.", "Use werkzeug.utils.secure_filename, check extensions and size."),
    R("SEC035", "Permissive CORS configuration", "low", r"Access-Control-Allow-Origin.{0,20}\*|\bCORS\(app\)|origins\s*=\s*[\"']\*[\"']", "py js java cs",
      "Allowing every origin may expose authenticated APIs to other sites.", "Restrict to known origins."),
    R("SEC036", "Service bound to all interfaces", "low", r"host\s*=\s*[\"']0\.0\.0\.0[\"']", "py",
      "Binding to 0.0.0.0 exposes the service to the network.", "Bind to 127.0.0.1 unless remote access is intended."),
    R("SEC037", "Hard-coded 'secret key' value", "high", r"""(?i)SECRET_KEY\s*=\s*["'][^"']{3,}["']""", "py config",
      "A fixed signing key lets attackers forge sessions/tokens if the source leaks.", "Read it from the environment.", "likely", True),
    # Docker
    R("DOC001", "Container runs as root", "medium", r"(?im)^\s*USER\s+(?:root|0)\s*$", "docker", "Root inside a container increases the impact of an escape.", "Create and switch to an unprivileged USER."),
    R("DOC002", "Unpinned base image tag", "low", r"(?im)^\s*FROM\s+(?:--\S+\s+)?[^\s:@]+(?::latest)?\s*(?:AS\s+\w+)?\s*$", "docker", "Untagged/latest images make builds non-reproducible and may pull vulnerable versions.", "Pin a specific version or digest."),
    R("DOC003", "ADD from remote URL", "medium", r"(?im)^\s*ADD\s+https?://", "docker", "Remote content is fetched without verification.", "Use curl with checksum verification, or COPY."),
    R("DOC004", "Secret in ENV/ARG", "high", r"(?im)^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY)\w*[= ]\s*\S+", "docker", "Values end up in image layers and metadata.", "Use build secrets or runtime injection.", "likely", True),
    R("DOC005", "Remote-access port exposed", "medium", r"(?im)^\s*EXPOSE\s+(?:22|23|3389)\b", "docker", "SSH/Telnet/RDP in a container is rarely needed.", "Remove the port; use `docker exec`."),
    R("DOC006", "Pipe-to-shell download", "medium", r"(?i)(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh", "docker", "Executes unverified remote code during build.", "Download, verify checksum, then run."),
    R("DOC010", "Privileged container", "high", r"(?i)privileged:\s*true", "compose", "Privileged mode gives near-host access.", "Remove it; grant only the specific capabilities needed."),
    R("DOC011", "Docker socket mounted", "high", r"/var/run/docker\.sock", "compose", "Access to the socket equals root on the host.", "Avoid mounting it or use a socket proxy."),
    R("DOC012", "Host network mode", "medium", r"(?i)network_mode:\s*[\"']?host", "compose", "Bypasses network isolation.", "Use bridge networks with explicit ports."),
    R("DOC013", "Port published on all interfaces / DB exposed", "low", r"""(?i)-\s*["']?(?:0\.0\.0\.0:)?(?:3306|5432|27017|6379|9200):\d+""", "compose", "Databases/caches exposed to the network are frequent attack targets.", "Bind to 127.0.0.1 or remove the mapping."),
    R("DOC014", "Secret value in compose environment", "high", r"""(?i)\b\w*(?:PASSWORD|SECRET|TOKEN)\w*\s*[:=]\s*["']?[^\s"'$]{4,}""", "compose", "Plain-text secrets in compose files get committed.", "Use env_file excluded from git, or Docker secrets.", "possible", True),
    # Cloud / IaC
    R("AWS001", "Wildcard principal", "high", r"""(?i)"Principal"\s*:\s*(?:"\*"|\{\s*"AWS"\s*:\s*"\*"\s*\})""", "iac", "Allows anyone to assume the policy's access.", "Restrict to specific accounts/roles."),
    R("AWS002", "Wildcard action", "high", r"""(?i)"Action"\s*:\s*"\*\"|\bactions\s*=\s*\[\s*"\*"\s*\]""", "iac", "Grants every action; violates least privilege.", "List only the required actions."),
    R("AWS003", "Open to the whole internet (0.0.0.0/0)", "medium", r"0\.0\.0\.0/0|::/0", "iac", "Any host on the internet can reach this resource.", "Limit CIDR ranges; avoid for SSH/DB ports."),
    R("AWS004", "Public storage ACL", "high", r"public-read(?:-write)?|(?i:block_public_acls\s*=\s*false|block_public_policy\s*=\s*false)", "iac", "Bucket content may be world-readable.", "Enable Block Public Access."),
    R("AWS005", "Encryption disabled", "medium", r"(?i)\bencrypted\s*=\s*false|\"Encrypted\"\s*:\s*false", "iac", "Data at rest is not encrypted.", "Enable encryption with KMS."),
]


def _tags(path):
    name = posixpath.basename(path).lower()
    ext = posixpath.splitext(name)[1]
    tags = {"any"}
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        tags.add("docker")
    if re.match(r"(docker-)?compose.*\.ya?ml$", name):
        tags |= {"compose", "config"}
    tags |= {".py": {"py"}, ".js": {"js"}, ".jsx": {"js"}, ".ts": {"js"}, ".tsx": {"js"}, ".mjs": {"js"},
             ".java": {"java"}, ".cs": {"cs"}, ".json": {"iac", "config"}, ".yml": {"iac", "config"},
             ".yaml": {"iac", "config"}, ".tf": {"iac"}, ".ini": {"config"}, ".cfg": {"config"},
             ".toml": {"config"}, ".conf": {"config"}, ".properties": {"config"}}.get(ext, set())
    if name == ".env" or name.startswith(".env."):
        tags.add("config")
    return tags


def _mask(line):
    line = re.sub(r"""(["'])[^"'\n]{4,}\1""", lambda m: m.group(1) + "****" + m.group(1), line)
    line = re.sub(r"(?i)((?:ENV|ARG)\s+\w+[= ])\S+", r"\1****", line)
    line = re.sub(r"(?i)(\w*(?:password|secret|token)\w*\s*[:=]\s*)[^\s\"']+", r"\1****", line)
    return re.sub(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", r"\1****************", line)


def scan(sources):
    findings = []
    for path, src in sorted(sources.items()):
        tags = _tags(path)
        name = posixpath.basename(path).lower()
        lines = src.split("\n")
        if name == ".env" or name.startswith(".env."):
            findings.append(dict(rule="ENV001", severity="medium", confidence="likely", title=".env file included in the project",
                                 file=path, line=1, evidence=name,
                                 explanation=".env files usually hold secrets and should not be committed or shared.",
                                 remediation="Add it to .gitignore and provide a .env.example instead."))
        if "docker" in tags and name.startswith("dockerfile") and not re.search(r"(?im)^\s*USER\s+", src) and "FROM" in src.upper():
            findings.append(dict(rule="DOC000", severity="medium", confidence="likely", title="Dockerfile never sets a non-root USER",
                                 file=path, line=1, evidence="(no USER instruction)",
                                 explanation="The container will run as root by default.",
                                 remediation="Add a USER instruction after installing dependencies."))
        for rule in RULES:
            if not (rule["tags"] & tags):
                continue
            for i, line in enumerate(lines, 1):
                m = rule["rx"].search(line)
                if not m:
                    continue
                if rule["id"] in ("SEC001", "SEC037", "DOC014", "DOC004") and PLACEHOLDER.search(line):
                    continue
                findings.append(dict(rule=rule["id"], severity=rule["severity"], confidence=rule["conf"],
                                     title=rule["title"], file=path, line=i,
                                     evidence=(_mask(line) if rule["mask"] else line).strip()[:200],
                                     explanation=rule["why"], remediation=rule["fix"]))
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["file"], f["line"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    return {"counts": counts, "findings": findings,
            "note": "Findings are pattern-based indicators for defensive review. Each needs human confirmation; "
                    "'likely' means the pattern is specific, 'possible' means context decides."}
