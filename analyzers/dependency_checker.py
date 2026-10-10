"""Dependency review: pinning hygiene + known-vulnerable versions.
Offline: small bundled advisory list (extend ADVISORIES). Optional online: OSV.dev API."""
import json
import posixpath
import re
import urllib.request

# (id, fixed_in, summary) - a small bundled sample, NOT a complete database.
ADVISORIES = {
    "PyPI": {
        "requests": [("CVE-2023-32681", "2.31.0", "Proxy-Authorization header leaked on redirect")],
        "pyyaml": [("CVE-2020-14343", "5.4", "Arbitrary code execution via full_load")],
        "jinja2": [("CVE-2024-22195", "3.1.3", "XSS via xmlattr filter")],
        "urllib3": [("CVE-2023-45803", "1.26.18", "Request body not stripped on redirect")],
        "flask": [("CVE-2023-30861", "2.2.5", "Session cookie may be cached by proxies")],
        "werkzeug": [("CVE-2024-34069", "3.0.3", "Debugger code execution risk")],
        "pillow": [("CVE-2023-4863", "10.0.1", "libwebp heap buffer overflow")],
    },
    "npm": {
        "lodash": [("CVE-2021-23337", "4.17.21", "Command injection via template")],
        "minimist": [("CVE-2021-44906", "1.2.6", "Prototype pollution")],
        "express": [("CVE-2024-29041", "4.19.2", "Open redirect")],
    },
}


def _vt(v):
    nums = [int(x) for x in re.findall(r"\d+", v or "")[:4]]
    return tuple(nums + [0] * (4 - len(nums)))


def _parse_requirements(path, src):
    out = []
    for raw in src.split("\n"):
        line = raw.split("#")[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(?:(==|>=|<=|~=|!=|>|<)\s*([\w.\-*]+))?", line)
        if m:
            out.append({"file": path, "ecosystem": "PyPI", "name": m.group(1).lower().replace("_", "-"),
                        "operator": m.group(2), "version": m.group(3), "spec": line})
    return out


def _parse_package_json(path, src):
    out = []
    try:
        data = json.loads(src)
    except ValueError:
        return out
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            m = re.match(r"^([\^~<>=]*)\s*(\d[\w.\-]*)", str(spec))
            out.append({"file": path, "ecosystem": "npm", "name": name.lower(), "operator": (m.group(1) or "==") if m else None,
                        "version": m.group(2) if m else None, "spec": f"{name}@{spec}", "dev": section == "devDependencies"})
    return out


def _osv(eco, name, version):
    body = json.dumps({"package": {"name": name, "ecosystem": eco}, "version": version}).encode()
    req = urllib.request.Request("https://api.osv.dev/v1/query", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        vulns = json.loads(r.read()).get("vulns", [])
    return [(v["id"], None, (v.get("summary") or "")[:140]) for v in vulns[:5]]


def analyze(sources, online=False):
    deps = []
    for path, src in sources.items():
        base = posixpath.basename(path).lower()
        if re.match(r"requirements.*\.txt$", base):
            deps += _parse_requirements(path, src)
        elif base == "package.json":
            deps += _parse_package_json(path, src)

    online_errors, queried = [], 0
    for d in deps:
        flags, advisories = [], []
        op, ver = d["operator"], d["version"]
        if not ver:
            flags.append("No version constraint - any version may be installed")
        elif op not in ("==", "===") and d["ecosystem"] == "PyPI":
            flags.append("Version range, not pinned - builds are not reproducible")
        elif d["ecosystem"] == "npm" and op in ("^", "~", ">", ">="):
            flags.append("Version range - resolved version may differ from the declared base")
        exact = ver is not None and op in ("==", "===", None, "")
        for adv_id, fixed, summary in ADVISORIES.get(d["ecosystem"], {}).get(d["name"], []):
            if ver and _vt(ver) < _vt(fixed):
                advisories.append({"id": adv_id, "fixed_in": fixed, "summary": summary, "source": "bundled",
                                   "certainty": "affected" if exact else "possible (range allows older versions)"})
        if online and ver and queried < 30:
            queried += 1
            try:
                for adv_id, _, summary in _osv(d["ecosystem"], d["name"], ver):
                    if all(a["id"] != adv_id for a in advisories):
                        advisories.append({"id": adv_id, "fixed_in": None, "summary": summary, "source": "OSV.dev",
                                           "certainty": "affected" if exact else "possible (range allows older versions)"})
            except Exception as e:  # network off, rate limit, ...
                online_errors.append(str(e)[:80])
                online = False
        d["flags"], d["advisories"] = flags, advisories
        d["status"] = "vulnerable" if advisories else ("review" if flags else "ok")

    return {"count": len(deps), "dependencies": deps,
            "vulnerable": sum(1 for d in deps if d["advisories"]),
            "online_checked": queried if not online_errors else 0,
            "online_error": online_errors[0] if online_errors else None,
            "note": "The bundled advisory list is a small sample; enable the online OSV check for broader coverage."}
