"""Code structure + quality analysis.
Python: full AST analysis. JS/TS, Java, C#: lightweight regex extraction (clearly labelled 'basic')."""
import ast
import hashlib
import posixpath
import re

LANG = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
        ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".cs": "csharp"}

RX = {
    "javascript": dict(imp=[r'import\s+[^;]*?from\s+[\'"]([^\'"]+)[\'"]', r'require\(\s*[\'"]([^\'"]+)[\'"]\s*\)'],
                       cls=r'\bclass\s+(\w+)',
                       fn=r'\bfunction\s*\*?\s*(\w+)|\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>'),
    "java": dict(imp=[r'^\s*import\s+([\w.*]+);'], cls=r'\b(?:class|interface|enum|record)\s+(\w+)',
                 fn=r'\b(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?[\w<>\[\],?]+\s+(\w+)\s*\('),
    "csharp": dict(imp=[r'^\s*using\s+([\w.]+);'], cls=r'\b(?:class|struct|interface|record|enum)\s+(\w+)',
                   fn=r'\b(?:public|private|protected|internal)\s+(?:static\s+)?(?:async\s+)?(?:virtual\s+|override\s+)?[\w<>\[\],?]+\s+(\w+)\s*\('),
}
RX["typescript"] = RX["javascript"]


def _ext(path):
    return posixpath.splitext(path)[1].lower()


def _complexity(node):
    c = 1
    for n in ast.walk(node):
        if isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.comprehension)):
            c += 1
        elif isinstance(n, ast.BoolOp):
            c += len(n.values) - 1
    return c


def _analyze_python(path, src, issues):
    info = {"path": path, "language": "python", "mode": "full (AST)", "lines": src.count("\n") + 1,
            "functions": [], "classes": [], "imports": []}
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        issues.append({"file": path, "line": e.lineno or 1, "severity": "high", "type": "syntax-error",
                       "message": f"File cannot be parsed: {e.msg}"})
        return info

    imported = {}  # local name -> (module, lineno)
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                info["imports"].append(a.name)
                imported[(a.asname or a.name).split(".")[0]] = (a.name, n.lineno)
        elif isinstance(n, ast.ImportFrom):
            mod = ("." * n.level) + (n.module or "")
            info["imports"].append(mod)
            for a in n.names:
                if a.name != "*" and n.module != "__future__":
                    imported[a.asname or a.name] = (mod, n.lineno)

    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    exported = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in n.targets):
            exported |= {e.value for e in getattr(n.value, "elts", []) if isinstance(e, ast.Constant)}
    if not path.endswith("__init__.py"):
        for name, (mod, line) in imported.items():
            if name not in used and name not in exported:
                issues.append({"file": path, "line": line, "severity": "low", "type": "unused-import",
                               "message": f"'{name}' imported from '{mod}' but never used"})

    bodies = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(n, "end_lineno", n.lineno)
            cx, length = _complexity(n), end - n.lineno + 1
            info["functions"].append({"name": n.name, "line": n.lineno, "end": end, "complexity": cx,
                                      "params": len(n.args.args)})
            if cx > 10:
                issues.append({"file": path, "line": n.lineno, "severity": "medium", "type": "high-complexity",
                               "message": f"'{n.name}' has cyclomatic complexity {cx} (>10); consider splitting it"})
            if length > 50:
                issues.append({"file": path, "line": n.lineno, "severity": "low", "type": "long-function",
                               "message": f"'{n.name}' is {length} lines long"})
            if len(n.args.args) > 6:
                issues.append({"file": path, "line": n.lineno, "severity": "low", "type": "many-parameters",
                               "message": f"'{n.name}' takes {len(n.args.args)} parameters"})
            for d in n.args.defaults + [x for x in n.args.kw_defaults if x]:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                    issues.append({"file": path, "line": n.lineno, "severity": "medium", "type": "mutable-default",
                                   "message": f"'{n.name}' uses a mutable default argument (shared between calls)"})
            body = n.body[1:] if n.body and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], "value", None), ast.Constant) else n.body
            if len(body) >= 3:
                h = hashlib.md5(ast.dump(ast.Module(body=body, type_ignores=[])).encode()).hexdigest()
                bodies.setdefault(h, []).append(n)
        elif isinstance(n, ast.ClassDef):
            info["classes"].append({"name": n.name, "line": n.lineno,
                                    "methods": [m.name for m in n.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]})
        elif isinstance(n, ast.ExceptHandler) and n.type is None:
            issues.append({"file": path, "line": n.lineno, "severity": "medium", "type": "bare-except",
                           "message": "Bare 'except:' hides real errors (also catches KeyboardInterrupt)"})
    for group in bodies.values():
        if len(group) > 1:
            names = ", ".join(f"{g.name} (line {g.lineno})" for g in group)
            issues.append({"file": path, "line": group[0].lineno, "severity": "low", "type": "duplicated-logic",
                           "message": f"Identical function bodies: {names}"})
    return info


def _analyze_generic(path, src, lang, issues):
    rx = RX[lang]
    info = {"path": path, "language": lang, "mode": "basic (regex)", "lines": src.count("\n") + 1,
            "functions": [], "classes": [], "imports": []}
    for pat in rx["imp"]:
        info["imports"] += [m.group(1) for m in re.finditer(pat, src, re.M)]
    for m in re.finditer(rx["cls"], src):
        info["classes"].append({"name": m.group(1), "line": src.count("\n", 0, m.start()) + 1, "methods": []})
    seen = set()
    for m in re.finditer(rx["fn"], src, re.M):
        name = next((g for g in m.groups() if g), None)
        if name and name not in ("if", "for", "while", "switch", "catch") and (name, m.start()) not in seen:
            seen.add((name, m.start()))
            info["functions"].append({"name": name, "line": src.count("\n", 0, m.start()) + 1,
                                      "end": None, "complexity": None, "params": None})
    if lang in ("javascript", "typescript"):
        for m in re.finditer(r'\b(var)\s+\w+', src):
            issues.append({"file": path, "line": src.count("\n", 0, m.start()) + 1, "severity": "low",
                           "type": "var-usage", "message": "'var' is function-scoped; prefer let/const"})
            break
        for m in re.finditer(r'[^=!]==[^=]', src):
            issues.append({"file": path, "line": src.count("\n", 0, m.start()) + 1, "severity": "low",
                           "type": "loose-equality", "message": "'==' performs type coercion; prefer '==='"})
            break
    return info


def _resolve(imp, from_path, py_index, paths):
    """Map an import string to a project file, or None if external."""
    if imp.startswith("."):
        if not imp.startswith("./") and not imp.startswith("../") and from_path.endswith(".py"):
            base = posixpath.dirname(from_path)
            dots = len(imp) - len(imp.lstrip("."))
            for _ in range(dots - 1):
                base = posixpath.dirname(base)
            rel = imp.lstrip(".").replace(".", "/")
            for cand in (posixpath.join(base, rel + ".py"), posixpath.join(base, rel, "__init__.py")):
                if cand in paths:
                    return cand
            return None
        target = posixpath.normpath(posixpath.join(posixpath.dirname(from_path), imp))
        for suffix in ("", ".js", ".jsx", ".ts", ".tsx", ".mjs", "/index.js", "/index.ts"):
            if target + suffix in paths:
                return target + suffix
        return None
    if from_path.endswith(".py"):
        parts = imp.split(".")
        for i in range(len(parts), 0, -1):
            key = "/".join(parts[:i])
            for cand in (key + ".py", key + "/__init__.py"):
                for p in py_index.get(cand, []):
                    return p
    return None


def analyze(sources):
    issues, files = [], []
    for path, src in sorted(sources.items()):
        lang = LANG.get(_ext(path))
        if not lang:
            continue
        files.append(_analyze_python(path, src, issues) if lang == "python" else _analyze_generic(path, src, lang, issues))

    paths = {f["path"] for f in files}
    py_index = {}
    for p in paths:
        if p.endswith(".py"):
            parts = p.split("/")
            for i in range(len(parts)):  # allow projects uploaded with a wrapper folder
                py_index.setdefault("/".join(parts[i:]), []).append(p)

    edges, external = set(), {}
    for f in files:
        for imp in f["imports"]:
            tgt = _resolve(imp, f["path"], py_index, paths)
            if tgt and tgt != f["path"]:
                edges.add((f["path"], tgt))
            elif not tgt and not imp.startswith("."):
                external.setdefault(imp.split(".")[0].split("/")[0], set()).add(f["path"])

    sev = {"high": 0, "medium": 1, "low": 2}
    issues.sort(key=lambda i: (sev.get(i["severity"], 3), i["file"], i["line"]))
    return {
        "summary": {"files": len(files), "lines": sum(f["lines"] for f in files),
                    "functions": sum(len(f["functions"]) for f in files),
                    "classes": sum(len(f["classes"]) for f in files), "issues": len(issues)},
        "files": files,
        "graph": {"nodes": [{"id": f["path"], "label": f["path"].split("/")[-1]} for f in files],
                  "edges": [{"source": a, "target": b} for a, b in sorted(edges)]},
        "external_imports": {k: sorted(v) for k, v in sorted(external.items())},
        "issues": issues,
        "note": "Python is analysed with a real AST parser; other languages use basic pattern matching and may miss constructs.",
    }
