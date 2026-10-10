"""Lightweight error normalisation + similarity (token Jaccard + difflib).
Pure standard library; can later be swapped for embeddings."""
import difflib
import hashlib
import re


def normalize(text):
    t = (text or "").lower()
    t = re.sub(r"'[^']*'|\"[^\"]*\"", "<str>", t)
    t = re.sub(r"(?:[a-z]:)?[\\/][^\s:]+", "<path>", t)
    t = re.sub(r"0x[0-9a-f]+", "<hex>", t)
    t = re.sub(r"\b\d+\b", "<n>", t)
    return re.sub(r"\s+", " ", t).strip()


def fingerprint(norm):
    return hashlib.sha1(norm.encode("utf-8")).hexdigest()[:16]


def _tokens(s):
    return set(re.findall(r"[a-z_<>]+", s))


def score(a, b):
    ta, tb = _tokens(a), _tokens(b)
    jac = len(ta & tb) / len(ta | tb) if ta | tb else 0.0
    return 0.5 * jac + 0.5 * difflib.SequenceMatcher(None, a, b).ratio()


def find_similar(norm, rows, threshold=0.6, top=3):
    out = []
    for r in rows:
        s = score(norm, r["norm"])
        if s >= threshold:
            out.append({"id": r["id"], "title": r["title"], "created_at": r["created_at"],
                        "similarity": round(s, 2)})
    out.sort(key=lambda x: -x["similarity"])
    return out[:top]
