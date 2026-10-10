"""Log summarisation: levels, grouped repeated errors, bursts and noteworthy events."""
import re
from collections import Counter, defaultdict

from .similarity import normalize

LEVEL = re.compile(r"\b(CRITICAL|FATAL|ERROR|ERR|WARN(?:ING)?|INFO|DEBUG|TRACE)\b", re.I)
TS = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})")
KEYWORDS = re.compile(r"(?i)timeout|timed out|connection refused|out of memory|oom|denied|unauthori[sz]ed|forbidden|"
                      r"failed login|authentication failed|deadlock|segfault|segmentation|panic|traceback|exception")


def _level(line):
    m = LEVEL.search(line)
    if not m:
        return None
    lv = m.group(1).upper()
    return {"ERR": "ERROR", "WARN": "WARNING", "FATAL": "CRITICAL"}.get(lv, lv)


def analyze(text, max_lines=200_000):
    lines = text.replace("\r\n", "\n").split("\n")[:max_lines]
    levels, groups, per_min, events = Counter(), {}, Counter(), []
    traces = 0
    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        lv = _level(line)
        if lv:
            levels[lv] += 1
        if "Traceback (most recent call last)" in line:
            traces += 1
        ts = TS.search(line)
        if lv in ("ERROR", "CRITICAL"):
            body = TS.sub("", line)
            body = LEVEL.sub("", body, count=1)
            key = normalize(body)[:160]
            g = groups.setdefault(key, {"count": 0, "first_line": i, "last_line": i, "sample": line.strip()[:240], "level": lv})
            g["count"] += 1
            g["last_line"] = i
            if ts:
                per_min[f"{ts.group(1)} {ts.group(2)}"] += 1
        if KEYWORDS.search(line) and len(events) < 25:
            events.append({"line": i, "level": lv, "text": line.strip()[:200]})

    ranked = sorted(groups.values(), key=lambda g: -g["count"])
    total_err = sum(g["count"] for g in ranked)
    bursts = []
    if per_min:
        avg = sum(per_min.values()) / len(per_min)
        bursts = [{"minute": m, "errors": n} for m, n in per_min.most_common(5) if n >= max(5, 3 * avg)]
    rare = [g for g in ranked if g["count"] == 1][:10] if len(ranked) > 5 else []
    return {
        "total_lines": len(lines), "levels": dict(levels), "traceback_count": traces,
        "error_total": total_err, "error_groups": ranked[:20], "distinct_errors": len(ranked),
        "bursts": bursts, "rare_errors": rare, "events": events,
        "note": "Grouping masks numbers, paths and quoted values so repeated errors collapse into one pattern.",
    }
