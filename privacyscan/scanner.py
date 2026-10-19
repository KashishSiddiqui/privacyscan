"""Walk files, apply rules line by line, compute a privacy score."""
import os
from dataclasses import dataclass, asdict

from .rules import RULES

EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".java", ".php", ".rb",
        ".go", ".env", ".yml", ".yaml", ".json", ".cfg", ".ini"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
WEIGHTS = {"high": 10, "medium": 4, "low": 1}
ORDER = {"high": 3, "medium": 2, "low": 1, "none": 99}


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    article: str
    message: str
    fix: str
    path: str
    line: int
    snippet: str

    def to_dict(self):
        return asdict(self)


def scan_text(text: str, path: str = "<memory>") -> list:
    findings = []
    for n, line in enumerate(text.splitlines(), 1):
        if "privacyscan: ignore" in line:
            continue
        for r in RULES:
            if r.pattern.search(line) and not (r.unless and r.unless.search(line)):
                findings.append(Finding(r.id, r.name, r.severity, r.article,
                                        r.message, r.fix, path, n, line.strip()[:120]))
    return findings


def _files(root):
    if os.path.isfile(root):
        yield root
        return
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for name in names:
            if os.path.splitext(name)[1].lower() in EXTS or name == ".env":
                yield os.path.join(d, name)


def scan_path(root: str):
    findings, count = [], 0
    for p in _files(root):
        try:
            if os.path.getsize(p) > 1_000_000:
                continue
            with open(p, encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        count += 1
        findings += scan_text(text, os.path.relpath(p, root) if os.path.isdir(root) else p)
    findings.sort(key=lambda f: (-ORDER[f.severity], f.path, f.line))
    return findings, count


def score(findings) -> int:
    return max(0, 100 - sum(WEIGHTS[f.severity] for f in findings))
