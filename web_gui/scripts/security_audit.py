#!/usr/bin/env python3
"""
ES: Auditoría estática de seguridad frontend para web_gui.
EN: Static frontend security audit for web_gui.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

JS_EXCLUDE = {ROOT / "libraries" / "chart.umd.js"}
TEXT_EXT = {".js", ".html", ".json", ".css", ".php"}

FORBIDDEN_JS = [
    (re.compile(r"\.innerHTML\s*="), "innerHTML assignment"),
    (re.compile(r"\.outerHTML\s*="), "outerHTML assignment"),
    (re.compile(r"\.insertAdjacentHTML\s*\("), "insertAdjacentHTML"),
    (re.compile(r"document\.write\s*\("), "document.write"),
    (re.compile(r"\beval\s*\("), "eval"),
    (re.compile(r"\bnew\s+Function\s*\("), "new Function"),
    (re.compile(r"setTimeout\s*\(\s*['\"]"), "setTimeout string"),
    (re.compile(r"setInterval\s*\(\s*['\"]"), "setInterval string"),
    (re.compile(r"javascript\s*:", re.I), "javascript: URL"),
]



FORBIDDEN_PHP = [
    (re.compile(r"\beval\s*\(", re.I), "PHP eval"),
    (re.compile(r"\b(shell_exec|exec|system|passthru|proc_open|popen)\s*\(", re.I), "PHP command execution"),
    (re.compile(r"`[^`]+`"), "PHP backtick execution"),
    (re.compile(r"\$_GET\s*\[\s*['\"]url['\"]\s*\]", re.I), "PHP open proxy url parameter"),
]

FORBIDDEN_HTML = [
    (re.compile(r"<script(?![^>]+\bsrc=)[^>]*>", re.I), "inline script tag"),
    (re.compile(r"<script[^>]+\bsrc=['\"]https?://", re.I), "remote script"),
    (re.compile(r"\son[a-z]+\s*=", re.I), "inline event handler"),
    (re.compile(r"javascript\s*:", re.I), "javascript: URL"),
    (re.compile(r"target=['\"]_blank['\"](?![^>]+rel=['\"][^'\"]*noopener)", re.I), "target=_blank without noopener"),
]


def strip_js_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(^|[^:])//.*", r"\1", text)
    return text


def iter_files():
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in TEXT_EXT:
            continue
        rel = path.relative_to(ROOT)
        if any(part.startswith(".") for part in rel.parts):
            continue
        yield path


def add(failures, path: Path, label: str, line: int, snippet: str):
    failures.append(f"{path.relative_to(ROOT)}:{line}: {label}: {snippet.strip()[:160]}")


def audit_js(path: Path, failures: list[str]):
    if path in JS_EXCLUDE:
        return
    text = strip_js_comments(path.read_text(errors="ignore"))
    for regex, label in FORBIDDEN_JS:
        for match in regex.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            add(failures, path, label, line, text.splitlines()[line - 1])
    if "localStorage" in text and "praesidium.token" in text:
        line = text.count("\n", 0, text.index("praesidium.token")) + 1
        add(failures, path, "JWT token storage in localStorage", line, text.splitlines()[line - 1])
    if "sessionStorage" in text and "token" in text.lower():
        line = text.count("\n", 0, text.index("sessionStorage")) + 1
        add(failures, path, "JWT token storage in sessionStorage", line, text.splitlines()[line - 1])



def audit_php(path: Path, failures: list[str]):
    text = path.read_text(errors="ignore")
    for regex, label in FORBIDDEN_PHP:
        for match in regex.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            add(failures, path, label, line, text.splitlines()[line - 1])


def audit_html(path: Path, failures: list[str]):
    text = path.read_text(errors="ignore")
    for regex, label in FORBIDDEN_HTML:
        for match in regex.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            add(failures, path, label, line, text.splitlines()[line - 1])


def walk_json(value, path=""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from walk_json(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_json(item, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def audit_i18n(path: Path, failures: list[str]):
    data = json.loads(path.read_text())
    for key, value in walk_json(data):
        if "<" in value or ">" in value:
            failures.append(f"{path.relative_to(ROOT)}:{key}: i18n value contains HTML-like angle brackets")
        if re.search(r"\bon[a-z]+\s*=|javascript\s*:", value, re.I):
            failures.append(f"{path.relative_to(ROOT)}:{key}: i18n value contains event handler/javascript URL")


def main() -> int:
    failures: list[str] = []
    for path in iter_files():
        if path.suffix == ".js":
            audit_js(path, failures)
        elif path.suffix == ".html":
            audit_html(path, failures)
        elif path.suffix == ".php":
            audit_php(path, failures)
        elif path.parts[-2:] in [("lang", "english.json"), ("lang", "espanol.json")]:
            audit_i18n(path, failures)
    if failures:
        print("WEBGUI SECURITY AUDIT FAILED")
        for failure in failures:
            print("-", failure)
        return 1
    print("WEBGUI SECURITY AUDIT PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
