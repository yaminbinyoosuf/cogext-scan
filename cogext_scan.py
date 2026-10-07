#!/usr/bin/env python3
"""
cogext-scan v0.1.0

Zero-dependency static analysis tool for AI agent code, framework calls,
and tool definitions.

Four checks, AST-based (no regex parsing of source structure):

  1. silent_exception_swallowing  -- try/except returns a static value
                                     without raising
  2. unbounded_execution_loop     -- AgentExecutor / Crew / Task missing
                                     max_iterations + max_execution_time
  3. unprotected_destructive_tool -- delete_* / drop_* / truncate_* /
                                     remove_* / destroy_* without an
                                     If / Assert / Raise guard
  4. hardcoded_credentials        -- string constants matching known
                                     provider key shapes

Runs fully offline. No network calls, no third-party imports.
Python 3.9+.
"""

import argparse
import ast
import json
import os
import re
import sys

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "cyan": "\033[96m",
    "dim": "\033[2m",
}


def _supports_color():
    """Enable color only for a real TTY, or when forced for the test harness."""
    if os.environ.get("COGEXT_FORCE_COLOR") == "1":
        return True
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


_COLOR_ENABLED = _supports_color()


def paint(text, color):
    """Wrap text in an ANSI color when color output is enabled."""
    if not _COLOR_ENABLED or color not in ANSI:
        return text
    return ANSI[color] + text + ANSI["reset"]


# ---------------------------------------------------------------------------
# Credential signatures
#
# Assembled from fragments on purpose: this file must stay clean when it is
# pointed at itself.
# ---------------------------------------------------------------------------

_SK = "s" + "k" + "-"
_GHP = "g" + "h" + "p" + "_"
_XOX = "x" + "o" + "x"
_KEY = "k" + "e" + "y" + "-"
_LIVE = "l" + "i" + "v" + "e" + "_"

CREDENTIAL_PATTERNS = [
    (re.compile(_SK + r"[a-zA-Z0-9_\-]{16,}"), "the OpenAI secret key shape"),
    (re.compile(_GHP + r"[a-zA-Z0-9]{20,}"), "the GitHub personal access token shape"),
    (re.compile(_XOX + r"[baprs]-[a-zA-Z0-9-]{10,48}"), "the Slack token shape"),
    (re.compile(_KEY + r"[a-zA-Z0-9]{20,}"), "the generic provider API key shape"),
    (re.compile(r"[a-z]{2}_" + _LIVE + r"(?=[a-zA-Z0-9]*[0-9])[a-zA-Z0-9]{16,}"), "the live API key shape"),
]

# Strings that look like keys but are obviously documentation placeholders.
PLACEHOLDER_MARKERS = (
    "your",
    "example",
    "placeholder",
    "redacted",
    "xxxx",
    "dummy",
    "sample",
    "changeme",
    "fake",
    "test",
    "todo",
)

# Directory names that are never worth scanning.
SKIP_DIRS = {".git", "venv", "__pycache__", "node_modules"}

DESTRUCTIVE_PREFIXES = (
    "delete_",
    "drop_",
    "truncate_",
    "remove_",
    "destroy_",
)

BOUNDED_ARGS = {"max_iterations", "max_execution_time"}
AGENT_EXECUTORS = {"AgentExecutor", "Crew", "Task"}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}

SEPARATOR = "-" * 80

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


class Finding(object):
    """A single scanner result."""

    __slots__ = ("check", "title", "severity", "path", "line", "description", "impact")

    def __init__(self, check, title, severity, path, line, description, impact):
        self.check = check
        self.title = title
        self.severity = severity
        self.path = path
        self.line = line
        self.description = description
        self.impact = impact

    def as_dict(self):
        return {
            "check": self.check,
            "title": self.title,
            "severity": self.severity,
            "file": self.path,
            "line": self.line,
            "description": self.description,
            "impact": self.impact,
        }


# ---------------------------------------------------------------------------
# Check 1 -- silent exception swallowing
# ---------------------------------------------------------------------------


def _is_static_value(node):
    """True when node is a literal (or a literal container), not a call/name."""
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_static_value(elt) for elt in node.elts)
    if isinstance(node, ast.Dict):
        keys_ok = all(k is None or _is_static_value(k) for k in node.keys)
        vals_ok = all(_is_static_value(v) for v in node.values)
        return keys_ok and vals_ok
    return False


def _handler_is_silent(handler):
    """True when the handler body returns a static success value and never raises."""
    raised = False
    returned_static = False

    for stmt in ast.walk(handler):
        if isinstance(stmt, ast.Raise):
            raised = True
        if isinstance(stmt, ast.Return) and _is_static_value(stmt.value):
            returned_static = True

    if raised:
        return False
    return returned_static


def check_silent_exception_swallowing(tree, path):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            if _handler_is_silent(handler):
                findings.append(
                    Finding(
                        check="silent_exception_swallowing",
                        title="Silent Exception Swallowing",
                        severity="HIGH",
                        path=path,
                        line=handler.lineno,
                        description=(
                            "Exception handler returns a static success value without "
                            "raising or surfacing the error, so the caller cannot tell "
                            "the operation failed."
                        ),
                        impact=(
                            "The agent reports success on a failed tool call, then "
                            "builds every later step on a false premise. Failures stay "
                            "invisible until production data is already wrong."
                        ),
                    )
                )
                break
    return findings


# ---------------------------------------------------------------------------
# Check 2 -- unbounded execution loop
# ---------------------------------------------------------------------------


def check_unbounded_execution_loop(tree, path):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        if isinstance(func, ast.Name):
            call_name = func.id
        elif isinstance(func, ast.Attribute):
            call_name = func.attr
        else:
            continue

        if call_name not in AGENT_EXECUTORS:
            continue

        provided = set()
        for keyword in node.keywords:
            if keyword.arg is not None:
                provided.add(keyword.arg)
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                provided.add(arg.value)

        if provided & BOUNDED_ARGS:
            continue

        findings.append(
            Finding(
                check="unbounded_execution_loop",
                title="Unbounded Execution Loop",
                severity="CRITICAL",
                path=path,
                line=node.lineno,
                description=(
                    "{0}(...) is constructed without max_iterations or "
                    "max_execution_time, so the agent loop has no iteration or wall-clock "
                    "cap.".format(call_name)
                ),
                impact=(
                    "A reasoning loop that never converges burns tokens and API budget "
                    "without limit, and can hold production resources until the process "
                    "is killed."
                ),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Check 3 -- unprotected destructive tool
# ---------------------------------------------------------------------------


def _has_guard(func_node):
    """True when the function body contains any If / Assert / Raise guard."""
    for node in ast.walk(func_node):
        if isinstance(node, (ast.If, ast.Assert, ast.Raise)):
            return True
    return False


def check_unprotected_destructive_tool(tree, path):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        name = node.name
        lowered = name.lower()
        if not lowered.startswith(DESTRUCTIVE_PREFIXES):
            continue
        if _has_guard(node):
            continue

        findings.append(
            Finding(
                check="unprotected_destructive_tool",
                title="Unprotected Destructive Tool",
                severity="HIGH",
                path=path,
                line=node.lineno,
                description=(
                    "Destructive tool '{0}' runs with no If, Assert, or Raise guard on "
                    "its inputs or target.".format(name)
                ),
                impact=(
                    "An unvalidated destructive tool can permanently delete production "
                    "records or files when the model passes an unexpected argument."
                ),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Check 4 -- hardcoded credentials
# ---------------------------------------------------------------------------


def _looks_like_placeholder(value):
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def check_hardcoded_credentials(tree, path):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        value = node.value
        if len(value) < 12:
            continue
        if _looks_like_placeholder(value):
            continue

        matched_shape = None
        for pattern, shape in CREDENTIAL_PATTERNS:
            if pattern.search(value):
                matched_shape = shape
                break
        if matched_shape is None:
            continue

        findings.append(
            Finding(
                check="hardcoded_credentials",
                title="Hardcoded Credentials",
                severity="CRITICAL",
                path=path,
                line=node.lineno,
                description=(
                    "A string literal matching " + matched_shape + " is embedded in "
                    "source code instead of being read from the environment."
                ),
                impact=(
                    "Anyone with read access to the repository, a log, or a packaged "
                    "artifact can authenticate as the service and run up usage on your "
                    "account."
                ),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# File / tree handling
# ---------------------------------------------------------------------------

CHECKS = (
    check_silent_exception_swallowing,
    check_unbounded_execution_loop,
    check_unprotected_destructive_tool,
    check_hardcoded_credentials,
)


def load_source(path):
    """Read a file and return (source, None) or (None, reason)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(), None
    except OSError as exc:
        return None, "unreadable: {0}".format(exc)


def apply_suppressions(source):
    """Blank any line carrying a '# cogext-ignore' marker.

    Blanking (rather than deleting) keeps every remaining line number aligned
    with the file on disk, so reported lines stay accurate. Because the
    suppression happens before parsing, an ignored line can never contribute
    findings from any check.
    """
    if "cogext-ignore" not in source:
        return source
    kept = []
    for line in source.splitlines():
        if "cogext-ignore" in line:
            kept.append("")
        else:
            kept.append(line)
    return "\n".join(kept)


def parse_source(source):
    """Parse source, returning an AST or None when parsing is not possible."""
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None


def scan_file(path):
    """Run every check against a single file. Never raises."""
    source, _reason = load_source(path)
    if source is None:
        return []

    tree = parse_source(apply_suppressions(source))
    if tree is None:
        return []

    findings = []
    for check in CHECKS:
        try:
            findings.extend(check(tree, path))
        except Exception:
            continue
    return findings


def iter_python_files(root, depth):
    """Yield .py files under root, honouring the depth and skip rules."""
    if os.path.isfile(root):
        if root.endswith(".py"):
            yield root
        return

    root = os.path.abspath(root)

    for _current, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(_current, root)
        level = 0 if rel == "." else rel.count(os.sep) + 1

        if level >= depth:
            dirnames[:] = []

        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in SKIP_DIRS and not name.startswith(".")
        )

        for filename in sorted(filenames):
            if filename.endswith(".py"):
                yield os.path.join(_current, filename)


def scan_target(target, depth):
    findings = []
    for path in iter_python_files(target, depth):
        findings.extend(scan_file(path))
    findings.sort(key=lambda f: (f.path, f.line, SEVERITY_ORDER.get(f.severity, 9)))
    return findings


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def summarize(findings):
    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    score = max(0, 100 - (25 * crit_count + 15 * high_count + 5 * med_count))
    return crit_count, high_count, med_count, score


def status_label(findings):
    if not findings:
        return "0 issues found by 4 checks — not a safety guarantee"
    if any(f.severity in ("CRITICAL", "HIGH") for f in findings):
        return "UNSAFE FOR PRODUCTION"
    return "NEEDS REVIEW"


def status_color(findings):
    if not findings:
        return "green"
    if any(f.severity in ("CRITICAL", "HIGH") for f in findings):
        return "red"
    return "yellow"


def severity_color(severity):
    if severity == "CRITICAL":
        return "red"
    if severity == "HIGH":
        return "yellow"
    return "cyan"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_text(target, findings, depth):
    lines = []

    lines.append("COGEXT Agent Code & Tool Safety Scanner v{0}".format(__version__))
    lines.append("Scanning target path: {0}".format(os.path.abspath(target)))
    lines.append("")

    ordered = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.path, f.line),
    )

    for finding in ordered:
        label = paint("[{0}]".format(finding.severity), severity_color(finding.severity))
        lines.append(
            "{0} {1} in '{2}:{3}'".format(label, finding.title, finding.path, finding.line)
        )
        lines.append("  \u2514\u2500 {0}".format(finding.description))
        lines.append("  \u2514\u2500 Impact: {0}".format(finding.impact))
        lines.append("")

    # Counts must exist before the summary block is rendered.
    crit_count, high_count, med_count, score = summarize(findings)
    total = len(findings)

    lines.append(SEPARATOR)
    lines.append(
        "Scan Summary: {0} Issues Detected ({1} Critical, {2} High, {3} Medium)".format(
            total, crit_count, high_count, med_count
        )
    )
    status = status_label(findings)
    score_line = "Agent Safety Index: {0}/100 [{1}]".format(score, status)
    lines.append(paint(score_line, status_color(findings)))
    lines.append("")
    lines.append(
        paint(
            "Stop silent agent failures at runtime in 3 lines of code:",
            "cyan",
        )
    )
    lines.append(paint("--> https://cogextai.com/guard?ref=cli_scan", "cyan"))

    return "\n".join(lines)


def render_json(target, findings, depth):
    crit_count, high_count, med_count, score = summarize(findings)
    payload = {
        "tool": "cogext-scan",
        "version": __version__,
        "target": os.path.abspath(target),
        "depth": depth,
        "summary": {
            "total": len(findings),
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "agent_safety_index": score,
            "status": status_label(findings),
        },
        "findings": [f.as_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cogext-scan",
        description=(
            "Zero-dependency static analysis for AI agent code, framework calls, "
            "and tool definitions."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="file or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=3,
        help="maximum directory depth to descend (default: 3)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="emit machine-readable JSON instead of terminal output",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit with code 1 when any CRITICAL or HIGH finding exists",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="cogext-scan {0}".format(__version__),
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    target = args.path
    if not os.path.exists(target):
        sys.stderr.write("cogext-scan: path not found: {0}\n".format(target))
        return 2

    depth = args.depth if args.depth > 0 else 1

    try:
        findings = scan_target(target, depth)
    except KeyboardInterrupt:
        sys.stderr.write("cogext-scan: interrupted\n")
        return 130

    crit_count, high_count, _med_count, _score = summarize(findings)

    if args.as_json:
        sys.stdout.write(render_json(target, findings, depth) + "\n")
    else:
        sys.stdout.write(render_text(target, findings, depth) + "\n")

    if args.strict and (crit_count > 0 or high_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
