from __future__ import annotations

import re
from typing import Optional

from .audit import normalize_name
from .models import (
    DirectiveEntry,
    RequirementEntry,
    RequirementsParseResult,
)


def parse_requirements_file(path: str) -> RequirementsParseResult:
    """Read a requirements file and return parsed entries + directives."""
    with open(path, "r", encoding="utf-8") as handle:
        return parse_requirements_text(handle.read())


def parse_requirements_text(text: str) -> RequirementsParseResult:
    """Parse editable requirements, flag directives, and keep unknown lines."""
    result = RequirementsParseResult()
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        # Drop inline comments and blank lines to avoid false parsing.
        cleaned = strip_inline_comment(raw_line)
        if not cleaned.strip():
            continue

        stripped = cleaned.strip()
        if is_directive(stripped):
            # Directives (e.g., VCS/URL/path) are recorded so the caller can skip.
            result.directives.append(DirectiveEntry(line_no=line_no, raw=stripped))
            continue

        parsed = parse_editable_requirement(stripped, line_no)
        if parsed:
            # Valid editable requirement that can be updated.
            result.editable.append(parsed)
        else:
            # Keep unparsed lines for diagnostics or future handling.
            result.unknown.append(DirectiveEntry(line_no=line_no, raw=stripped))

    if result.directives:
        # Any directive means we should avoid editing the file automatically.
        result.skip_reason = "directive or unsupported install option detected"

    return result


def strip_inline_comment(line: str) -> str:
    """Remove inline comments while preserving requirement tokens."""
    if "#" not in line:
        return line
    if line.lstrip().startswith("#"):
        # Full-line comment becomes an empty string.
        return ""
    parts = re.split(r"\s+#", line, maxsplit=1)
    return parts[0].rstrip()


def is_directive(line: str) -> bool:
    """Detect lines that imply a non-standard requirement source."""
    lower = line.lower()
    # Leading dashes usually indicate pip options like -r, -f, or -e.
    if lower.startswith("-"):
        return True
    if lower.startswith(("git+", "hg+", "svn+", "bzr+")):
        return True
    if "://" in line:
        return True
    if line.startswith((".", "/", "~")):
        return True
    if lower.startswith("file:"):
        return True
    if "@" in line:
        return True
    return False


def parse_editable_requirement(
    line: str,
    line_no: int,
) -> Optional[RequirementEntry]:
    """Parse simple PEP 440 name + optional version constraints."""
    # Strictly accept "name" plus optional version specifiers (no extras).
    name_re = r"[A-Za-z0-9][A-Za-z0-9._-]*"
    op_re = r"(==|>=|<=|~=|!=|>|<)"
    version_re = r"[A-Za-z0-9][A-Za-z0-9._-]*"
    spec_re = rf"{op_re}\s*{version_re}"
    combined_re = (
        rf"^(?P<name>{name_re})(?P<spec>\s*(?:{spec_re})(?:\s*,\s*{spec_re})*)?\s*$"
    )
    match = re.match(combined_re, line)
    if not match:
        return None
    name = match.group("name")
    spec = match.group("spec") or ""
    return RequirementEntry(name=name, spec=spec.strip(), line_no=line_no, raw=line)


def find_requirement_line(path: str, package_name: str) -> Optional[str]:
    """Return the raw requirement line for a package from the given file."""
    normalized_target = normalize_name(package_name)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line_no, raw_line in enumerate(handle, start=1):
                # Match only editable requirements (skip directives/unknowns).
                cleaned = strip_inline_comment(raw_line)
                if not cleaned.strip():
                    continue
                parsed = parse_editable_requirement(cleaned.strip(), line_no)
                if not parsed:
                    continue
                if normalize_name(parsed.name) == normalized_target:
                    return raw_line.strip()
    except OSError:
        return None
    return None
