#!/usr/bin/env python3
"""Skill validator for anbeime-cybersecurity-skills repository.

Validates skill structure, YAML frontmatter, and content requirements.
"""

import os
import re
import sys
import yaml
from pathlib import Path
from typing import List, Tuple

SKILL_DIR = Path(__file__).parent.parent / "skills"
VALID_SUFFIXES = {".md", ".yaml", ".yml"}


def validate_frontmatter(content: str) -> Tuple[bool, List[str]]:
    """Validate YAML frontmatter in SKILL.md."""
    errors = []
    if not content.startswith("---\n"):
        errors.append("Missing opening YAML frontmatter delimiter")
        return False, errors

    # Find the closing ---
    close_match = re.search(r"\n---\n", content)
    if not close_match:
        errors.append("Missing closing YAML frontmatter delimiter")
        return False, errors

    frontmatter = content[4:close_match.start()]
    try:
        data = yaml.safe_load(frontmatter)
    except yaml.YAMleException as e:
        errors.append(f"Invalid YAML frontmatter: {e}")
        return False, errors

    if not isinstance(data, dict):
        errors.append("YAML frontmatter must be a mapping")
        return False, errors

    if "name" not in data:
        errors.append("Missing 'name' field in frontmatter")
    if "description" not in data:
        errors.append("Missing 'description' field in frontmatter")

    return len(errors) == 0, errors


def validate_markdown(content: str) -> Tuple[bool, List[str]]:
    """Validate markdown content requirements."""
    errors = []
    if content.count("#") < 1:
        errors.append("Missing at least one heading (#)")

    # Count lines in body (excluding frontmatter)
    if content.startswith("---\n"):
        close_match = re.search(r"\n---\n", content)
        body_start = close_match.end() if close_match else len(content)
        body = content[body_start:]
    else:
        body = content

    lines = body.strip().split("\n")
    if len(lines) < 10:
        errors.append("Body must be at least 10 lines")

    return len(errors) == 0, errors


def validate_skill_dir(skill_path: Path) -> List[str]:
    """Validate a single skill directory."""
    errors = []

    if not skill_path.exists():
        errors.append(f"Skill directory does not exist: {skill_path}")
        return errors

    # anbeime/skill uses nested structure: skills/<name>/<name>/SKILL.md
    skill_md = skill_path / "SKILL.md"
    if not skill_md.exists():
        inner = skill_path / skill_path.name
        skill_md = inner / "SKILL.md"

    if not skill_md.exists():
        errors.append(f"Missing SKILL.md in {skill_path} or {skill_path / skill_path.name}")
        return errors

    content = skill_md.read_text(encoding="utf-8")
    fm_valid, fm_errors = validate_frontmatter(content)
    md_valid, md_errors = validate_markdown(content)

    if not fm_valid:
        errors.extend([f"[Frontmatter] {e}" for e in fm_errors])
    if not md_valid:
        errors.extend([f"[Body] {e}" for e in md_errors])

    # Check references directory exists (relative to skill_path / SKILL.md's dir)
    skill_module_dir = skill_md.parent
    references = skill_module_dir / "references"
    if references.exists():
        ref_files = list(references.glob("*.md"))
        if not ref_files:
            errors.append("References directory exists but contains no .md files")

    return errors


def validate_repositories() -> Tuple[bool, List[str]]:
    """Validate the entire repository."""
    errors = []

    if not SKILL_DIR.exists():
        errors.append(f"Skills directory not found: {SKILL_DIR}")
        return False, errors

    skill_dirs = list(SKILL_DIR.iterdir())
    if not skill_dirs:
        errors.append(f"No skills found in {SKILL_DIR}")

    for skill_dir in skill_dirs:
        if skill_dir.is_dir():
            errors.extend(validate_skill_dir(skill_dir))

    return len(errors) == 0, errors


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Validate anbeime-cybersecurity-skills skills")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate skill directories",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Specific skill directory to validate",
    )
    args = parser.parse_args()

    if args.path:
        target = Path(args.path)
        errors = validate_skill_dir(target)
        if errors:
            print("VALIDATION FAILED:")
            for e in errors:
                print(f"  ✗ {e}")
            return 1
        else:
            print("VALIDATION PASSED")
            return 0

    valid, errors = validate_repositories()

    if valid:
        print("VALIDATION PASSED — All skills are valid.")
        return 0

    print("VALIDATION FAILED:")
    for e in errors:
        print(f"  ✗ {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
