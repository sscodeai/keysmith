#!/usr/bin/env python3
"""Check that every translated doc mirrors its English original.

The public repo keeps Japanese mirrors next to their English originals
(README.md / README.ja.md, AGENTS.md / AGENTS.ja.md, ...). A feature commit that
only edits the English file leaves a stale mirror behind, which reads as
abandonment. This compares the structure — heading count and code-fence count —
of each pair and fails when they drift.

    python3 scripts/check-doc-parity.py

Exit code 0 when every pair matches, 1 otherwise.
"""
import os
import sys

SKIP_DIRS = {".git", "build", "dist", "node_modules", ".docusaurus"}


def count(path, pred):
    with open(path, encoding="utf-8") as fh:
        return sum(1 for line in fh if pred(line))


def is_heading(line):
    return line.startswith("#")


def is_fence(line):
    return line.strip() == "```"


def pairs(root="."):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if not name.endswith(".ja.md"):
                continue
            english = name[: -len(".ja.md")] + ".md"
            if english in filenames:
                found.append((os.path.join(dirpath, english), os.path.join(dirpath, name)))
    return sorted(found)


def main():
    checked = pairs()
    if not checked:
        print("no translated doc pairs found")
        return 0

    failures = []
    for en, ja in checked:
        en_h, ja_h = count(en, is_heading), count(ja, is_heading)
        en_f, ja_f = count(en, is_fence), count(ja, is_fence)
        ok = en_h == ja_h and en_f == ja_f
        print("%-28s headings %d/%d  fences %d/%d  %s"
              % (en, en_h, ja_h, en_f, ja_f, "OK" if ok else "DRIFT"))
        if not ok:
            failures.append(en)

    if failures:
        print("\nstale mirrors: %s" % ", ".join(failures))
        print("mirror the missing sections, or update the heading/fence structure so it matches")
        return 1
    print("\nall %d doc pairs are in sync" % len(checked))
    return 0


if __name__ == "__main__":
    sys.exit(main())
