"""Source code reader for Java fuzz-target analysis.

Reads ``.java`` files from a path, locates class definitions, and
returns the full class text for inclusion in the LLM prompt.

The reader is geared towards Java applet / application targets.
Override or extend for other languages or more selective extraction.
"""

import logging
import os
import re

log = logging.getLogger(__name__)

# Budget cap for the assembled context string (characters).
DEFAULT_BUDGET = 16000


class SourceReader:
    """Read Java source files and extract class text for the LLM prompt.

    Extension points
    ----------------
    - ``collect_files()`` -- CAN override to change which files are
      collected (e.g. read a build manifest, skip test directories).
    - ``score_file()`` -- CAN override to change prioritisation
      (e.g. boost files that import parsing libraries).
    - ``extract_classes()`` -- SHOULD override for non-Java targets or
      if you need AST-level precision (e.g. via tree-sitter).
    - ``build_context()`` -- CAN override to change final assembly
      (e.g. prepend a natural-language format description).
    """

    # Extensions to consider.
    # SHOULD be extended for other JVM languages (.kt, .scala, .groovy).
    SOURCE_EXTENSIONS = {".java"}

    # Substrings in filenames that suggest input-handling relevance.
    # SHOULD be extended with target-specific names.
    PRIORITY_KEYWORDS = [
        "main", "applet", "fuzz", "harness", "target",
        "parse", "parser", "read", "input", "decode",
        "servlet", "handler", "processor", "request",
        "packet", "message", "frame", "protocol",
    ]

    def __init__(self, source_path, budget=DEFAULT_BUDGET):
        """
        Args:
            source_path: Single ``.java`` file or directory to scan.
            budget: Max characters for the assembled context string.
        """
        self.source_path = source_path
        self.budget = budget

    # ==================================================================
    # File discovery and prioritisation
    # ==================================================================

    def collect_files(self):
        """Return a list of ``.java`` file paths under ``source_path``.

        CAN be overridden to e.g. filter by package, skip tests, or
        read a build manifest.

        Returns:
            list[str]: Absolute paths.
        """
        path = self.source_path
        if os.path.isfile(path):
            return [path]

        result = []
        for root, _dirs, files in os.walk(path):
            for fname in files:
                if os.path.splitext(fname)[1].lower() in self.SOURCE_EXTENSIONS:
                    result.append(os.path.join(root, fname))
        return result

    def score_file(self, filepath):
        """Return a priority score for *filepath* (higher = more relevant).

        CAN be overridden to incorporate additional signals (coverage
        data, build-graph distance, git recency, etc.).

        Returns:
            int: Priority score.
        """
        name = os.path.basename(filepath).lower()
        score = 0
        for kw in self.PRIORITY_KEYWORDS:
            if kw in name:
                score += 10
        # Smaller files are easier to include in full.
        try:
            if os.path.getsize(filepath) < 8192:
                score += 2
        except OSError:
            pass
        return score

    # ==================================================================
    # Class extraction
    # ==================================================================

    # Matches top-level and inner class/interface/enum declarations.
    _RE_CLASS = re.compile(
        r"^[ \t]*(?:public\s+|protected\s+|private\s+|static\s+|"
        r"abstract\s+|final\s+)*"
        r"(?:class|interface|enum)\s+(\w+)",
        re.MULTILINE,
    )

    def extract_classes(self, filepath):
        """Extract complete class definitions from a ``.java`` file.

        SHOULD be overridden for non-Java targets.

        The default implementation reads the file, locates each
        top-level ``class`` / ``interface`` / ``enum`` declaration by
        brace-depth tracking, and returns the full text of every class
        found.

        Args:
            filepath: Absolute path to the ``.java`` file.

        Returns:
            list[tuple[str, str]]: List of ``(class_name, full_text)``
                pairs, one per class found in the file.
        """
        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                source = f.read()
        except OSError as e:
            log.warning("Could not read %s: %s", filepath, e)
            return []

        lines = source.split("\n")
        classes = []

        i = 0
        while i < len(lines):
            m = self._RE_CLASS.match(lines[i])
            if m:
                class_name = m.group(1)
                # Collect the full class body by tracking brace depth.
                block = []

                # Include preceding annotations/comments (javadoc, etc.)
                j = i - 1
                preamble = []
                while j >= 0 and (lines[j].strip().startswith("@")
                                  or lines[j].strip().startswith("*")
                                  or lines[j].strip().startswith("//")
                                  or lines[j].strip().startswith("/*")
                                  or lines[j].strip() == ""):
                    preamble.append(lines[j])
                    j -= 1
                preamble.reverse()
                block.extend(preamble)

                depth = 0
                while i < len(lines):
                    block.append(lines[i])
                    depth += lines[i].count("{") - lines[i].count("}")
                    i += 1
                    if depth <= 0 and "{" in "".join(block):
                        break

                classes.append((class_name, "\n".join(block)))
                continue

            i += 1

        # If no class declaration was matched, return the whole file --
        # the heuristic may have missed an unusual declaration style.
        if not classes:
            classes.append((os.path.splitext(os.path.basename(filepath))[0],
                            source))

        return classes

    # ==================================================================
    # Context assembly
    # ==================================================================

    def build_context(self):
        """Collect, prioritise, and assemble source context.

        CAN be overridden to change assembly strategy (e.g. add a
        preamble describing the expected input format).

        Returns:
            str: Combined context string within budget.
        """
        files = self.collect_files()
        if not files:
            log.warning("No source files found at %s", self.source_path)
            return "(no source files found)"

        # Sort by priority (highest first).
        scored = [(self.score_file(f), f) for f in files]
        scored.sort(key=lambda x: x[0], reverse=True)

        sections = []
        used = 0
        files_included = 0

        for _score, filepath in scored:
            remaining = self.budget - used
            if remaining <= 200:
                break

            relpath = os.path.relpath(filepath, self.source_path)
            classes = self.extract_classes(filepath)

            for class_name, class_text in classes:
                header = f"// ── {relpath} :: {class_name} ──\n"
                entry = header + class_text
                if len(entry) > remaining:
                    # Truncate but still include partial context.
                    entry = entry[:remaining] + "\n// ... truncated ..."
                sections.append(entry)
                used += len(entry) + 1
                remaining = self.budget - used
                if remaining <= 200:
                    break

            files_included += 1

        skipped = len(files) - files_included
        if skipped > 0:
            sections.append(
                f"\n// ({skipped} more file(s) omitted to fit budget)")

        log.info("Source context: %d/%d files, %d chars",
                 files_included, len(files), used)
        return "\n".join(sections)
