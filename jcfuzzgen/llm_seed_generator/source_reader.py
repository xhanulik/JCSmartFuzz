"""Source code reader for Java fuzz-target analysis.

Reads a single ``.java`` file, locates class definitions, and returns
the full class text for inclusion in the LLM prompt.

The reader is geared towards Java applet / application targets.
Override or extend for other languages.
"""

import logging
import os
import re

log = logging.getLogger(__name__)

# Budget cap for the assembled context string (characters).
DEFAULT_BUDGET = 16000


class SourceReader:
    """Read a Java source file and extract class/method text for the prompt.

    Extension points
    ----------------
    - ``extract_classes()`` -- SHOULD override for non-Java targets or
      if you need AST-level precision (e.g. via tree-sitter).
    - ``build_context()`` -- CAN override to change final assembly
      (e.g. prepend a natural-language format description).
    """

    def __init__(self, source_path, budget=DEFAULT_BUDGET):
        """
        Args:
            source_path: Path to a single ``.java`` source file.
            budget: Max characters for the assembled context string.
        """
        self.source_path = source_path
        self.budget = budget

    def _read_source(self):
        """Return file text, or empty string on error."""
        try:
            with open(self.source_path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError as e:
            log.warning("Could not read %s: %s", self.source_path, e)
            return ""

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

    def extract_classes(self, source):
        """Extract complete class definitions from *source* text.

        SHOULD be overridden for non-Java targets.

        Locates each top-level ``class`` / ``interface`` / ``enum``
        declaration by brace-depth tracking and returns the full text
        of every class found.

        Returns:
            list[tuple[str, str]]: List of ``(class_name, full_text)``
                pairs, one per class found in the file.
        """
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
            classes.append((
                os.path.splitext(os.path.basename(self.source_path))[0],
                source,
            ))

        return classes

    # ==================================================================
    # Method extraction (by name)
    # ==================================================================

    @staticmethod
    def _method_decl_re(name):
        """Build a regex matching a Java method declaration line for *name*.

        Matches lines like::

            public static short wrapVerifyPin(APDU apdu, byte[] buffer) {
            private void coreVerifyPin(byte[] buf, short off) {

        The match anchors on the method name followed by ``(`` and
        requires a preceding return-type token on the same line, which
        excludes method calls like ``wrapVerifyPin(apdu, buf);``.
        """
        return re.compile(
            r"^\s*"
            r"(?:public\s+|private\s+|protected\s+|static\s+|final\s+|"
            r"synchronized\s+|abstract\s+|native\s+|default\s+)*"
            r"(?:<[^>]+>\s+)?"                    # generics
            # The return-type slot must not be a statement/expression
            # keyword -- otherwise lines like "return fooMethod(...)"
            # would match as declarations.
            r"(?!(?:return|throw|new|if|while|for|do|switch|case|else|"
            r"break|continue|try|catch|finally|assert)\b)"
            r"[\w\.]+(?:\s*\[\s*\])*\s+"          # return type token
            + re.escape(name) + r"\s*\("
        )

    def extract_methods(self, source, method_names):
        """Extract complete method bodies from *source* for each name.

        SHOULD be overridden for non-Java targets (or swap in an AST
        parser for stricter matching).

        Uses brace-depth tracking to delimit each method body, and
        prepends adjacent javadoc / annotation lines to the extracted
        block.

        Args:
            source: Full text of the ``.java`` file.
            method_names: Iterable of method names to look for.

        Returns:
            list[tuple[str, str]]: ``(method_name, source_text)`` pairs
                for every name that was found.  A name missing from the
                file simply does not appear in the result.
        """
        lines = source.split("\n")
        found = []

        for target in method_names:
            decl_re = self._method_decl_re(target)
            for i, line in enumerate(lines):
                if not decl_re.match(line):
                    continue

                # Pull in adjacent preamble (annotations, javadoc).
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

                block = list(preamble) + [lines[i]]
                depth = lines[i].count("{") - lines[i].count("}")
                seen_open = "{" in lines[i]
                k = i + 1
                while k < len(lines):
                    block.append(lines[k])
                    depth += lines[k].count("{") - lines[k].count("}")
                    if "{" in lines[k]:
                        seen_open = True
                    k += 1
                    # Stop once we close the method body, or on an
                    # abstract / interface-style declaration that ends
                    # with ';' before any brace appears.
                    if seen_open and depth <= 0:
                        break
                    if not seen_open and lines[k - 1].rstrip().endswith(";"):
                        break

                found.append((target, "\n".join(block)))
                break  # One declaration per name is enough.

        return found

    def build_method_context(self, method_names):
        """Return concatenated text of named methods extracted from the file.

        Methods that cannot be located are listed at the end as a
        comment so the prompt makes the miss explicit instead of
        silently omitting it.

        Args:
            method_names: List of method names to extract, e.g.
                ``["wrapVerifyPin", "coreVerifyPin"]``.

        Returns:
            str: Assembled source text, or a placeholder when nothing
                was found.
        """
        source = self._read_source()
        if not source:
            return f"(could not read {self.source_path})"

        hits = self.extract_methods(source, method_names)
        found_names = {name for name, _ in hits}
        missing = [n for n in method_names if n not in found_names]

        relpath = os.path.basename(self.source_path)
        sections = [f"// ── {relpath} :: {name} ──\n{text}"
                    for name, text in hits]

        if not sections:
            return f"(methods not found: {', '.join(method_names)})"

        if missing:
            sections.append(f"\n// (methods not found: {', '.join(missing)})")

        log.info("Method context: %d/%d methods extracted",
                 len(method_names) - len(missing), len(method_names))
        return "\n\n".join(sections)

    # ==================================================================
    # Context assembly
    # ==================================================================

    def build_context(self):
        """Read the source file and assemble the full-class context.

        CAN be overridden to change assembly strategy (e.g. add a
        preamble describing the expected input format).

        Returns:
            str: Combined context string within budget.
        """
        source = self._read_source()
        if not source:
            return f"(could not read {self.source_path})"

        relpath = os.path.basename(self.source_path)
        classes = self.extract_classes(source)

        sections = []
        used = 0
        for class_name, class_text in classes:
            remaining = self.budget - used
            if remaining <= 200:
                break
            header = f"// ── {relpath} :: {class_name} ──\n"
            entry = header + class_text
            if len(entry) > remaining:
                entry = entry[:remaining] + "\n// ... truncated ..."
            sections.append(entry)
            used += len(entry) + 1

        log.info("Source context: %d class(es), %d chars",
                 len(sections), used)
        return "\n".join(sections)
