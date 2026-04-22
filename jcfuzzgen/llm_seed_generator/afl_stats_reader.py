"""AFL++ stats and queue reader.

This module provides read-only access to the AFL++ output directory.
It is used by the seed generator to observe fuzzer state, but is also
useful on its own for monitoring or scripting.

Nothing in this file is LLM-specific -- it only reads AFL++ artifacts.
"""

import glob
import logging
import os
import re
import time

log = logging.getLogger(__name__)


_RE_OP = re.compile(r",op:([^,]+)")
_RE_ORIG = re.compile(r",orig:([^,]+)")


def parse_queue_name(name):
    """Extract AFL++ metadata from a queue filename.

    Returns a dict with ``is_original`` (bool), ``is_cov`` (bool), and
    ``op`` (str | None).  ``op`` is set to ``"initial seed (...)"`` for
    files that carry an ``orig:`` field, to the mutation operator
    otherwise.
    """
    is_cov = ",+cov" in name
    orig_m = _RE_ORIG.search(name)
    is_original = orig_m is not None
    if is_original:
        op = f"initial seed ({orig_m.group(1)})"
    else:
        op_m = _RE_OP.search(name)
        op = op_m.group(1) if op_m else None
    return {"is_original": is_original, "is_cov": is_cov, "op": op}


class AFLStatsReader:
    """Reads AFL++ fuzzer stats and queue state from the output directory.

    This class is complete as-is and should not need modification for
    typical use.  You may want to extend it if you need to read
    additional AFL++ artifacts (e.g. hangs/, .synced/).
    """

    def __init__(self, afl_out_dir):
        self.out_dir = afl_out_dir
        self.instance_dir = self._find_instance_dir()

    def _find_instance_dir(self):
        """Find the AFL++ instance directory (handles -M/-S naming)."""
        candidates = glob.glob(os.path.join(self.out_dir, "*/fuzzer_stats"))
        if candidates:
            return os.path.dirname(candidates[0])
        # Might be the directory itself (single instance, no subdirectory)
        if os.path.isfile(os.path.join(self.out_dir, "fuzzer_stats")):
            return self.out_dir
        return None

    def wait_for_fuzzer(self, timeout=300):
        """Block until AFL++ creates its output directory and fuzzer_stats."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.instance_dir = self._find_instance_dir()
            if self.instance_dir:
                log.info("Found AFL++ instance at %s", self.instance_dir)
                return True
            log.info("Waiting for AFL++ to start (looking in %s) ...",
                     self.out_dir)
            time.sleep(5)
        return False

    def read_stats(self):
        """Parse fuzzer_stats into a dict.

        Returns:
            dict: Key-value pairs from fuzzer_stats, or empty dict on error.
        """
        if not self.instance_dir:
            return {}
        stats_path = os.path.join(self.instance_dir, "fuzzer_stats")
        stats = {}
        try:
            with open(stats_path) as f:
                for line in f:
                    if ":" in line:
                        key, val = line.split(":", 1)
                        stats[key.strip()] = val.strip()
        except OSError as e:
            log.warning("Could not read fuzzer_stats: %s", e)
        return stats

    def read_path_costs(self):
        """Parse ``path_costs.csv`` and return entries sorted by cost.

        The CSV is ``;``-separated with columns::

            Input file;Time;Memory;Instr.;User-Defined

        Rows are sorted ascending by ``(time, memory, instructions,
        user_defined)`` so the cheapest (most interesting) entries come
        first.

        Returns:
            list[dict]: Each dict has keys ``filename`` (str),
                ``time`` (int), ``memory`` (int), ``instructions`` (int),
                ``user_defined`` (int).  Empty list if the file is
                missing or unparseable.
        """
        if not self.instance_dir:
            return []
        csv_path = os.path.join(self.instance_dir, "path_costs.csv")
        rows = []
        try:
            with open(csv_path) as f:
                header = f.readline()  # skip header
                if not header:
                    return []
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(";")
                    if len(parts) < 5:
                        continue
                    try:
                        rows.append({
                            "filename":     parts[0].strip(),
                            "time":         int(parts[1].strip()),
                            "memory":       int(parts[2].strip()),
                            "instructions": int(parts[3].strip()),
                            "user_defined": int(parts[4].strip()),
                        })
                    except (ValueError, IndexError):
                        continue
        except OSError:
            return []

        # Sort ascending: lowest cost = most interesting.
        rows.sort(key=lambda r: (r["time"], r["memory"],
                                 r["instructions"], r["user_defined"]))
        return rows
