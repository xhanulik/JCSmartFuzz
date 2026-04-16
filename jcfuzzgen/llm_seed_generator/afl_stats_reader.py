"""AFL++ stats and queue reader.

This module provides read-only access to the AFL++ output directory.
It is used by the seed generator to observe fuzzer state, but is also
useful on its own for monitoring or scripting.

Nothing in this file is LLM-specific -- it only reads AFL++ artifacts.
"""

import glob
import logging
import os
import time

log = logging.getLogger(__name__)


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

    def read_queue_entries(self, max_entries=50):
        """Read the most interesting queue entries according to path costs.

        When ``path_costs.csv`` is available, entries are ranked by cost
        (ascending -- lowest cost = most interesting for fuzzing) and
        the *max_entries* cheapest are returned.  Falls back to the most
        recent entries when cost data is unavailable.

        Args:
            max_entries: Maximum number of entries to return.

        Returns:
            list[tuple[str, bytes]]: List of (filename, content) pairs,
                ordered by cost (cheapest first) when cost data exists,
                or by recency otherwise.
        """
        if not self.instance_dir:
            return []
        queue_dir = os.path.join(self.instance_dir, "queue")

        # Try cost-based selection first.
        costs = self.read_path_costs()
        if costs:
            # Pick the max_entries lowest-cost filenames.
            selected = [row["filename"] for row in costs[:max_entries]]
            result = []
            for fname in selected:
                entry_path = os.path.join(queue_dir, fname)
                try:
                    with open(entry_path, "rb") as f:
                        result.append((fname, f.read()))
                except OSError:
                    continue
            return result

        # Fallback: most recent entries by sort order.
        entries = sorted(glob.glob(os.path.join(queue_dir, "id:*")))
        result = []
        for entry_path in entries[-max_entries:]:
            try:
                with open(entry_path, "rb") as f:
                    content = f.read()
                result.append((os.path.basename(entry_path), content))
            except OSError:
                continue
        return result

    def read_crashes(self, max_entries=20):
        """Read crashing inputs.

        Returns:
            list[tuple[str, bytes]]: List of (filename, content) pairs.
        """
        if not self.instance_dir:
            return []
        crash_dir = os.path.join(self.instance_dir, "crashes")
        entries = sorted(glob.glob(os.path.join(crash_dir, "id:*")))
        result = []
        for entry_path in entries[-max_entries:]:
            try:
                with open(entry_path, "rb") as f:
                    result.append((os.path.basename(entry_path), f.read()))
            except OSError:
                continue
        return result

    def read_plot_data(self, last_n_lines=20):
        """Read the tail of plot_data for trend analysis.

        Returns:
            list[str]: Last N lines of plot_data.
        """
        if not self.instance_dir:
            return []
        plot_path = os.path.join(self.instance_dir, "plot_data")
        try:
            with open(plot_path) as f:
                lines = f.readlines()
            if not lines:
                return []
            # First line is the column header; always include it.
            header = [lines[0]]
            data = lines[1:]
            return header + data[-last_n_lines:]
        except OSError:
            return []

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

    def is_coverage_stalling(self):
        """Check if the fuzzer has gone multiple cycles without new paths."""
        stats = self.read_stats()
        try:
            cycles_wo_finds = int(stats.get("cycles_wo_finds", "0"))
        except ValueError:
            return False
        return cycles_wo_finds > 2
