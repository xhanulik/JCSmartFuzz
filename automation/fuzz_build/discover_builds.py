#!/usr/bin/env python3
"""Populate the per-repo `fuzz_build` object in corpus/dataset.json for the
Java corpus repos (build_systems javac/Ant/Gradle/Maven).

For each target entry it clones the repo (fetching a pinned commit when the
link pins one), locates the on-card applet, derives the javac source root(s)
and package, maps the applet's non-standard imports to canonical lib tokens,
and records everything a downstream driver needs to compile the applet + the
harness-generated FuzzApplet/FuzzDriver into .class files.

Usage:
    python3 discover_builds.py [--cache DIR] [--only SUBSTR] [--dry-run]

--dry-run prints what would be written without modifying dataset.json.
Repos are cached under --cache (default: ~/.cache/jcsmartscan-clones) and reused.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET = REPO_ROOT / "corpus" / "dataset.json"
# Any Java build system: the fuzzing compile is universal `javac`, so Ant/Gradle/
# Maven repos use the same fuzz_build fields as the direct-`javac` ones.
TARGET_BUILD_SYSTEMS = {"javac", "Ant", "Gradle", "Maven"}
BASE_LIBS = ["jcardsim", "kelinci", "bouncycastle"]
FIELD_ORDER = ["name", "link", "category", "build_systems", "fuzz_build"]

# public JC API packages jcardsim provides (no extra jar needed)
JC_STD = ("java.", "javacard.framework", "javacard.security", "javacardx.crypto",
          "javacardx.apdu", "javacardx.framework", "javacardx.security",
          "javacardx.biometry", "javacardx.external", "javax.smartcardio",
          "com.licel.jcardsim", "edu.cmu.sv.kelinci", "org.bouncycastle")

# import prefixes that are NOT missing dependencies: JDK/host classes (present
# under JDK 8) and test/build-tool helpers that aren't part of the applet.
IGNORE_IMPORT_PREFIXES = ("javax.", "com.sun.", "junit", "org.junit", "org.testng",
                          "org.apache.tools.ant", "org.gradle", "groovy.", "org.mockito")

# import-prefix -> (lib token, runnable_under_jcardsim, note)
IMPORT_LIBS = [
    ("org.globalplatform",  "globalplatform", True,  None),
    ("visa.openplatform",   "openplatform",   True,  None),
    ("com.sun.javacard",    "oracle-jckit",   True,  "imports Oracle RI-internal com.sun.javacard.* (needs the Oracle JC Kit jar)"),
    ("com.google.iot.cbor", "cbor",           True,  None),
    ("sim.toolkit",         "sim-toolkit",    False, "SIM Toolkit applet: compiles with the SAT API jar but jcardsim has no (U)SAT runtime"),
    ("sim.access",          "sim-toolkit",    False, "SIM Toolkit applet: compiles with the SAT API jar but jcardsim has no (U)SAT runtime"),
    ("com.gemplus",         "gemplus-pacap",  False, "proprietary Gemplus PACAP libraries, likely not publicly obtainable"),
]

# repos that contain a compilable Applet subclass but are NOT fuzz targets
# (build tooling / simulators that ship example or internal applets)
KNOWN_NON_TARGET = {
    "martinpaljak/ant-javacard": "build-task repo; only trivial test-fixture applets (testapplets.*)",
    "martinpaljak/jcardengine": "Java Card simulator/engine, not a target applet",
}

APPLET_RE = re.compile(r"\bextends\s+(?:javacard\.framework\.)?Applet\b")
PKG_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)
IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)", re.M)


def parse_link(link):
    u = urllib.parse.urlparse(link)
    if "softwareheritage.org" in u.netloc:
        origin = (urllib.parse.parse_qs(u.query).get("origin_url") or [""])[0]
        u = urllib.parse.urlparse(origin)
    if u.netloc.lower() != "github.com":
        return None
    parts = [p for p in u.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1].removesuffix(".git")
    ref = subpath = None
    if len(parts) >= 4 and parts[2] in ("tree", "blob", "commit"):
        ref = parts[3]
        subpath = "/".join(parts[4:]) if len(parts) > 4 else None
    return owner, repo, ref, subpath


def git(args, cwd=None, timeout=120):
    return subprocess.run(["git", *args], cwd=cwd, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def ensure_clone(owner, repo, ref, cache):
    dest = cache / f"{owner}__{repo}"
    url = f"https://github.com/{owner}/{repo}.git"
    if not (dest / ".git").is_dir():
        r = git(["clone", "--depth", "1", "--single-branch", url, str(dest)], timeout=180)
        if r.returncode != 0:
            return None, None, r.stderr.strip().splitlines()[-1] if r.stderr else "clone failed"
    # default branch name (recorded when the link doesn't pin a commit)
    head = git(["symbolic-ref", "--short", "HEAD"], cwd=dest)
    default_ref = head.stdout.strip() or "HEAD"
    used_ref = default_ref
    # if the link pinned a ref, fetch+checkout it (covers commit-pinned repos
    # whose default branch lacks the sources, e.g. MuscleApplet)
    if ref and ref != default_ref:
        f = git(["fetch", "--depth", "1", "origin", ref], cwd=dest, timeout=180)
        if f.returncode == 0:
            git(["checkout", "-q", "FETCH_HEAD"], cwd=dest)
            used_ref = ref
    return dest, used_ref, None


def java_files(root):
    for dp, _, fs in os.walk(root):
        if os.sep + ".git" in dp:
            continue
        for f in fs:
            if f.endswith(".java"):
                yield Path(dp) / f


def source_root_of(applet_file, package):
    """Strip the package path off the applet file's dir -> javac source root."""
    d = applet_file.parent
    if package:
        suffix = os.sep + package.replace(".", os.sep)
        if str(d).endswith(suffix):
            return Path(str(d)[: -len(suffix)])
    return d


def analyze(dest, subpath):
    """Return a build dict for a cloned repo, or a not-buildable dict."""
    applets = []          # (file, package)
    has_android = has_native = has_java = False
    for dp, _, fs in os.walk(dest):
        if os.sep + ".git" in dp:
            continue
        if any(f.endswith((".c", ".h")) for f in fs):
            has_native = True
        for f in fs:
            if not f.endswith(".java"):
                continue
            has_java = True
            t = (Path(dp) / f).read_text(encoding="utf-8", errors="replace")
            if re.search(r"^\s*import\s+android\.", t, re.M):
                has_android = True
            if APPLET_RE.search(t) and "javacard.framework" in t and "import android." not in t:
                m = PKG_RE.search(t)
                applets.append((Path(dp) / f, m.group(1) if m else ""))

    # drop applets that live inside an Android project tree (HCE reimplementations,
    # not on-card applets) -- e.g. Virtual-Keycard's Muscle_Card_on_Android
    applets = [(fp, pkg) for fp, pkg in applets if "android-projects" not in str(fp).split(os.sep)]

    if not applets:
        if has_android:
            reason = "Android app (HCE); no on-card Java Card applet"
        elif has_native and not has_java:
            reason = "native/host code; no Java Card applet"
        elif has_java:
            reason = "no javacard.framework.Applet subclass (library/tooling)"
        else:
            reason = "no Java sources"
        return {"buildable": False, "reason": reason}

    # choose the target applet: prefer one under the link's subpath
    target = None
    if subpath:
        for fp, pkg in applets:
            if subpath.split("/")[-1] in str(fp) or subpath.replace("/", os.sep) in str(fp):
                target = (fp, pkg)
                break
    if target is None:
        target = applets[0]
    _, applet_package = target

    # source roots: unique roots derived from every detected applet, but only
    # those that are an ancestor of the target root (avoids pulling bundled SDK
    # samples that live under a different tree, e.g. SIC's java_card_kit).
    target_root = source_root_of(target[0], target[1])
    roots = {target_root}
    for fp, pkg in applets:
        r = source_root_of(fp, pkg)
        if r == target_root or str(r).startswith(str(target_root) + os.sep) or str(target_root).startswith(str(r) + os.sep):
            roots.add(r)
    # keep the shallowest root(s)
    roots = sorted(str(r.relative_to(dest)) for r in roots)
    roots = [r for r in roots if not any(r != o and r.startswith(o + "/") for o in roots)] or roots

    # packages declared ANYWHERE in the repo -> imports of these are internal
    # (avoids false-flagging a repo's own helper packages that live in a
    # different source tree than the applet).
    internal_pkgs = set()
    for jf in java_files(dest):
        m = PKG_RE.search(jf.read_text(encoding="utf-8", errors="replace"))
        if m:
            internal_pkgs.add(m.group(1))

    # scan imports under the chosen source root(s) -> extra libs + notes
    extra, notes, external = [], [], set()
    jdk = "8"
    for sd in (dest / r for r in roots):
        for jf in java_files(sd):
            t = jf.read_text(encoding="utf-8", errors="replace")
            for imp in IMPORT_RE.findall(t):
                if "com.sun.org.apache.xml.internal" in imp and "JDK-internal" not in " ".join(notes):
                    notes.append("uses JDK-internal com.sun.org.apache.xml.internal.* (present only in JDK <=8)")
                matched = False
                for prefix, token, runnable, note in IMPORT_LIBS:
                    if imp.startswith(prefix):
                        matched = True
                        if token not in extra:
                            extra.append(token)
                        if note and note not in notes:
                            notes.append(note)
                if matched or imp.startswith(JC_STD) or imp.startswith(IGNORE_IMPORT_PREFIXES):
                    continue
                pkg = imp.rsplit(".", 1)[0]
                if pkg in internal_pkgs or any(imp.startswith(p + ".") for p in internal_pkgs):
                    continue
                external.add(pkg)

    return {
        "buildable": True,
        "method": "javac",
        "source_roots": roots,
        "applet_package": applet_package,
        "required_libs": BASE_LIBS + extra,
        "jdk": jdk,
        "_external": sorted(external),   # consumed by main() to decide method
        "_notes": notes,                 # base notes; main() finalizes
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "jcsmartscan-clones")
    ap.add_argument("--only", default=None, help="only process entries whose link/name contains this substring")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)

    data = json.loads(DATASET.read_text(encoding="utf-8"))
    targets = [e for e in data if set(e["build_systems"]) & TARGET_BUILD_SYSTEMS]
    if args.only:
        targets = [e for e in targets if args.only in e["link"] or args.only in e["name"]]
    print(f"{len(targets)} target entries", file=sys.stderr)

    review = []
    for i, e in enumerate(targets, 1):
        parsed = parse_link(e["link"])
        if not parsed:
            e["fuzz_build"] = {"buildable": False, "reason": "non-GitHub / unresolvable link"}
            continue
        owner, repo, ref, subpath = parsed
        dest, used_ref, err = ensure_clone(owner, repo, ref, args.cache)
        if err:
            e["fuzz_build"] = {"buildable": False, "reason": f"repository unavailable ({err})"}
            print(f"[{i}/{len(targets)}] {owner}/{repo}: UNAVAILABLE ({err})", file=sys.stderr)
            continue
        slug = f"{owner}/{repo}"
        if slug in KNOWN_NON_TARGET:
            b = {"buildable": False, "reason": KNOWN_NON_TARGET[slug]}
        else:
            b = analyze(dest, subpath)
        b["repo_url"] = f"https://github.com/{owner}/{repo}.git"
        b["git_ref"] = ref if (ref and ref == used_ref) else used_ref
        # finalize method + notes for analyzed (buildable) entries. Genuine
        # external deps -> use the repo's DECLARED native build (from
        # build_systems) to resolve the classpath; else keep javac + a warning.
        if "_notes" in b:
            ext = b.pop("_external", [])
            notes = b.pop("_notes", [])
            native = [x for x in ("Maven", "Gradle", "Ant") if x in e["build_systems"]]
            if ext and native:
                tool = {"Maven": "maven", "Gradle": "gradle", "Ant": "ant"}[native[0]]
                b["method"] = "native-classpath"
                b["native"] = {"tool": tool}
                notes.append(f"non-standard deps ({', '.join(ext[:6])}) -- resolved via the "
                             f"repo's {tool} build (method native-classpath)")
            elif ext:
                notes.append("non-standard imports not covered by known libs "
                             "(may need extra jars): " + ", ".join(ext[:8]))
            b["notes"] = "; ".join(notes) or None
        # order keys nicely
        order = ["buildable", "reason", "method", "repo_url", "git_ref",
                 "source_roots", "applet_package", "required_libs", "native", "jdk", "notes"]
        e["fuzz_build"] = {k: b[k] for k in order if k in b}
        tag = "OK  " if b["buildable"] else "SKIP"
        print(f"[{i}/{len(targets)}] {tag} {owner}/{repo}: "
              + (f"roots={b.get('source_roots')} libs={b.get('required_libs')}" if b["buildable"] else b["reason"]),
              file=sys.stderr)
        if not b["buildable"] or (b.get("notes")):
            review.append((e["name"], e["fuzz_build"].get("reason") or b.get("notes")))

    if args.dry_run:
        print("\n--dry-run: dataset.json not modified", file=sys.stderr)
    else:
        out = [{k: e[k] for k in FIELD_ORDER if k in e} for e in data]
        DATASET.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"\nwrote {DATASET}", file=sys.stderr)

    from collections import Counter
    c = Counter(("buildable" if e.get("fuzz_build", {}).get("buildable") else "not-buildable")
                for e in targets)
    print(f"\nsummary: {dict(c)}", file=sys.stderr)
    print("review (not-buildable / with notes):", file=sys.stderr)
    for name, why in review:
        print(f"  - {name}: {why}", file=sys.stderr)


if __name__ == "__main__":
    main()
