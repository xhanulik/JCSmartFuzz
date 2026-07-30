#!/usr/bin/env python3
"""Compile a corpus applet + the harness-generated FuzzApplet/FuzzDriver into
runnable .class files, driven entirely by the per-repo `fuzz_build` object in
corpus/dataset.json (populated by discover_builds.py).

Flow: look up the entry -> clone repo at fuzz_build.git_ref -> drop the harness
FuzzApplet<Op>/FuzzDriver<Op> into the applet package -> resolve fuzz_build.required_libs
to jars via build_libs.json -> compile (fuzz_build.method) -> print $CLASSES and the
Part-2 (Kelinci/AFL++) commands from automation/README.md.

Usage:
    python3 build_target.py --entry "<name|link substring>" \\
        --harness-out <dir with FuzzApplet*.java/FuzzDriver*.java> \\
        [--work DIR] [--libs build_libs.json] [--dry-run]

--dry-run resolves and prints the full plan + compile command without cloning
or compiling (works with no jars present).
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
DATASET = REPO_ROOT / "corpus" / "dataset.json"
DEFAULT_LIBS = HERE / "build_libs.json"


def find_entry(data, key):
    hits = [e for e in data if key == e["name"] or key in e["link"] or key in e["name"]]
    if len(hits) != 1:
        sys.exit(f"error: --entry {key!r} matched {len(hits)} entries; be more specific")
    return hits[0]


def lib_path(token, libs_map):
    """Absolute path for a single token (relative paths resolve against repo
    root), or None if the token is not mapped."""
    p = libs_map.get(token)
    if not p:
        return None
    path = Path(p)
    return str(path if path.is_absolute() else REPO_ROOT / path)


def resolve_libs(tokens, libs_map):
    """token -> absolute jar path (relative paths resolve against repo root).
    Returns (resolved_paths, missing_tokens)."""
    resolved, missing = [], []
    for tok in tokens:
        path = lib_path(tok, libs_map)
        if not path:
            missing.append(tok); continue
        resolved.append(path)
        if not Path(path).exists():
            missing.append(tok)
    return resolved, missing


def git(args, cwd=None, timeout=180):
    return subprocess.run(["git", *args], cwd=cwd, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def clone(build, work):
    dest = work / re.sub(r"[^\w.-]", "_", build["repo_url"].rstrip("/").split("/")[-1].removesuffix(".git"))
    if not (dest / ".git").is_dir():
        r = git(["clone", "--depth", "1", "--single-branch", build["repo_url"], str(dest)])
        if r.returncode != 0:
            sys.exit(f"error: clone failed: {r.stderr.strip()}")
    ref = build.get("git_ref")
    if ref:
        head = git(["symbolic-ref", "--short", "HEAD"], cwd=dest).stdout.strip()
        if ref != head:
            f = git(["fetch", "--depth", "1", "origin", ref], cwd=dest)
            if f.returncode == 0:
                git(["checkout", "-q", "FETCH_HEAD"], cwd=dest)
    return dest


def place_harness_files(harness_out, dest, source_root):
    """Copy FuzzApplet*/FuzzDriver*.java into <source_root>/<their package path>/.
    Returns (driver_class_name, placed_paths)."""
    files = sorted(Path(harness_out).glob("Fuzz*.java"))
    if not files:
        sys.exit(f"error: no Fuzz*.java found in --harness-out {harness_out}")
    placed, driver_class = [], None
    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.M)
        pkg = m.group(1) if m else ""
        dst_dir = Path(source_root) / pkg.replace(".", os.sep)
        dst_dir.mkdir(parents=True, exist_ok=True)
        dst = dst_dir / f.name
        shutil.copy2(f, dst)
        placed.append(dst)
        if f.name.startswith("FuzzDriver"):
            driver_class = f.stem
    return driver_class, placed


def part2_hint(driver_class, classes_dir, libs_map):
    driver = driver_class or "FuzzDriver<Op>"
    # The Part-2 commands need the same kelinci/jcardsim/bouncycastle jars the
    # compile used -- emit their export lines (resolved from build_libs.json) so
    # the block is copy-paste runnable, not just a template with bare $VARS.
    kelinci = lib_path("kelinci", libs_map) or "<set kelinci jar in build_libs.json>"
    jcardsim = lib_path("jcardsim", libs_map) or "<set jcardsim jar in build_libs.json>"
    bc = lib_path("bouncycastle", libs_map) or "<set bouncycastle jar in build_libs.json>"
    return f"""
Next (Part 2 -- identical for every build system, see automation/README.md):
  # Kelinci's instrumentor uses the Java-8 URLClassLoader classpath hack and
  # throws "Error adding location to class path" on JDK 9+, so run Part 2 with
  # JDK 8: install it alongside (sudo apt-get install -y openjdk-8-jdk) and
  # point JAVA8 at it. The Part-1 javac and Python stages stay on your default JDK.
  export JAVA8=/usr/lib/jvm/java-8-openjdk-amd64   # adjust to your JDK 8 path
  export CLASSES={classes_dir}
  export KELINCI={kelinci}
  export JCARDSIM={jcardsim}
  export BC={bc}
  $JAVA8/bin/java -cp $KELINCI edu.cmu.sv.kelinci.instrumentor.Instrumentor -i $CLASSES -o bin-instr -skipmain
  mkdir -p in out && touch in/testcase
  $JAVA8/bin/java -cp bin-instr:$JCARDSIM {driver} in/testcase
  $JAVA8/bin/java -cp bin-instr:$JCARDSIM:$BC edu.cmu.sv.kelinci.Kelinci {driver} @@
  <engine>/afl-fuzz -i in -o out <engine>/fuzzerside/interface @@
"""


def native_resolve_desc(tool):
    """Human-readable description of how method=native-classpath resolves deps."""
    return {
        "maven": "mvn dependency:build-classpath (compile scope)",
        "gradle": "gradle printFuzzCp (runtimeClasspath via init script)",
        "ant": "collect lib/**/*.jar from the repo",
    }.get(tool, f"resolve via {tool}")


def resolve_native_classpath(tool, dest):
    """Use the repo's own build tool ONLY to resolve its dependency classpath
    (lightweight hybrid); the actual fuzzing compile is still javac. Returns a
    list of jar paths, or raises on failure."""
    if tool == "maven":
        out = dest / ".fuzz_cp.txt"
        r = subprocess.run(["mvn", "-q", "-DincludeScope=compile",
                            "dependency:build-classpath", f"-Dmdep.outputFile={out}"],
                           cwd=dest, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if not out.exists():
            raise RuntimeError(f"maven classpath resolution failed:\n{r.stdout[-1500:]}")
        return [p for p in out.read_text().strip().split(os.pathsep) if p]
    if tool == "gradle":
        init = dest / ".fuzz_init.gradle"
        init.write_text("allprojects { tasks.register('printFuzzCp') { doLast { "
                        "try { println configurations.runtimeClasspath.asPath } catch (e) {} } } }\n")
        gradle = "./gradlew" if (dest / "gradlew").exists() else "gradle"
        r = subprocess.run([gradle, "-q", "--console=plain", "-I", str(init), "printFuzzCp"],
                           cwd=dest, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        lines = [l for l in r.stdout.splitlines() if ".jar" in l and os.pathsep in l]
        if not lines:
            raise RuntimeError(f"gradle classpath resolution failed:\n{r.stdout[-1500:]}")
        return [p for p in lines[-1].split(os.pathsep) if p]
    if tool == "ant":
        jars = [str(p) for p in dest.rglob("*.jar") if "lib" in p.parts]
        if not jars:
            raise RuntimeError("ant: no lib/**/*.jar found to build a dependency classpath")
        return jars
    raise RuntimeError(f"unknown native tool {tool!r}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--entry", required=True, help="corpus entry name or link substring")
    ap.add_argument("--harness-out", type=Path, help="dir with FuzzApplet*/FuzzDriver*.java (required unless --dry-run)")
    ap.add_argument("--work", type=Path, default=Path.home() / ".cache" / "jcsmartscan-builds")
    ap.add_argument("--libs", type=Path, default=DEFAULT_LIBS)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    data = json.loads(DATASET.read_text(encoding="utf-8"))
    entry = find_entry(data, args.entry)
    build = entry.get("fuzz_build")
    if not build:
        sys.exit(f"error: entry {entry['name']!r} has no fuzz_build metadata (run discover_builds.py)")
    if not build.get("buildable"):
        sys.exit(f"error: {entry['name']!r} is not buildable: {build.get('reason')}")
    method = build.get("method", "javac")
    if method not in ("javac", "native-classpath"):
        sys.exit(f"error: unknown build method {method!r}")
    native_tool = (build.get("native") or {}).get("tool")

    libs_map = json.loads(args.libs.read_text(encoding="utf-8"))
    libs_map = {k: v for k, v in libs_map.items() if not k.startswith("_")}
    classpath, missing = resolve_libs(build["required_libs"], libs_map)

    print(f"entry:        {entry['name']}")
    print(f"repo:         {build['repo_url']} @ {build.get('git_ref')}")
    print(f"method:       {build['method']}  (jdk {build.get('jdk', '8')})")
    print(f"source_roots: {build['source_roots']}")
    print(f"applet_pkg:   {build['applet_package']}")
    print(f"required_libs:{build['required_libs']}")
    if build.get("notes"):
        print(f"notes:        {build['notes']}")
    if missing:
        print(f"UNRESOLVED libs (edit {args.libs.name}): {missing}", file=sys.stderr)

    if args.dry_run:
        roots = " ".join(f"<repo>/{r}" for r in build["source_roots"])
        cp = ":".join(classpath) or "<classpath from build_libs.json>"
        jdk = build.get("jdk", "8")
        print("\n[dry-run] would:")
        print(f"  1. clone {build['repo_url']} @ {build.get('git_ref')}")
        if method == "native-classpath":
            print(f"  2. resolve dependency classpath via {native_tool}: {native_resolve_desc(native_tool)}")
            cp = f"<{native_tool}-resolved deps>:{cp}"
        print(f"  {'3' if method=='native-classpath' else '2'}. copy <harness-out>/Fuzz*.java into "
              f"<repo>/{build['source_roots'][0]}/{build['applet_package'].replace('.', '/')}/")
        print(f"  {'4' if method=='native-classpath' else '3'}. javac -source {jdk} -target {jdk} -cp {cp} \\")
        print(f"           -d <work>/classes $(find {roots} -name '*.java')")
        return

    if not args.harness_out:
        sys.exit("error: --harness-out is required (unless --dry-run)")
    if missing:
        sys.exit(f"error: cannot compile, unresolved libs {missing}; edit {args.libs}")

    args.work.mkdir(parents=True, exist_ok=True)
    dest = clone(build, args.work)
    src_root0 = dest / build["source_roots"][0]
    driver_class, placed = place_harness_files(args.harness_out, dest, src_root0)
    print(f"placed: {[str(p.relative_to(dest)) for p in placed]}")

    if method == "native-classpath":
        print(f"resolving dependency classpath via {native_tool} ...")
        try:
            native_cp = resolve_native_classpath(native_tool, dest)
        except RuntimeError as e:
            sys.exit(f"error: {e}")
        print(f"  resolved {len(native_cp)} dependency jar(s) from the {native_tool} build")
        classpath = native_cp + classpath

    sources = []
    for r in build["source_roots"]:
        sources += [str(p) for p in (dest / r).rglob("*.java")]
    classes_dir = dest / "fuzz-classes"
    classes_dir.mkdir(exist_ok=True)
    jdk = build.get("jdk", "8")
    cmd = ["javac", "-source", jdk, "-target", jdk, "-cp", ":".join(classpath),
           "-d", str(classes_dir), *sources]
    print(f"\ncompiling {len(sources)} sources -> {classes_dir}")
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if r.returncode != 0:
        print(r.stdout, file=sys.stderr)
        sys.exit(f"javac failed (rc={r.returncode})")
    print(f"OK: {sum(1 for _ in classes_dir.rglob('*.class'))} .class files in {classes_dir}")
    print(part2_hint(driver_class, classes_dir, libs_map))


if __name__ == "__main__":
    main()
