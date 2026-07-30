# automation/fuzz_build

Compile a corpus applet + its harness `FuzzApplet`/`FuzzDriver` into `.class`
files for fuzzing, driven by the per-repo `fuzz_build` metadata in
[`corpus/dataset.json`](../../corpus/dataset.json).

## Setup (once)

Edit `build_libs.json` to point the library tokens at jars on your machine
(`jcardsim`, `kelinci`, `bouncycastle`, plus any extra API jars a repo needs).
`kelinci.jar` isn't on Maven — build it from [`engine/diffuzz`](../../engine/diffuzz).

## build_target.py — build one target

```bash
python3 build_target.py --entry "<name|link substring>" \
    --harness-out <dir with FuzzApplet*/FuzzDriver*.java> \
    [--work DIR] [--libs build_libs.json] [--dry-run]
```

Clones the repo, drops the harness `Fuzz*.java` into the applet package, runs
`javac`, then prints `$CLASSES` and the copy-paste Part-2 (Kelinci/AFL++)
commands with `KELINCI`/`JCARDSIM`/`BC` resolved. `--harness-out` is the output of
`assemble_harness.py` — per method, `.../generated/<Class>.<method>/`.
`--dry-run` prints the plan without cloning or compiling.

> Run the printed Part-2 commands with **JDK 8** (Kelinci's instrumentor fails on
> JDK 9+): `sudo apt-get install -y openjdk-8-jdk`,
> `export JAVA8=/usr/lib/jvm/java-8-openjdk-amd64`, and prefix each with
> `$JAVA8/bin/java`.

## discover_builds.py — populate the metadata (one-off)

```bash
python3 discover_builds.py [--cache DIR] [--only SUBSTR] [--dry-run]
```

Clones each corpus repo and writes its `fuzz_build` object (source roots, applet
package, `required_libs`, git ref) back into `dataset.json`. Idempotent.
