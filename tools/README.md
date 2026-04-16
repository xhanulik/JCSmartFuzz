# Fuzzing tools

Submodules containing tools used for differential fuzzing.

## Submodules

### AFLplusplus (branch: `wca`)

Fork of [AFL++](https://github.com/xhanulik/AFLplusplus) with WCA (Worst-Case Analysis) support.

**Build:**

```bash
cd tools/AFLplusplus
make all
sudo make install  # optional, installs system-wide
```

**Dependencies:** GCC, GNU Make, standard C build tools.

### DifFuzz (branch: `afl++`)

[DifFuzz](https://github.com/xhanulik/diffuzz) — a Java-based differential fuzzer built on top of Kelinci, using AFL as the underlying fuzzing engine.

**Build:**

```bash
cd tools/diffuzz
./tool/setup.sh
```

This runs the full build: the AFL fuzzer (`afl-2.51b-wca`), the `fuzzerside` interface, and the Kelinci instrumentor (via Gradle).

**Dependencies:** Git, GCC, GNU Make, Java JDK 1.8+, Gradle, Python 3 with NumPy.

## Updating submodules

Cloning the repo with:

```bash
git clone --recurse-submodules
```

checks out the exact pinned commit, NOT the latest branch tip.
To update to the latest branch version, run:

```bash
git submodule update --remote
```
