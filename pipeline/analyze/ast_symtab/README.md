# Construction of AST and symbol table

AST + symbol-table extractor for Java Card applet source trees, producing
per-method context records intended to be fed to an LLM for method-by-method
review (bounds checks, transient array misuse, PIN/crypto handling, etc.).

## How it works

1. Recursively finds all `.java` files under the input directory.
2. Parses each with [`javalang`](https://github.com/c2nes/javalang) (pure
   Python, no JVM/Maven/JDT required).
3. **Pass 1 (symbol table):** records every class/interface/enum with its
   package, `extends`/`implements`, declared fields (name -> type) and method
   signatures (name -> list of overload signatures).
4. **Pass 2 (per-method extraction):** for every method **and constructor**
   (constructors are recorded with `"method": "<init>"`, giving their field
   initialization lines via the same `field_dataflow` analysis described
   below), resolves as much as
   it can using the symbol table built in pass 1:
   - unqualified calls -> same class (or framework/external if not found)
   - `this.x()` / bare `x()` -> same class
   - `obj.x()` where `obj` is a local var, parameter, or field with a known
     declared type -> that type's class
   - anything else is marked `"external": true` (framework APIs like
     `javacard.framework.*`, `javacardx.*`, or unresolved 3rd-party calls)
5. Extracts a brace-matched source snippet per method, plus locals, field
   reads/writes, and throws clause.
6. Emits `methods.jsonl` (one JSON object per method — feed this to an LLM,
   one record per prompt or batched), `symbol_table.json` (class index), and
   `call_graph.json` (resolved caller -> callee edges, internal calls only).

This is a lightweight, best-effort resolver — not a full compiler frontend.
It does not do generic type inference, overload resolution by argument
types, or classpath-based resolution against the real Java Card SDK jars.
For calls into `javacard.framework`/`javacardx.*` etc., these correctly show
up as `"external": true` since those classes aren't declared in-repo.
Unqualified/`this.` calls resolve through the superclass chain, so
inherited-method calls are not misclassified as external.

Each line of `methods.jsonl` is a self-contained review unit that can be used
for LLM testing. For richer per-method prompts, join in `call_graph.json` to
attach callee signatures/snippets, or `symbol_table.json` to attach the full
field list of `class` for context on what state the method can touch.

### Per-method fields deterministically resolvable from the table

- **`params`** — exact declared parameter types (no inference needed; taken
  straight from the AST).
- **`field_dataflow`** — every non-local (own class + inherited) field the
  method touches, with reads/writes counts and a `classification`:
  - `read_before_write` — the field's value is consumed before this method
    ever assigns it → a candidate for external/fuzz input.
  - `written_first` — the method assigns the field before reading it →
    internal state the method produces, not consumes.
  Computed via a single deterministic lexical DFS over the method body (see
  docstring in `extract.py` for the exact, documented approximations around
  branches/loops and shadowing).
- **`transitive_calls`** / **`transitive_private_helpers`** — the full
  reachable closure of internally-resolved callees from this method (not
  just direct calls), with `transitive_private_helpers` restricted to
  callees whose declaration is `private`. `recursive: true` marks methods
  that transitively call themselves (including through overload-name
  collisions — see docstring).

## Output format

Three files are written (all built in `extract.py`'s `main()`). Types below
use `<...>` for placeholders; every "type" string is `type_to_str`'d (array
dimensions become a trailing `[]`, `void` for none).

### `symbol_table.json` — the class index

A single object keyed by **simple class name** (built at
`extract.py` `main()`, from `ClassInfo`):

```json
{
  "PinApplet": {
    "package": "com.example",           // "" when the file has no package
    "kind": "class",                    // "class" | "interface" | "enum"
    "extends": "Applet",                // string; a list for multi-extends interfaces; null if none
    "implements": ["ISO7816"],          // [] if none
    "fields": { "referencePin": "byte[]", "triesLeft": "byte" },
    "methods": {
      "checkPin": [                       // one entry PER overload (keyed by name only)
        { "return_type": "boolean", "params": [["pin", "byte[]"]], "modifiers": ["private"] }
      ],
      "<init>": [                         // constructors are stored under "<init>"
        { "return_type": "void", "params": [["len", "short"]], "modifiers": ["public"] }
      ]
    }
  }
}
```

Note: in `symbol_table.json`, `params` are **`[name, type]` pairs** (2-element
arrays). In `methods.jsonl` below, `params` are **`{name, type}` objects** —
the two files differ here.

### `methods.jsonl` — one JSON object per line (the central artifact)

One record per method **and** per constructor (`"method": "<init>"`). Built by
`_extract_one`, then enriched with the call-graph fields in `main()`:

```json
{
  "file": "src/PinApplet.java",
  "class": "PinApplet",
  "method": "checkPin",                 // or "<init>" for a constructor
  "modifiers": ["private"],
  "return_type": "boolean",             // "void" for constructors
  "params":  [ { "name": "pin",  "type": "byte[]" } ],
  "throws":  [ "ISOException" ],         // [] if none
  "locals":  [ { "name": "i",    "type": "short" } ],
  "field_dataflow": [
    {
      "field": "referencePin",
      "owner_class": "PinApplet",        // declaring class (own or inherited)
      "type": "byte[]",
      "reads": 1,
      "writes": 0,
      "first_access": "read",            // "read" | "write"
      "classification": "read_before_write"   // "read_before_write" | "written_first"
    }
  ],
  "calls": [
    {
      "qualifier": "Util",               // the receiver text, or null for bare/this calls
      "method": "arrayCompare",
      "resolved_owner": "javacard.framework.Util",  // in-repo class, import FQN, or null
      "external": true                   // true when resolved_owner is not an in-repo class
    }
  ],
  "start_line": 42,                       // null if the node has no position
  "source": "boolean checkPin(byte[] pin) { ... }",   // verbatim brace-matched snippet; null if no start_line
  "transitive_calls": ["PinApplet.compare"],          // full internal-call closure (not just direct)
  "recursive": false,                                 // true if the method transitively calls itself
  "transitive_private_helpers": ["PinApplet.compare"] // subset of transitive_calls that are private
}
```

### `call_graph.json` — resolved edges (internal calls only)

Nodes are `"Class.method"` strings; overloads collapse to one node per
`(class, name)`:

```json
{
  "direct":      { "PinApplet.checkPin": ["PinApplet.compare"] },
  "transitive":  { "PinApplet.checkPin": ["PinApplet.compare"] },
  "recursive_methods": ["PinApplet.mix"],
  "transitive_private_helpers": { "PinApplet.checkPin": ["PinApplet.compare"] }
}
```

## Usage

```
pip install javalang
python extract.py <path_to_applet_src_dir> [-o output_dir]
```

Default output dir is `<src_dir>/../ast_out`.
