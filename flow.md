1. Install javalang and start virtual environment:
python3 -m venv .venv
source .venv/bin/activate
pip install javalang

2. Clone target repo
git clone https://github.com/OpenCryptoProject/JCMathLib.git

3. Parse applets ource code to obtain AST and symbol table
python3  ~/devel/JCSmartScan/pipeline/analyze/ast_symtab/extract.py JCMathLib/applet/src/main/java/opencrypto/jcmathlib/ -o ast_out
→ast_out/symbol_table.json
→ast_out/methods.jsonl
→ast_out/call_graph.json

4. Narrow number of method candidates based on idioms matching
python3 ~/devel/JCSmartScan/pipeline/analyze/candidate_narrowing/prefilter_rank_candidates.py ast_out/methods.jsonl -o candidates.jsonl
→candidates.jsonl

5. Narrow number of method candidates based on LLM decision from pre-filtered candidates
LLM_API_TOKEN=xxx python3 ~/devel/JCSmartScan/pipeline/analyze/candidate_narrowing/llm_final_verdict.py ast_out/methods.jsonl --candidates candidates.jsonl -o verdicts.jsonl
→verdicts.jsonl
→No candidate is suitable

6. Narrow number of method candidates based on LLM decision from all methods
LLM_API_TOKEN=xxx python3 ~/devel/JCSmartScan/pipeline/analyze/candidate_narrowing/llm_final_verdict.py ast_out/methods.jsonl -o verdicts.jsonl
→verdicts.jsonl

7. Filter best methods for testing
python3 ~/devel/JCSmartScan/pipeline/analyze/candidate_narrowing/filter_verdicts.py verdicts.jsonl
→filtered_verdicts.jsonl

<applet src tree>
      │  ast_symtab/extract.py
      ▼
ast_out/methods.jsonl        ← THE central artifact: one JSON record per method
ast_out/symbol_table.json      (class → package/fields index)
ast_out/call_graph.json        (resolved caller→callee edges)
      │
      │  candidate_narrowing/prefilter_rank_candidates.py   (reads methods.jsonl)
      ▼
candidates.jsonl             ← ranked shortlist w/ fired static rules
      │
      │  candidate_narrowing/llm_final_verdict.py   (methods.jsonl + candidates.jsonl)   ← LLM
      ▼
verdicts.jsonl               ← per-method security verdict {is_security_relevant, severity, …}
errors.jsonl                   (replies that failed the schema/retry gate)
      │
      │  candidate_narrowing/filter_verdicts.py   (reads verdicts.jsonl)
      ▼
filtered_verdicts.jsonl      ← is_security_relevant only, ranked, top-N  → the Stage-2 work list

---

8. Extract context
python3 ~/devel/JCSmartScan/pipeline/harness/harness_extraction/extract_context.py ~/test/JCMathLib/applet/src/main/java/opencrypto/jcmathlib/ ast_out --verdicts filtered_verdicts.jsonl -o context.json
→context.json

9. Generate core and wrapper methods
LLM_API_TOKEN=xxx python3 ~/devel/JCSmartScan/pipeline/harness/harness_extraction/llm_extract_operation.py context.json -o operation.json
→operation.json

10. Generate fuzzing harness
python3 ~/devel/JCSmartScan/pipeline/harness/harness_extraction/assemble_harness.py context.json operation.json -o generated/
→generated/<Class>.<method>/FuzzApplet<Op>.java
→generated/<Class>.<method>/FuzzDriver<Op>.java

<src> + ast_out/{methods,symbol_table}.json + filtered_verdicts.jsonl
      │  extract_context.py --verdicts        (deterministic; one entry per relevant method)
      ▼
context.json                 ← JSON LIST: per-method {target source, helper_imports,
      │                          constants, error_codes, fields+init_line, ins_byte, verdict_hint}
      │  llm_extract_operation.py             ← LLM (one call per list element) + fidelity gate
      ▼
operation.json               ← JSON LIST: per-method {operation_name, ins_name, timing_risk,
      │                          core_method, wrapper_method}, each tagged with {class, method}
operation_errors.json          (methods that failed the gate — skipped, batch continues)
      │
      │  assemble_harness.py context.json operation.json   (+ skeletons/*.java templates)
      ▼
generated/<Class>.<method>/FuzzApplet<Op>.java
generated/<Class>.<method>/FuzzDriver<Op>.java     ← one harness pair PER method (each/each)

---

11. Build fuzzing setup

python3 ~/devel/JCSmartScan/automation/fuzz_build/build_target.py --entry "JCMathLib"  --harness-out generated/<Class>.<method>/

12. Instrument binaries

export JAVA8=/usr/lib/jvm/java-8-openjdk-amd64
$JAVA8/bin/java -cp $KELINCI edu.cmu.sv.kelinci.instrumentor.Instrumentor -i $CLASSES -o bin-instr -skipmain
