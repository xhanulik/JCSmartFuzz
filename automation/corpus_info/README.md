# automation/corpus_info

Corpus statistics over [`corpus/dataset.json`](../../corpus/dataset.json).

```bash
python3 corpus_stats.py          # text report
python3 corpus_stats.py --json   # machine-readable
```

Reports usable-repo counts (from each repo's `fuzz_build` metadata), build-system
and category distributions, the extra libraries usable repos need, and the
reasons the rest can't build.
