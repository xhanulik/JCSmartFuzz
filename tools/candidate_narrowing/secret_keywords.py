#!/usr/bin/env python3
"""
Shared "does this name look like secret material or crypto" keyword
regexes, used by all three prefilter signal sources
(prefilter_idiom_signals.py, prefilter_dataflow_signals.py,
prefilter_name_signals.py) so the keyword list is maintained in exactly
one place instead of drifting apart across copies.
"""
import re

SECRET_RE = re.compile(
    r"(?i)\b(pin|secret|passwd|password|privkey|priv_key|prkey|apdukey|"
    r"cryptokey|key|sessionkey|session_key|skey)\w*"
)

CRYPTO_METHOD_RE = re.compile(
    r"(?i)(encrypt|decrypt|sign|verify|mac|hash|derive|kdf|checkpin|verifypin|comparepin)"
)


def name_matches(name):
    return bool(name) and bool(SECRET_RE.search(name))
