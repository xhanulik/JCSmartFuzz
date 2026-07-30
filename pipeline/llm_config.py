"""Central LLM-backend configuration for the pipeline.

All LLM-calling stages (analyze/candidate_narrowing, harness/harness_extraction,
seeds/initial, seeds/sidecar) read their endpoint / model / timeout / token
through this module instead of hardcoding a specific provider.

Resolution order for every value (first hit wins):
    1. environment variable   (LLM_ENDPOINT, LLM_MODEL, LLM_TIMEOUT, LLM_API_TOKEN)
    2. llm_config.ini          ([llm] section: endpoint, model, timeout, api_token)
    3. built-in default        (only timeout has one; see _DEFAULTS)

`llm_config.ini` is git-ignored so a local endpoint/model/token is never
committed. Copy `llm_config.ini.example` to `llm_config.ini` and edit it, or
export the environment variables. The .ini is located by walking up from this
file to the repo root, so it is found regardless of the caller's cwd.
"""
import configparser
import os
from pathlib import Path

# config key -> overriding environment variable
_ENV = {
    "endpoint": "LLM_ENDPOINT",
    "model": "LLM_MODEL",
    "timeout": "LLM_TIMEOUT",
    "api_token": "LLM_API_TOKEN",
}

# last-resort defaults (endpoint/model deliberately have none: they identify the
# backend and must be supplied via env var or llm_config.ini)
_DEFAULTS = {
    "timeout": "120",
}

_CONFIG_FILENAME = "llm_config.ini"
_EXAMPLE_FILENAME = "llm_config.ini.example"
_file_values = None


def _load_file_values():
    """Read the [llm] section of the first llm_config.ini found walking up from
    this file. Cached; returns {} when no file exists."""
    global _file_values
    if _file_values is None:
        _file_values = {}
        for base in Path(__file__).resolve().parents:
            candidate = base / _CONFIG_FILENAME
            if candidate.is_file():
                cp = configparser.ConfigParser(interpolation=None)
                cp.read(candidate, encoding="utf-8")
                if cp.has_section("llm"):
                    _file_values = {k: v for k, v in cp.items("llm")}
                break
    return _file_values


def get(key, default=None):
    """Resolve one config value: env var > llm_config.ini > _DEFAULTS > default.
    Returns None if nothing supplies it. Empty strings in the file are ignored."""
    env_name = _ENV.get(key)
    if env_name:
        env_val = os.environ.get(env_name)
        if env_val:
            return env_val
    file_val = _load_file_values().get(key)
    if file_val:
        return file_val
    if default is not None:
        return default
    return _DEFAULTS.get(key)


def _require(key):
    val = get(key)
    if not val:
        raise RuntimeError(
            f"LLM {key} is not configured. Set the {_ENV[key]} environment "
            f"variable, or add '{key} = ...' under [llm] in {_CONFIG_FILENAME} "
            f"(copy {_EXAMPLE_FILENAME} to get started)."
        )
    return val


def endpoint():
    """OpenAI-compatible chat-completions URL. Required."""
    return _require("endpoint")


def model():
    """Default model name. Required (override per-run with --model)."""
    return _require("model")


def timeout():
    """Request timeout in seconds (default 120)."""
    return float(get("timeout"))


def api_token():
    """Bearer token, or None if unset (callers decide whether it's required)."""
    return get("api_token")
