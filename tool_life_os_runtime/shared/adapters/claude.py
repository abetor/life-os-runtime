"""Claude Code CLI adapter vendored from the tool template.

Its flag behavior was validated in live orchestration and research workloads.
Do not change it without a live compatibility check.

`claude -p --output-format json [...] -- "prompt"` -> stdout single-json:
{result, session_id, total_cost_usd, is_error, subtype, ...}.

Validated facts:
- the schema is supplied inline with ``--json-schema``, not by path;
- ``--`` before the prompt is required because ``--allowedTools`` greedily
  consumes the next positional argument and otherwise reports "Input must be provided";
- resume uses the ``--resume <session_id>`` flag;
- ``claude -p`` uses subscription quota, but issue #43333 documents silent API
  billing, so callers should record usage and compare it with expectations.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .base import Capabilities, HarnessAdapter, RunResult

# The default whitelist permits web and read operations but not project writes.
# This is an enforced read-only boundary. Supply explicit allowed_tools to a writer.
READ_ONLY_TOOLS = "WebSearch WebFetch Read Grep Glob LS"


class ClaudeAdapter(HarnessAdapter):
    name = "claude"

    def __init__(self, binary: str = "claude"):
        self.binary = binary

    def capabilities(self) -> Capabilities:
        return Capabilities(json_events=True, schema_output=True, native_resume=True,
                            subagents=True, mcp=True)

    def build_cmd(self, prompt, *, model=None, effort=None, resume_session_id=None,
                  schema_path=None, system_prompt_path=None, allowed_tools=None):
        cmd = [self.binary, "-p", "--output-format", "json",
               "--permission-mode", "default"]
        if model:
            cmd += ["--model", model]
        # In non-interactive -p with mode=default, a tool outside the whitelist
        # cannot run because nobody can approve it. The whitelist is the call's
        # capability boundary.
        cmd += ["--allowedTools", allowed_tools or READ_ONLY_TOOLS]
        if effort:
            cmd += ["--effort", effort]
        if system_prompt_path:
            # Append a separate system prompt without clobbering project CLAUDE.md.
            cmd += ["--append-system-prompt-file", system_prompt_path]
        if resume_session_id:
            cmd += ["--resume", resume_session_id]
        if schema_path:
            schema = Path(schema_path).read_text("utf-8").strip()
            if not schema:
                raise ValueError(f"empty schema {schema_path}; refusing an unconstrained call")
            cmd += ["--json-schema", schema]  # Claude takes inline JSON; Codex takes a path.
        cmd += ["--", prompt]
        return cmd

    def parse_output(self, stdout, exit_code) -> RunResult:
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, ValueError):
            # Preserve non-JSON output from a pre-format crash.
            return RunResult(ok=exit_code == 0 and bool(stdout.strip()),
                             text=stdout, exit_code=exit_code)
        ok = exit_code == 0 and not data.get("is_error", False)
        return RunResult(ok=ok, text=data.get("result") or "", exit_code=exit_code,
                         session_id=data.get("session_id"),
                         cost_usd=data.get("total_cost_usd"), raw=data)

    def quota_patterns(self) -> re.Pattern:
        # Observed JSON subtype forms for subscription and API limits.
        return re.compile(r"error_max_turns|resets at|upgrade to|claude usage", re.I)
