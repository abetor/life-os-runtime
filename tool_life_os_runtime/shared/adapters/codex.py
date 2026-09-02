"""OpenAI Codex CLI adapter vendored from the tool template.

The flag behavior was validated in live orchestration and research workloads
with Codex 0.137. Do not change it without a live compatibility check.

`codex exec [resume <id>] --json -c approval_policy=never [--sandbox ...]
[--model M] [-c model_reasoning_effort=E] [-c model_instructions_file=PATH]
[--output-schema PATH] "prompt"` -> stdout is a JSONL event stream
(thread.started/thread_id, item.completed/agent_message, turn.completed/usage).

Validated facts, including production fixes first observed in the research tool:
- ``stdin=DEVNULL`` in ``base.run`` prevents Codex exec from hanging while it
  waits for EOF on inherited stdin;
- ``--skip-git-repo-check`` is required when the tool working directory is not
  a Git repository, otherwise Codex reports "Not inside a trusted directory";
- resume is the ``exec resume <id>`` subcommand and does not accept ``--sandbox``;
  the equivalent mode must be passed with ``-c sandbox_mode=``;
- approval_policy and effort are configuration overrides, not exec flags;
- an output schema is passed by path, unlike Claude's inline schema;
- schema output and resume are incompatible (codex#14343, closed as not planned);
- ChatGPT subscriptions reject Claude model names with a 400 invalid_request,
  so omitting ``--model`` selects the account default;
- Codex reports tokens rather than currency, so cost_usd is None and usage is raw.
"""
from __future__ import annotations

import json
from pathlib import Path

from .base import Capabilities, HarnessAdapter, RunResult

# Claude-family aliases include full claude-* names and short Claude CLI names.
_CLAUDE_ALIASES = {"sonnet", "opus", "haiku"}


def _claude_family(model: str) -> bool:
    m = model.lower()
    return m.startswith("claude") or m in _CLAUDE_ALIASES


class CodexAdapter(HarnessAdapter):
    name = "codex"

    def __init__(self, binary: str = "codex"):
        self.binary = binary

    def capabilities(self) -> Capabilities:
        # Subagents are TOML definitions under .codex/agents; MCP is client and server.
        return Capabilities(json_events=True, schema_output=True, native_resume=True,
                            subagents=True, mcp=True)

    def build_cmd(self, prompt, *, model=None, effort=None, resume_session_id=None,
                  schema_path=None, system_prompt_path=None, allowed_tools=None):
        # Ignore allowed_tools because Codex has no per-tool allowlist; the
        # sandbox mode defines the available capabilities.
        if resume_session_id and schema_path:
            # Fail closed, as with an empty Claude schema: silently discarding a
            # constraint is not allowed. Choose resume with post-validation or a
            # fresh session with schema enforcement.
            raise ValueError("codex: schema and resume are incompatible (codex#14343); choose one")
        cmd = [self.binary, "exec"]
        if resume_session_id:
            cmd += ["resume", resume_session_id]  # Subcommand, not a --resume flag.
            # `exec resume` rejects --sandbox, so use a configuration override.
            sandbox = ["-c", "sandbox_mode=workspace-write"]
        else:
            sandbox = ["--sandbox", "workspace-write"]
        # Autonomous headless run: no approval prompts and workspace write access.
        cmd += ["--json", "-c", "approval_policy=never", *sandbox]
        # A configured working directory may not be a Git repository; without
        # this flag Codex rejects it as
        # "Not inside a trusted directory".
        cmd += ["--skip-git-repo-check"]
        # A Claude-family name produces a 400 invalid_request on a ChatGPT
        # subscription. Omit --model to use the account default; pass explicit
        # Codex model names through unchanged.
        if model and not _claude_family(model):
            cmd += ["--model", model]
        if effort:
            cmd += ["-c", f"model_reasoning_effort={effort}"]  # Config override, not --effort.
        if system_prompt_path:
            cmd += ["-c", f"model_instructions_file={system_prompt_path}"]
        if schema_path:
            schema = Path(schema_path).read_text("utf-8").strip()
            if not schema:
                raise ValueError(f"empty schema {schema_path}; refusing an unconstrained call")
            cmd += ["--output-schema", schema_path]  # Codex takes a path; Claude takes inline JSON.
        cmd.append(prompt)
        return cmd

    def parse_output(self, stdout, exit_code) -> RunResult:
        """Parse Codex JSONL rather than Claude-style single JSON.

        Concatenate text from agent_message content blocks instead of using a
        list repr, map thread_id to session_id, and preserve usage under raw.
        Invalid lines are skipped. If no valid JSON line exists, return an
        explicit unsuccessful result containing the raw output.
        """
        text_parts: list[str] = []
        usage = err = session_id = codex_error_info = None
        parsed_any = False
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(ev, dict):
                continue
            parsed_any = True
            t = ev.get("type")
            if t == "thread.started":
                session_id = ev.get("thread_id")  # Codex equivalent of resume session_id.
                continue
            item = ev.get("item") if isinstance(ev.get("item"), dict) else ev
            if ev.get("codex_error_info") or item.get("codex_error_info"):
                codex_error_info = ev.get("codex_error_info") or item.get("codex_error_info")
            itype = item.get("item_type") or item.get("type")
            if t == "item.completed" and itype == "agent_message":
                txt = item.get("text")
                if txt is None:
                    txt = item.get("content")
                if isinstance(txt, list):
                    txt = "".join(b.get("text", "") for b in txt if isinstance(b, dict))
                if txt:
                    text_parts.append(str(txt))
            elif t == "turn.completed":
                usage = ev.get("usage")
            elif t == "error" or ev.get("is_error"):
                err = str(ev.get("message") or ev.get("error") or "codex error")
        if not parsed_any:
            # A pre-format crash is not JSONL. Preserve it; classify also checks stderr.
            return RunResult(ok=False, text=stdout or "", exit_code=exit_code)
        ok = exit_code == 0 and err is None
        # Preserve err and codex_error_info for base.classify so classification
        # remains centralized rather than duplicated across adapters.
        return RunResult(ok=ok, text="\n".join(text_parts), exit_code=exit_code,
                         session_id=session_id, cost_usd=None,
                         raw={"usage": usage, "error": err or "",
                              "codex_error_info": codex_error_info or ""})
