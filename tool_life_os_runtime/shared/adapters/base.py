"""Harness port for LLM work through interchangeable subscription-backed CLIs.

Vendored from the tool template. Its CLI mechanics were validated in earlier
agent orchestration and research tools, including production fixes to the
Codex adapter and stop classifier. This repository owns the file; change flags
or patterns only after a live compatibility check.

The minimum harness contract is: (1) a headless one-shot process with prompt
and cwd, (2) final text on stdout, and (3) a distinguishable failure. Everything
else is a capability flag. The wrapper emulates absent capabilities instead of
claiming they exist. The done/quota/transient/fatal classifier lives here
because the CLIs expose no machine-readable quota query.
"""
from __future__ import annotations

import re
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

# These patterns are common to CLI harnesses; adapters extend quota_patterns().
#
# CLASS BOUNDARY. An earlier production bug grouped 429 and "rate limit" with
# genuine quota exhaustion. A concurrency burst then produced an ordinary 429,
# the classifier returned quota, the CLI exited 75, and an external driver
# removed the remaining work from its queue even though seconds of waiting would
# have fixed it. Classes must be separated by remedy, not by similar names.
#
# _QUOTA means the subscription budget is exhausted. Only a reset window, often
# hours or days away, fixes it. Match words about the budget, not request rate.
# Observed forms:
# claude - "Claude usage limit reached ... resets at", "You've hit your weekly limit",
# "5-hour limit reached"; codex - "You've hit your usage limit", "out of credits".
# `(?<!rate[ -])\blimit (reached|exceeded)` encodes the narrow boundary: "usage
# limit exceeded" is quota, while "rate limit exceeded", the conventional
# throttling wording of OpenAI-compatible APIs, is not.
_QUOTA = re.compile(r"usage limit|weekly limit|session limit|5-hour|out of credits|quota"
                    r"|(?:hit|reached) your [^.\n]{0,24}limit"
                    r"|(?<!rate[ -])\blimit (?:reached|exceeded)", re.I)
# _TRANSIENT is fixed by retrying after seconds or minutes. Burst throttling
# (429 / "too many requests" / "rate limit") belongs here. Both harnesses treat
# it separately from quota and retry it with backoff themselves, so it reaches
# this layer only after their retries. The right response is to wait longer, not
# stop with a quota checkpoint. For mixed text such as "429: usage limit
# reached", classify checks quota first. This is deliberate: repeatedly hitting
# a real quota is worse than one extra wait, and budget wording is more specific
# than the generic 429 code.
_TRANSIENT = re.compile(r"\b(?:429|500|502|503|529)\b|too many requests|rate.?limit"
                        r"|at capacity|try a different model|server[_ -]?overloaded|\boverloaded\b|timed?.?out|connection|"
                        r"temporarily|try again|ECONNRESET|EAI_AGAIN", re.I)

# Map stop classes to the CLI exit-code contract.
STOP_TO_EXIT = {"done": 0, "quota": 75, "transient": 111, "fatal": 1}


@dataclass
class Capabilities:
    """Capabilities implemented natively; the wrapper emulates the rest."""
    json_events: bool
    schema_output: bool
    native_resume: bool
    subagents: bool
    mcp: bool


@dataclass
class RunResult:
    ok: bool
    text: str
    exit_code: int
    session_id: Optional[str] = None
    stop: str = "done"                 # done | quota | transient | fatal
    cost_usd: Optional[float] = None
    raw: dict = field(default_factory=dict)
    stderr: str = ""


class HarnessAdapter(ABC):
    """Per-CLI command construction and parsing; subclasses do not replace run()."""
    name: str = "harness"

    @abstractmethod
    def capabilities(self) -> Capabilities: ...

    @abstractmethod
    def build_cmd(self, prompt: str, *, model: Optional[str] = None,
                  effort: Optional[str] = None, resume_session_id: Optional[str] = None,
                  schema_path: Optional[str] = None, system_prompt_path: Optional[str] = None,
                  allowed_tools: Optional[str] = None) -> list[str]: ...

    @abstractmethod
    def parse_output(self, stdout: str, exit_code: int) -> RunResult: ...

    def quota_patterns(self) -> Optional[re.Pattern]:
        """Return per-CLI quota indicators in addition to common patterns."""
        return None

    def classify(self, result: RunResult) -> str:
        """Return done, quota, transient, or fatal in contract-defined order.

        1. QUOTA is checked even for otherwise successful output because a
           harness may exit 0 while saying that a usage limit was reached. It
           also wins mixed text such as ``429: usage limit reached``.
        2. A successful result becomes done. Throttling is deliberately checked
           after this step: an exit-0 429 means the harness recovered internally,
           and externally collected text about rate limits must not turn a
           successful run into a transient failure.
        3. TRANSIENT covers burst throttling and network failures from an
           unsuccessful call.

        Raw blob keys are part of the port contract: subtype/api_error_status
        for Claude single JSON, error for Codex JSONL error events, and
        codex_error_info for structured rollout/task_complete errors.
        """
        blob = f"{result.text}\n{result.stderr}\n{result.raw.get('subtype', '')}\n" \
               f"{result.raw.get('api_error_status', '')}\n{result.raw.get('error', '')}\n" \
               f"{result.raw.get('codex_error_info', '')}"
        extra = self.quota_patterns()
        if _QUOTA.search(blob) or (extra and extra.search(blob)):
            return "quota"
        if result.ok:
            return "done"
        if _TRANSIENT.search(blob):
            return "transient"
        return "fatal"

    def run(self, prompt: str, *, cwd: str, timeout: Optional[float] = None,
            **build_kw) -> RunResult:
        """Run the harness once; this is the only place that spawns a process."""
        cmd = self.build_cmd(prompt, **build_kw)
        try:
            # stdin=DEVNULL is a production fix: Codex exec reads inherited stdin
            # until EOF ("Reading additional input from stdin...") and otherwise hangs.
            proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                                  timeout=timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or "") if isinstance(e.stdout, str) else ""
            return RunResult(ok=False, text=out, exit_code=-1,
                             stderr="wall-timeout", stop="transient")
        res = self.parse_output(proc.stdout, proc.returncode)
        res.stderr = proc.stderr or ""
        res.stop = self.classify(res)
        if res.stop != "done":
            res.ok = False
        return res
