"""Bounded, executable evidence for the technical Gate P4.

Constants in this module describe the expected boundary.  They do not claim
that an upstream command ran: only :func:`run_upstream_evidence` can produce
an observation, and :func:`validate_upstream_evidence` requires its exact
command results.  The integrated proof invokes the real sibling ``research``
and ``llmwiki`` CLIs in a caller-owned disposable root.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Mapping, Sequence

from ...connectors.gateway import GatewayConnector, GatewayDeliveryService
from ...connectors.llmwiki import LlmWikiConnector
from ...connectors.researcher import ResearcherConnector
from ...connectors.scheduler import canonical_recipe_descriptors


P4_GATE_SCHEMA_VERSION = 1

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_HEAD = re.compile(r"^[0-9a-f]{40}$")
_SOURCE_ID = re.compile(r"^src_[0-9a-f]{12}$")
_CLAIM_ID = re.compile(r"^clm_[0-9a-f]{12}$")
_CONNECTOR_SOURCE_FILES = (
    "coursedump/__init__.py",
    "coursedump/connector.py",
    "gateway/__init__.py",
    "gateway/connector.py",
    "llmwiki/__init__.py",
    "llmwiki/connector.py",
    "probes/__init__.py",
    "probes/capabilities.py",
    "researcher/__init__.py",
    "researcher/connector.py",
    "scheduler/__init__.py",
    "scheduler/connector.py",
    "scheduler/installer.py",
    "scheduler/recipes.py",
)
_MAX_UPSTREAM_OUTPUT_BYTES = 64 * 1024 * 1024
_MAX_RUNTIME_SOURCE_BYTES = 8 * 1024 * 1024
_MAX_RUNTIME_SOURCE_TOTAL_BYTES = 64 * 1024 * 1024
_ALLOWED_OS_CALLS = frozenset(
    {
        "os.access",
        "os.close",
        "os.fsencode",
        "os.fspath",
        "os.fstat",
        "os.fsync",
        "os.killpg",
        "os.listdir",
        "os.open",
        "os.read",
        "os.scandir",
        "os.set_blocking",
        "os.stat",
        "os.strerror",
        "os.write",
    }
)


class P4GateError(ValueError):
    """Gate evidence is missing, unsafe, or inconsistent."""


@dataclass(frozen=True)
class ConnectorBoundary:
    """One subprocess source and the only accepted machine-output mode."""

    connector_id: str
    source_file: str
    process_function: str
    popen_argv_expression: str
    operations: tuple[str, ...]
    output_mode: str
    schema_contract: str


@dataclass(frozen=True)
class ConnectorSourcePolicy:
    """Exact reviewed AST, imports, and call sites for one production source."""

    source_file: str
    ast_sha256: str
    imports: tuple[str, ...]
    call_count: int
    call_inventory_sha256: str
    source_sha256: str = ""


@dataclass(frozen=True)
class InstallSourcePolicy:
    """Exact source proof for runtime files that may participate in installation."""

    source_file: str
    ast_sha256: str
    import_count: int
    import_inventory_sha256: str
    call_count: int
    call_inventory_sha256: str
    source_sha256: str = ""


@dataclass(frozen=True)
class UpstreamSpec:
    """Accepted upstream code anchor and commands that still must be executed."""

    repo: str
    accepted_head: str
    test_argv: tuple[str, ...]
    baseline_argv: tuple[str, ...]


@dataclass(frozen=True)
class CommandEvidence:
    """Privacy-safe observation from one completed subprocess command."""

    argv: tuple[str, ...]
    returncode: int
    duration_ms: int
    stdout_bytes: int
    stderr_bytes: int
    stdout_sha256: str
    stderr_sha256: str
    timed_out: bool


@dataclass(frozen=True)
class RepositorySnapshot:
    """Clean committed repository identity observed around one command."""

    head: str
    tree: str
    clean: bool


@dataclass(frozen=True)
class UpstreamEvidence:
    """Observed repository identity and its two executed acceptance commands."""

    schema_version: int
    repo: str
    accepted_head: str
    accepted_head_is_ancestor: bool
    before_tests: RepositorySnapshot
    after_tests: RepositorySnapshot
    after_baseline: RepositorySnapshot
    tests: CommandEvidence
    baseline: CommandEvidence


@dataclass(frozen=True)
class SafeInstallEvidence:
    """Static/public-API proof that clean install cannot activate transports."""

    schema_version: int
    scheduler_recipe_ids: tuple[str, ...]
    scheduler_statuses: tuple[str, ...]
    gateway_required_parameters: tuple[str, ...]
    implicit_activation_calls: tuple[str, ...]


@dataclass(frozen=True)
class E2EEvidence:
    """Portable result of the real researcher/llmwiki/runtime review chain."""

    schema_version: int
    status: str
    researcher_head_before: str
    researcher_head_after: str
    llmwiki_head_before: str
    llmwiki_head_after: str
    source_kind: str
    plan_id: str
    corpus_sha256: str
    document_count: int
    researcher_import_status: str
    researcher_import_output_sha256: str
    researcher_import_windows: int
    researcher_import_candidates: int
    researcher_import_verified: int
    researcher_import_duplicates: int
    topic_ref: str
    topic_snapshot_sha256: str
    llmwiki_audit_status: str
    llmwiki_audit_findings: int
    llmwiki_audit_sha256: str
    llmwiki_audited_snapshot_sha256: str
    review_status: str
    review_source_ref: str
    review_source_sha256: str
    scratch_before_sha256: str
    scratch_after_sha256: str
    forbidden_before_sha256: tuple[tuple[str, str], ...]
    forbidden_after_sha256: tuple[tuple[str, str], ...]


_BOUNDARIES = (
    ConnectorBoundary(
        "coursedump",
        "coursedump/connector.py",
        "_run_process",
        "list(argv)",
        ("capabilities", "plan", "run", "status"),
        "json",
        "ProbeSpec plus exact operation envelopes",
    ),
    ConnectorBoundary(
        "gateway",
        "gateway/connector.py",
        "_run_process",
        "list(argv)",
        ("capabilities", "dispatch-event", "receipt"),
        "json",
        "ProbeSpec plus GatewayEvent/GatewayReceipt",
    ),
    ConnectorBoundary(
        "llmwiki",
        "llmwiki/connector.py",
        "_run_validate",
        "argv",
        ("validate",),
        "exit-code-only",
        "public topic spec 0.1.x direct reader",
    ),
    ConnectorBoundary(
        "probes",
        "probes/capabilities.py",
        "_run_bounded",
        "argv",
        ("capabilities",),
        "json",
        "exact ProbeSpec capability envelope",
    ),
    ConnectorBoundary(
        "researcher",
        "researcher/connector.py",
        "_run_process",
        "list(argv)",
        ("capabilities", "start", "status", "resume", "extend", "source-plan"),
        "json",
        "ProbeSpec plus source-plan and topic snapshot contracts",
    ),
    ConnectorBoundary(
        "scheduler",
        "scheduler/connector.py",
        "_run_process",
        "list(argv)",
        ("capabilities", "list", "doctor", "job-schema"),
        "json",
        "ProbeSpec plus exact scheduler observation envelopes",
    ),
)

_SOURCE_POLICIES = (
    ConnectorSourcePolicy(
        "coursedump/__init__.py",
        "4ef0340d49c7ab6a959c2aac80fb5afd92e80deae8ece0781856a34ac3e8aed4",
        (
            "from|1|connector|COURSEDUMP_CONNECTOR_SCHEMA_VERSION|",
            "from|1|connector|CoursedumpArtifactManifest|",
            "from|1|connector|CoursedumpConnectorError|",
            "from|1|connector|CoursedumpConnector|",
            "from|1|connector|CoursedumpEstimate|",
            "from|1|connector|CoursedumpPlanItem|",
            "from|1|connector|CoursedumpPlan|",
            "from|1|connector|CoursedumpRun|",
            "from|1|connector|CoursedumpStatus|",
            "from|1|connector|parse_artifact_manifest|",
            "from|1|connector|render_artifact_manifest|",
        ),
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    ConnectorSourcePolicy(
        "coursedump/connector.py",
        "2c2a03e9d5721e71685d23236b3118d04d29e5191afab9d2b5d46fd9af5a4612",
        (
            "from|0|__future__|annotations|",
            "from|0|dataclasses|dataclass|",
            "from|0|datetime|datetime|",
            "from|0|pathlib|Path|",
            "from|0|pathlib|PurePosixPath|",
            "from|0|tool_life_os_runtime.ext.connectors.probes|DEFAULT_SPECS|",
            "from|0|tool_life_os_runtime.ext.flows.book|BOOK_SCHEMA_VERSION|",
            "from|0|tool_life_os_runtime.ext.flows.book|BookSourceManifest|",
            "from|0|tool_life_os_runtime.ext.flows.ingest|INGEST_CONNECTOR_SCHEMA_VERSION|",
            "from|0|tool_life_os_runtime.ext.flows.ingest|IngestConnectorRequest|",
            "from|0|tool_life_os_runtime.ext.flows.ingest|IngestConnectorResult|",
            "from|0|typing|Mapping|",
            "from|0|typing|Sequence|",
            "import|hashlib|",
            "import|json|",
            "import|math|",
            "import|os|",
            "import|re|",
            "import|selectors|",
            "import|signal|",
            "import|stat|",
            "import|subprocess|",
            "import|time|",
            "import|unicodedata|",
        ),
        644,
        "ebba5d6c9f1066e87d44a7611e382028c7b87e1918e09bed120b0347b783f781",
    ),
    ConnectorSourcePolicy(
        "gateway/__init__.py",
        "fcd03385cfc02d375be7ab8b56f6f38bd46e0679d68ea6031e0df1c48e8e67b3",
        (
            "from|1|connector|GATEWAY_CONNECTOR_SCHEMA_VERSION|",
            "from|1|connector|GATEWAY_DELIVERY_ACTION_ORDER|",
            "from|1|connector|GatewayConnectorError|",
            "from|1|connector|GatewayConnector|",
            "from|1|connector|GatewayDeliveryCapabilities|",
            "from|1|connector|GatewayDeliveryOutcome|",
            "from|1|connector|GatewayDeliveryService|",
            "from|1|connector|GatewayDelivery|",
            "from|1|connector|GatewayEvent|",
            "from|1|connector|GatewayReceipt|",
            "from|1|connector|MAX_GATEWAY_MACHINE_BYTES|",
        ),
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    ConnectorSourcePolicy(
        "gateway/connector.py",
        "e4dc96efe157f342e738799ea7ef9e9c6036924e1cbc7aebc9bf80817b2719e6",
        (
            "from|0|__future__|annotations|",
            "from|0|dataclasses|dataclass|",
            "from|0|pathlib|Path|",
            "from|0|tool_life_os_runtime.ext.connectors.probes|DEFAULT_SPECS|",
            "from|0|tool_life_os_runtime.ext.review.authority|ActionCapability|",
            "from|0|tool_life_os_runtime.ext.review.authority|AuthorityError|",
            "from|0|tool_life_os_runtime.ext.review.authority|AuthorityPolicy|",
            "from|0|tool_life_os_runtime.ext.runs|OutboxError|",
            "from|0|tool_life_os_runtime.ext.runs|OutboxStore|",
            "from|0|tool_life_os_runtime.ext.runs|bound_receipt_effect_hash|",
            "from|0|tool_life_os_runtime.ext.runs|validate_event|",
            "from|0|tool_life_os_runtime.ext.runs|validate_receipt|",
            "from|0|typing|Mapping|",
            "from|0|typing|Sequence|",
            "import|hashlib|",
            "import|json|",
            "import|math|",
            "import|os|",
            "import|re|",
            "import|selectors|",
            "import|signal|",
            "import|stat|",
            "import|subprocess|",
            "import|time|",
            "import|unicodedata|",
        ),
        376,
        "2d0ef2cfbd11a100638013b55e865fc2409abf78873b542880f2f9224bc208a6",
    ),
    ConnectorSourcePolicy(
        "llmwiki/__init__.py",
        "02e070f1e2dbdbf376d5d15208f6175a5433a0c744b8c0df2d2b87a7b8802a5d",
        (
            "from|1|connector|HashedRecord|",
            "from|1|connector|LlmWikiConnectorError|",
            "from|1|connector|LlmWikiConnector|",
            "from|1|connector|MAX_CONNECTOR_OUTPUT_BYTES|",
            "from|1|connector|SUPPORTED_SPEC_VERSION|",
            "from|1|connector|TopicIssue|",
            "from|1|connector|TopicSnapshot|",
            "from|1|connector|TopicValidation|",
            "from|1|connector|VALIDATE_ARGV_SUFFIX|",
            "from|1|connector|VALIDATE_EXIT_CODES|",
            "from|1|connector|WikiPage|",
        ),
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    ConnectorSourcePolicy(
        "llmwiki/connector.py",
        "8ab6b905acdbeaa18c06193f4bf5db0c02996d3af024474101e026c52eb5d865",
        (
            "from|0|__future__|annotations|",
            "from|0|dataclasses|dataclass|",
            "from|0|pathlib|Path|",
            "from|0|pathlib|PurePosixPath|",
            "from|0|typing|Mapping|",
            "from|0|typing|Sequence|",
            "import|hashlib|",
            "import|json|",
            "import|os|",
            "import|re|",
            "import|selectors|",
            "import|signal|",
            "import|stat|",
            "import|subprocess|",
            "import|time|",
            "import|unicodedata|",
        ),
        516,
        "9684afabc401f95e5b9c6006a6fa91f4854efeb0d0c2d48cd8840cea3e2931ef",
    ),
    ConnectorSourcePolicy(
        "probes/__init__.py",
        "c489f530336d3f5b8aab8ac60e363d0851f1b6b0b3b166cb8e7e50eb125f017e",
        (
            "from|1|capabilities|CapabilityContract|",
            "from|1|capabilities|DEFAULT_SPECS|",
            "from|1|capabilities|MachineOutputContract|",
            "from|1|capabilities|ProbeRecord|",
            "from|1|capabilities|ProbeSpec|",
            "from|1|capabilities|probe_all|",
            "from|1|capabilities|probe_tool|",
        ),
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    ConnectorSourcePolicy(
        "probes/capabilities.py",
        "0a4d8c1e7e62d500b9c10e20546daebac4c4aaaf1a2ab37546331f543d8b1d76",
        (
            "from|0|__future__|annotations|",
            "from|0|dataclasses|dataclass|",
            "from|0|dataclasses|field|",
            "from|0|pathlib|Path|",
            "from|0|typing|Any|",
            "from|0|typing|BinaryIO|",
            "from|0|typing|Mapping|",
            "from|0|typing|Sequence|",
            "import|json|",
            "import|os|",
            "import|shutil|",
            "import|signal|",
            "import|stat|",
            "import|subprocess|",
            "import|threading|",
            "import|time|",
            "import|unicodedata|",
        ),
        232,
        "4f846e0a2a7e2f0b46c44cf9029c4f0afc4e5393d351ebccec7e9884ca3834f1",
    ),
    ConnectorSourcePolicy(
        "researcher/__init__.py",
        "87b2fa8561a3375086e97cd182a11567e62f2a89f78c5f3ac3063320da241fa3",
        (
            "from|1|connector|MAX_CONNECTOR_OUTPUT_BYTES|",
            "from|1|connector|RESEARCHER_CONNECTOR_SCHEMA_VERSION|",
            "from|1|connector|ResearcherArtifactRef|",
            "from|1|connector|ResearcherArtifactRegistration|",
            "from|1|connector|ResearcherConnectorError|",
            "from|1|connector|ResearcherConnector|",
            "from|1|connector|ResearcherEvent|",
            "from|1|connector|ResearcherImportResult|",
            "from|1|connector|ResearcherResult|",
            "from|1|connector|ResearcherReviewAdapter|",
            "from|1|connector|ResearcherSourceDocument|",
            "from|1|connector|ResearcherSourcePlan|",
            "from|1|connector|TopicBoundary|",
        ),
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    ConnectorSourcePolicy(
        "researcher/connector.py",
        "f1478e4b60d26d7eecc3baa659c3fb4f676b27f5e4041e5767e807fb9569fad6",
        (
            "from|0|__future__|annotations|",
            "from|0|dataclasses|dataclass|",
            "from|0|pathlib|Path|",
            "from|0|pathlib|PurePosixPath|",
            "from|0|tool_life_os_runtime.ext.connectors.llmwiki|HashedRecord|",
            "from|0|tool_life_os_runtime.ext.connectors.llmwiki|TopicSnapshot|",
            "from|0|tool_life_os_runtime.ext.connectors.llmwiki|WikiPage|",
            "from|0|tool_life_os_runtime.ext.connectors.probes|DEFAULT_SPECS|",
            "from|0|typing|Callable|",
            "from|0|typing|Mapping|",
            "from|0|typing|Protocol|",
            "from|0|typing|Sequence|",
            "import|hashlib|",
            "import|json|",
            "import|math|",
            "import|os|",
            "import|re|",
            "import|selectors|",
            "import|signal|",
            "import|stat|",
            "import|subprocess|",
            "import|time|",
            "import|unicodedata|",
        ),
        541,
        "746d29376046af15efc9cbadcbbf4b39b4f154254b3c284c2a199216f56dac47",
    ),
    ConnectorSourcePolicy(
        "scheduler/__init__.py",
        "9a4e7067551a7520e535fd3c873e3bb2a460d4af1b0e481f54612321b39fd721",
        (
            "from|1|connector|MAX_SCHEDULER_OUTPUT_BYTES|",
            "from|1|connector|SCHEDULER_CONNECTOR_SCHEMA_VERSION|",
            "from|1|connector|SchedulerConnectorError|",
            "from|1|connector|SchedulerConnector|",
            "from|1|connector|SchedulerDoctor|",
            "from|1|connector|SchedulerJobPolicy|",
            "from|1|connector|SchedulerJobSchedule|",
            "from|1|connector|SchedulerJobSchema|",
            "from|1|connector|SchedulerJobState|",
            "from|1|connector|SchedulerJob|",
            "from|1|connector|SchedulerList|",
            "from|1|connector|SchedulerProblem|",
            "from|1|installer|SCHEDULER_INSTALL_SCHEMA_VERSION|",
            "from|1|installer|SchedulerCheck|",
            "from|1|installer|SchedulerInstallResult|",
            "from|1|installer|SchedulerRecipeAction|",
            "from|1|installer|SchedulerRecipePlan|",
            "from|1|installer|check_recipes|",
            "from|1|installer|diff_recipes|",
            "from|1|installer|install_recipes|",
            "from|1|installer|uninstall_recipes|",
            "from|1|recipes|SCHEDULER_RECIPE_SCHEMA_VERSION|",
            "from|1|recipes|SchedulerRecipe|",
            "from|1|recipes|canonical_recipe_descriptors|",
            "from|1|recipes|recipe_set_sha256|",
            "from|1|recipes|render_recipe|",
            "from|1|recipes|validate_recipe|",
        ),
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    ConnectorSourcePolicy(
        "scheduler/connector.py",
        "e56d6941cbf9d9a83445cc6d19c1e960acdeb75837e2c3f51250a4ca3702bd10",
        (
            "from|0|__future__|annotations|",
            "from|0|dataclasses|dataclass|",
            "from|0|pathlib|Path|",
            "from|0|tool_life_os_runtime.ext.connectors.probes|DEFAULT_SPECS|",
            "from|0|typing|Mapping|",
            "from|0|typing|Sequence|",
            "import|datetime|",
            "import|json|",
            "import|math|",
            "import|os|",
            "import|re|",
            "import|selectors|",
            "import|signal|",
            "import|stat|",
            "import|subprocess|",
            "import|time|",
            "import|unicodedata|",
        ),
        323,
        "c42cec73ec7c42f75379f2c18d89d2aa984e82bc3015504439f32fc3b828b0b3",
    ),
    ConnectorSourcePolicy(
        "scheduler/installer.py",
        "3bee873d729b880c98fb9f227ba9590bf181628eda444eb0118a868d4e582ab9",
        (
            "from|0|__future__|annotations|",
            "from|0|dataclasses|dataclass|",
            "from|0|dataclasses|field|",
            "from|0|pathlib|Path|",
            "from|0|typing|Mapping|",
            "from|0|typing|Sequence|",
            "from|1|connector|SchedulerConnectorError|",
            "from|1|recipes|SchedulerRecipe|",
            "from|1|recipes|recipe_set_sha256|",
            "from|1|recipes|render_recipe|",
            "from|1|recipes|validate_recipe|",
            "import|ctypes|",
            "import|fcntl|",
            "import|hashlib|",
            "import|json|",
            "import|os|",
            "import|re|",
            "import|stat|",
            "import|sys|",
        ),
        445,
        "64cda58f3e8fa223481a6ce01c3c7727f49213cf0bac145bbabfc94a14c3bfed",
    ),
    ConnectorSourcePolicy(
        "scheduler/recipes.py",
        "5b08a9894d5575b2fa80ce833aff90d2a2c80ad92d33a3987f68eec031d3e3a5",
        (
            "from|0|__future__|annotations|",
            "from|0|dataclasses|dataclass|",
            "from|0|typing|Sequence|",
            "from|1|connector|SchedulerConnectorError|",
            "import|hashlib|",
            "import|json|",
            "import|re|",
            "import|shlex|",
            "import|unicodedata|",
        ),
        98,
        "027546545e8a547ec477ea875c1dc3a062e8719ea29930db6a853742a000cae1",
    ),
)

_INSTALL_SOURCE_POLICIES = (
    InstallSourcePolicy(
        "__init__.py",
        "2e378aaaf2f8d9a02d7c051be4c8931440f840ba50ba3a9c7d4e3bc7d330de0e",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "__main__.py",
        "9a3c8d26c4c86f5b613643ef1591321d75e6b093108f41106a310d89e01f643c",
        2,
        "26c0cbbd58e339ab536341eec76267d4f700f6c3bbcadc2da817bca2f6d22cf6",
        2,
        "0bacd3a98a1b59422b1705adaa26ac9ec3d49da7d0d93d4a3f7ac8068b33a37d",
    ),
    InstallSourcePolicy(
        "cli.py",
        "0764cc4d4ba26d0851206f042a858526b49c63f72f338331b487944c22385830",
        39,
        "110e41e79565b6a97ff39cfd5c259ae1da9cfd3427b98fa7d53c51a9d7d94cee",
        252,
        "35890cdee8d9bf39db722bc2821359b21fd6be71608d9c6b32e839c603e1c4fe",
    ),
    InstallSourcePolicy(
        "dev_manifest/__init__.py",
        "4b53d7afd93c211f5824eed4aa9c49e9f6c7c55c5d720e7f682c2506e616f398",
        5,
        "de2624ba1f29641976810c8afe7e9cc0c661463ae99f2cc34813b49f99bc21fd",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "dev_manifest/__main__.py",
        "e559e833212a47e945163ea0ec80a2ae6f59ee4c60c8f8ccbc9cce6a3d5373a6",
        1,
        "cb43acdb3224066986f76ab6e4629c686d0bd938c54af9f555373b731218e107",
        2,
        "35fd77acf6f135a3442317f81d0c9f742c396216290638485b8fe3f80c497834",
    ),
    InstallSourcePolicy(
        "dev_manifest/scanner.py",
        "02640e99726e3f2b6945329a0f5424ee8280cf313225c44ac3f2beb704b5f78f",
        20,
        "dc5d032b4e445b29b0951582aa3440654bfe138296381d679e864bae98633607",
        369,
        "e7ab06feba72464fb6206b2e81e4a495c918d13dbbe96c3afcba6f054a8951ab",
    ),
    InstallSourcePolicy(
        "ext/flows/__init__.py",
        "1caf8f8e59018139a5e100a2b911c11f6464c5524097ad0bfdd9a46782a0b0a2",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/ambient/__init__.py",
        "659f846397df724880182fb5a5d137a1a905687d2187c98322766502901916d5",
        16,
        "8c3527e25fb7703c0ad35b7115597aabc2a271138bfbf9733dd88bc292455962",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/ambient/flow.py",
        "ede1df7bcd68f9b4d7582c88a3d41c8cc1ddb18eb10ad3d81abae38b03f50279",
        42,
        "ec88e98f82259b191de483f326e5193784ecba83d97af5323a9c5af62577b10f",
        1186,
        "b7ceb149390845710930ba81ef8f0104f8c645bd0e9df577e4dba61130aff01b",
    ),
    InstallSourcePolicy(
        "ext/flows/ask/__init__.py",
        "537436709f7e55bcad17c51f88f2a66a94d8e223e821b4b1316d95b150534f4c",
        11,
        "e116fafa0829c4b3583b8d54602f8935f5506f03c7b81284743aeccf4a6ee665",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/ask/flow.py",
        "20436baa6c02c5376ea7079f3f17dc41df043a0a4e84867a829607ca5d57c6ea",
        35,
        "cdee6567993ef79120226ea8d845de2ad2901c95bed0294eb8c256ff0fff1308",
        493,
        "18abd9b5a2ca22366fdc0e8288fb19853ac91829351b27337c324fe03ed9aaf5",
    ),
    InstallSourcePolicy(
        "ext/flows/book/__init__.py",
        "fb31b53ca870924ede8df401622167f1e8de91125770701202260e04590ad054",
        21,
        "c2f386ed8f12b150a36c6d95c77d10e9a8c35e0ac77c0958c1e6773a7b63cf68",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/book/flow.py",
        "2c2507d67370517d4c9e3b37544a2f47c07e1eb4e2ada53b28cdb85d40242be7",
        45,
        "a1f5fdac3a299ff52b680f826fb43245a0e54d6f0871ee211b00fcddcdfde9dd",
        936,
        "303a5998ed10d4c32268af6fda2f964d28f0f59c8c5346e24a8d6fa0a592e291",
    ),
    InstallSourcePolicy(
        "ext/flows/bundle/__init__.py",
        "cb2ee0933b800f9c19f14998cec0a7cb1faf12432ac491b23d07da16b1252262",
        18,
        "73b72db1f32de217fd181e131d70f6ee937adc0d99a3ef577936018a228e49fe",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/bundle/flow.py",
        "198268b1121e09b69a660b260b650d0caee8ee16c499f1cf0957cc1a069e77cf",
        42,
        "7ecb853217cd0a3e229e884ca6922c77d70748458efa4eb5b668bde4a34f0d48",
        674,
        "85043b393e7eba4619a2d2d452d15e3562f4a9b461589f3c0a70655a50494845",
    ),
    InstallSourcePolicy(
        "ext/flows/distill/__init__.py",
        "eadf0803c0741cf92397554afa8c2897be59d5b89ef93d06f4c997ecaab80bf3",
        15,
        "e42a123e96a0652e103008a401f2206a06cb35260ecb30a5952c08fd422d8351",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/distill/flow.py",
        "33069ff28ab0f4d4596e7a0a46f90bc2ab99aac56ef275c4b8b054bc3a146ab4",
        29,
        "e97b66aaeea551ecc2ad312d7c103111a2dcbca9552ddf59b175d8a2e49b5a76",
        416,
        "bd8e9f070b94e2a545622d20e846266274f503fd1e126c314692b7b7374c5080",
    ),
    InstallSourcePolicy(
        "ext/flows/entities/__init__.py",
        "d1e9c9fa9498f003e33cf95b9c529a1755c39f857db3974bbcf152cbfc33f61a",
        25,
        "c157897ddddbdf251b02593ad7067c86de61e00e2a1cbb2b428fb7eddbc1cd2b",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/entities/flow.py",
        "6edd3e77bcf7a54ff7caf9236e3b205aff5d1b12fa38d3fb5ee37d6923ed1083",
        29,
        "2df77276abbc7cd18767b02bc0c9328206d050bcff9d08be1ab1058c6b851db6",
        998,
        "2b811f7fd7c5121c2883b890dbc7a897d11fecffa2701598c957f3f810796f03",
    ),
    InstallSourcePolicy(
        "ext/flows/finalize/__init__.py",
        "7c566a9acce73aadd73eac6f7a93888b6ac629cddc58b3e713833b5220bb5b0a",
        14,
        "187796f5a9fb03893bf3cfb5fa5e4acaa0cc886db81cbda62bbdb1a977495ebd",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/finalize/flow.py",
        "e67eed3df3385ecb5a1c573887dfc007dce3a42b17b4b52aab8a626970a01877",
        77,
        "99130e05f19044e13db71e7a467ef52aa566a66a2dd0d14e0e5f5df720f24a0e",
        1264,
        "9491d86a0fca14657b957fa36388416152d430f61b46a467d85de32216ddd741",
    ),
    InstallSourcePolicy(
        "ext/flows/grill_me/__init__.py",
        "8afc0e9bdffe9021a95c5d3e5baa8c31e9d656dd18856a986b7a6eaca4556615",
        28,
        "f9dfb55ec1f35091cc21e39b8ce88034f4fe72dde8537c167e78b435185b5060",
        3,
        "3625012d82e54a20427c2aa71148868029997d590b347787f25f8bbf53890415",
    ),
    InstallSourcePolicy(
        "ext/flows/grill_me/flow.py",
        "8db9f923e7bade07c0062a1786d9d46bc5bad8d308b72512d7f9c22cc7e563d4",
        28,
        "6b7aaa63c4d15540ec04e70af53b9e3daf9efc1be9e1f85213c4d6ffe7030e3d",
        761,
        "26bf494daab30b7f3bdb5b288a7317f05abb8674a9a9b2df5ff7e41353857650",
    ),
    InstallSourcePolicy(
        "ext/flows/ingest/__init__.py",
        "03a9054a9c9f1cba3e73444c81b73d21f3936403e38f9eb08c0f9cea167a1f88",
        19,
        "f925a34e55297d942f16c2ed337f55035e86888a7107fdfaf78e8d8a7bafe9a9",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/ingest/flow.py",
        "907b91abfff6ffea5c2563f1c82fffec5dc17ebd867c8cb9eab6065bdb0a9002",
        43,
        "a205355b0677e0f0c722d396f3a8d16a2f4a2f6a49cdb50e720ab321e7036505",
        396,
        "f9e460fb4e17095cda18b7751d3277867206ef0767725b0bb804ee223ef1d9fe",
    ),
    InstallSourcePolicy(
        "ext/flows/lint/__init__.py",
        "a1fbd235b1d975d86a9f3fd6266ef0aedde127283536c99da418ae90a64dc68b",
        30,
        "acfca05155aa4171ecc3db69e5111010fbd8950d6ccc215d2e69ee91f1b07ae5",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/lint/flow.py",
        "cd5d9cd4f8efcb999d82ee195740f61a2aacb51eaf97fcd0a1b13bcb057547ee",
        43,
        "d49d01abce7142154f464d5c9f0ca527ea79e8ddd9ddf1acb071b5a2da8a5df4",
        1662,
        "375962ba5b01b9c11c2a5f9592671c90915182afaabf7293e4702908085c5b7e",
    ),
    InstallSourcePolicy(
        "ext/flows/memory/__init__.py",
        "0a37de5cebefc58ed0df25501668c136e3451d1cbdc445d43d62baf2ba7ac090",
        30,
        "fcebfc559a4b8987147a961c4d37a35f9bcb0c17c21c7aea4b3e10aea4a02749",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/memory/flow.py",
        "1f529ae96746f673b21b62b64c9b847c4a5474ed8760ab19f0ac6415b3fb8c53",
        33,
        "e97fb713208ad27ae662d713aabebf2dc266e18e43119bd2b2aa7c42218b6587",
        1020,
        "201d8becc033ab04377eed6a0d0a1243bb0babd3cb07ae9f408ac8ce3c3438f3",
    ),
    InstallSourcePolicy(
        "ext/flows/mentor/__init__.py",
        "da67290bd44502ed9236552ba80c877b1e5a9287f1d5b24bc992f6df58f66c19",
        29,
        "734e861975714fc72772759d5353380628a52edcb63d0dddcf80ff310463adfe",
        3,
        "465b4b9c0bb68ba091c99dcf23c8fa20bd0cb980091ec7c2bbe35932747f87fc",
    ),
    InstallSourcePolicy(
        "ext/flows/mentor/flow.py",
        "dca9daa2e6773d8cd03a1278a41a3b14aacfce9c132c24dd8ec79a1c8e0db1cb",
        26,
        "be17c1e0b9ed450649a5a0b85ad0553ef9d9781e8aca5df9c2ea7ed0e097b3e0",
        664,
        "972e3267b28f25790f986d713dd38625439473a4d2c0cbbe5ceb785b120cbe16",
    ),
    InstallSourcePolicy(
        "ext/flows/obsidian/__init__.py",
        "819223b16857897b86c053d8088495135015205e9074c474aede65dd7e7ae1a7",
        20,
        "eb408c3a157862a4d0b6da973f8bb244e217e64e03a8efc6859fbea6eb77c084",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/obsidian/flow.py",
        "db725d76b813286e44811dc68d9b0c6e2b647a5b09e1b2ff970f38a578ca1a09",
        23,
        "29789bc0ae22d971e7f6833bccb2c4050e3e07ac3f2c1637256f8a497147b42b",
        721,
        "aaab5084e73be32c1bcad9bd713af210a643536f59f53a3b7be21972ba0136fc",
    ),
    InstallSourcePolicy(
        "ext/flows/plan/__init__.py",
        "61801e72556b7de352f51bf1a5e5f7f141c20246ad78e2b5f02c9378cb1d18da",
        29,
        "b239bbcd226c4d9c51794d0dd95b492890c8a359d4e75d21aba80b44225dcab5",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/plan/flow.py",
        "08a1baeab5fa469cfba5b0d6934f3d9a7ae777cf4fa5aefb6c3b20e06bd7af44",
        32,
        "1b27dfb19fe4565a3f8f48ba980dea78a8c2bdaf7e2e9962ee8a83b32dcfbba6",
        1595,
        "d42303e64c1e324f4c556fa99df5c3ae06115dcc047e1f0587dc25fad79b4a94",
    ),
    InstallSourcePolicy(
        "ext/flows/project/__init__.py",
        "5540cbbeb15d7b821cfeab2e62869c80670eb5d7cdcbf2d88eb443e7614ca973",
        25,
        "149b526d169e7b00f3119187485ca6d9db72dfe937e8d58ff43b05dc5cb44a37",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/project/flow.py",
        "273abf151e03ac0eb62422d646fdd1bf159c0662baa440049c3e8b510f0d3832",
        29,
        "9335c552d01326fd6581a959cb7690ac636e75e4dc6d9518a578a4e5556bd16f",
        1621,
        "7154d333dc1b203f84df95e1bd147e29c2c4c1a942ab97115e8027e9391e2596",
    ),
    InstallSourcePolicy(
        "ext/flows/report/__init__.py",
        "91d1ec43e78e0731de87560b52c806fcdb1bf2f507aae236de1e21b473703418",
        22,
        "556b0054f46dc70c10f2756c5cd1e21cc10d0230fc5191164e075c4d822f8f93",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/flows/report/flow.py",
        "8d4b4e03f68141c05297026079a7da63bbadca10daf6f45b03f09c655647d418",
        43,
        "bb9f4fb1204137e104f1d06e19a1dde0b06252b909292fa43d5bd4912ac8a927",
        843,
        "676f97943b26c52d0c455907724aed066d7f23a36eecfa6e0eb12735ef2ad0de",
    ),
    InstallSourcePolicy(
        "ext/review/__init__.py",
        "8eec600e4b215450b88cb3fa93a1d3da42fcddcaeb3524a6efc3a1384f68666a",
        4,
        "6a081cbe33504c404236a2e14d8f08e9b45f446925734d894593874404c8cd0d",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/review/apply/__init__.py",
        "57b09e9f6b7cebb6e86d3a11930d310037179c2c0f74cea2e8d68454cc6efde8",
        6,
        "55a584aefdbcbedeb2deb27f3d1a9135b5f85f64070d5108f6f1139f53efb67f",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/review/apply/transaction.py",
        "759dd2163beeaf9193c7987739a2c21b765a2d481d56c291b5af1a6947b83e5c",
        38,
        "810eea4ee5bfb6ddac112a1c857a04528e0c3445f1bd2be209206462e459bafb",
        471,
        "8ae6c83bb97cca31dd4dd0201b1d6faaf59ecdb2af13bc65ad812281e51857a4",
    ),
    InstallSourcePolicy(
        "ext/review/artifact/__init__.py",
        "e8bc0d4ea8d04958d0562e59390d131ab7df58e4d991561d47ffbf811493130b",
        30,
        "f856d828ecf4b4d75086df61e2ecf858bf2949309f5117ae4f12eb58208cb581",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/review/artifact/model.py",
        "00173a8e30706975e648d188b0b679f5dc5d20d119575635b3157499e8a79d05",
        10,
        "7f74334ac70caa95de4ef7ef6034a0df0f904b984a329f859121a135a178ccef",
        383,
        "d765d3e6d5859226deae718f4ef058db95be8fefeffce96a1644e5f4c34efd78",
    ),
    InstallSourcePolicy(
        "ext/review/authority.py",
        "b36bee4c2e0c64c3b44206ca6f196526ce633bb41cca4552844741e7c45ed7bd",
        10,
        "3a428b66bf42d59e0bb19c1e52664612c8cdba90a7a8987aa555fa53236a0fca",
        95,
        "9e546f6a9cc03265bbf0c5830d47c4190d8931655b9dd7b115ac857718cd1039",
    ),
    InstallSourcePolicy(
        "ext/review/decision/__init__.py",
        "caa2495929d432a5f466c514bd8903d59c9579a45290ceca2e3894c297c76a89",
        3,
        "7516639a7a3afa4af3c0ce1b5bc65d7ad0ec98b6ab7a66bd8cad09a078e539f2",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/review/decision/model.py",
        "6ae05efbdfd4f366090b70bffacea59a52c0c6b49f6af25389b363a4d7f99ca4",
        11,
        "a59109aeaeb6d9735688b656136ada1b3a5106c54b0cfd3ba055d1d0438d1d60",
        31,
        "d444ad5103b41298a2ff1fdfa6cdf808a0cca74cf723aae05bb52c3c1f54da18",
    ),
    InstallSourcePolicy(
        "ext/runs/__init__.py",
        "ec49f0d81c56161d66f063040e8700eb7b0cc0f9db866d32cd06c225d00e3298",
        16,
        "62c4520cf2dbe581e0424b8350628b3f0ac77c2f0ccb7f9ece06196e857142d0",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/runs/outbox.py",
        "b079c12916e0b2ebedd6ff5e96a670410b32bf0b016a6910437ab9cfdb5feeca",
        36,
        "e4da5b145ac9a7844bad6b5d4228cb253d4a5aab4f651dc0e5beae72d1fa2ea5",
        598,
        "3d6e9b2c08a91913cfa7b80799ec210b52268b01b8af393a6cd46158e6d82e76",
    ),
    InstallSourcePolicy(
        "ext/runs/store.py",
        "041b4a8c062f69d622031ad58b6f02035839c44d06568da258aeacbae18982b0",
        46,
        "1e7718f65645642c5b682d295e26a9a203b3540ffd6229e14498bec3fca06b1f",
        1482,
        "035abd99ccedaec0f1c3433122c5544008498e7b84c2ebff7ddaedfb1d99e346",
    ),
    InstallSourcePolicy(
        "ext/skills/__init__.py",
        "c3392bcb11f990912b225da700d68217f051438864a105e77a987fb801355f71",
        48,
        "47c9583459127856d68256ac8d619178aaea4704f71a23f3f6810c97f1dde520",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/skills/installer.py",
        "4063ba3cbe5990b41dbfbe1e418a8c02059acb2d342b8b9a699965c1c05c650a",
        23,
        "0c96b6202c744cbd77f29a20876d062c309ec0e8b786f48bc6302d5d524c7e65",
        587,
        "58b7a55d9c648a0af9c4a2430caa2925eff7e51062c530946ce2e5c445494afe",
    ),
    InstallSourcePolicy(
        "ext/skills/resources/__init__.py",
        "e9c792636e58fac948a872638abe5d8f959b415f9dda43d7b5f3cb6380f869c4",
        39,
        "1e391916c6ef38f690ab631cc7a018893d5c06b66e72ff8abf108a396e13611a",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/skills/resources/catalog.py",
        "b3b2428c71c718d2f0d7d554cdabe13e7cef50bf402ac773436822a7e6228316",
        22,
        "7dc09419724cc532bf5d9839078a2f32be5853a5497364f93b8cba43e364b422",
        45,
        "414c789ac0204e9c0e395d0626ec3e36869f9229c48d470abc2c02eaf9bfe590",
    ),
    InstallSourcePolicy(
        "ext/skills/resources/evals.py",
        "1d8b88fffa8b31481493c2837ebb26d8da7296737da66122f0f4c086e97382d1",
        15,
        "53134f358c3dde52f0de6ae5967c316eec5c14de05c519ac143fe05d06a50df5",
        180,
        "1b9f8883e8c92936ebbafd41cbcef656139c4139ab1484fd613fe1a39cc27ec9",
    ),
    InstallSourcePolicy(
        "ext/skills/resources/model.py",
        "03bf7bea46f55b92572ed743a317121378300cef1eaf1126bfc80448bf27cfd7",
        8,
        "82eb3f9182aaa42ee9a5e6c320a4561bcac8d2d50b304c69a63ac2e7f5e4e645",
        183,
        "7f3f540ab684b010a3b1c1633ea16f20d120b40eff30631226bcfb6431e115d4",
    ),
    InstallSourcePolicy(
        "ext/vault/config/__init__.py",
        "9e00b15bba3a56a77573c53ecbde3163a41402aad67aeab73df27cb66feef260",
        13,
        "72e975978c9c02b40f150b3d2774165bacc2a3e3189e0b2cece3be825ded7778",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/vault/config/models.py",
        "6d9b4ee2c8478b6b5be84684d07c12d7c259e176ae11d860582dab187c955269",
        12,
        "d1ee8d79aa75317c10cb786fbb1329da28296c79b51f6d15dfefcda85b5104b9",
        174,
        "08a53b2c8290e8d65a12e694d795dc9748a9df87488fb81fd28bc83cefb94c8d",
    ),
    InstallSourcePolicy(
        "ext/vault/doctor/__init__.py",
        "f34301635697aef6323345cd77ea8ce162f2fc1d152fe9fd4f74284aea6b3b67",
        8,
        "010430a161edc7a3c73e79a6ccb048352b7f78897a5fa3ae4e3a5fed63b7b344",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/vault/doctor/report.py",
        "d382dd2575f8dd9f5c2dbee7467a76ddaa6b00ef218ce685d802c615c1562689",
        29,
        "e655f9fceca87d970480dd093ad374f6279398e9528cb49eb6a5f3d399d3b280",
        438,
        "4e090de296f89b5d639ffdb1c9edd203a9519c23a02244b2fae7af49463c60e8",
    ),
    InstallSourcePolicy(
        "ext/vault/migrate/__init__.py",
        "b847ab450dace360d2d2221c740c297aaa158269b008e6f0bb0fd0d61e377d2a",
        17,
        "16388e6ad5637e128fbd478ece7a72073388032d09d268568d9edd83611967df",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/vault/migrate/core.py",
        "96b3f0b96c5dc05679cd8cb9d9c1586a5deeffbefcfb70db7c528074d3318b9f",
        21,
        "17d1f6c7927006aa21c9ec16cba06eead34b385cbb688191a30c296f51b76e28",
        538,
        "11fb7b39030bdca72701a787285d244cb51337a30dcce4e7bd2b9414ca791a1e",
    ),
    InstallSourcePolicy(
        "ext/vault/schema/__init__.py",
        "72246d3b19f4ffefd6d21e46ea9d781201eaac578d02c3eb7ed5b4aa48eec3ea",
        12,
        "ebbbbea41714f6c168267b33de237dc11518af4617057209ea04cf8c085192ea",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "ext/vault/schema/model.py",
        "a0f8b901b115064619539500efd101340030ddb6ddb3ddb39fcdddfc03169bdd",
        11,
        "2935154f0b03f06cdde77cf642626bf03cb1b597cb517850c3a03170383e9449",
        156,
        "8bfbfdc0f9c282008cd00cdd659afc7b7f00a481f9d01cf7266fbcd046fe0553",
    ),
    InstallSourcePolicy(
        "failure_authority/__init__.py",
        "9621181760e88b573443c445b2d95c4fed17212217bb56370a691c21793f60d8",
        18,
        "3570a47c306c42ff8d4434a637c8b4406c35043601c6913f4c5ab06651f1669a",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "failure_authority/catalog.py",
        "620b7ad61bf500b82769ca452bbde401dd1424b79d3506f753491712906e28bd",
        2,
        "f138abcd6552aadf006c2059480d777bf1f99557f6453a20dae34657cbbb18b6",
        169,
        "8c4fd12cee62fa30d968a8b7dad85c6d64562a8caa983da621d2825cdde655cd",
    ),
    InstallSourcePolicy(
        "failure_authority/registry.py",
        "b0e5df574b043bed6bad6ba2e912c286bead401fea88f675bcb519510c5c36d9",
        1,
        "009098a83a7f409785d6412db21ebb09ff637853d613a3a609a93c9506b87f00",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "failure_authority/render.py",
        "c16115d71f23be3e0b31287f6cd7cd0cb75c7d4bd9e72205c57303d3b453cde3",
        8,
        "eccd07fc343af33534151d2a81fa149724b5788772b76834a2ac8f3dcd0a4ffb",
        28,
        "14f5d6a1dc034f4a241e13f47e5ea388c2bc5667c55e1c6e1a148c0c3835636e",
    ),
    InstallSourcePolicy(
        "failure_authority/validation.py",
        "667c0a77215f73b254fbafc82ffe64430bc15b764075c1df00275cf7c0ff95f4",
        14,
        "66686117e24624e5b6cb52f7683f421fbb9934b1f52dd57abe7abcd2484dc4f3",
        156,
        "6764a72ba1a6cea7414811bd843354f81a26ee5af9bb75986ac3901542097f5f",
    ),
    InstallSourcePolicy(
        "shared/__init__.py",
        "8a4540dea32e1b23278deb80ecf150a4d2118006aebadad4c2f5f53ae786e966",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        0,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    InstallSourcePolicy(
        "shared/adapters/__init__.py",
        "d3866d21d60a8e2986c4df628fc57e73ca788c9f077d22e66c37173c1fdfe919",
        6,
        "276e8c6f59ce94b19d423cd4ee59b38f830858b48adc59d01b242177f9fd2252",
        3,
        "d56a5b97e0b3e64ce536436ff1b7b575e0862cb014883f5345d4ffe52ad058de",
    ),
    InstallSourcePolicy(
        "shared/adapters/base.py",
        "bfc64e5f89577778fc049f655f77bbd7e865e85dbb3d1fb6870df786b471f20c",
        8,
        "e2106a93b796736d3fef8d402fc20f6d867a1d162b49f73a67188d74b11cffd7",
        17,
        "4fc84d547fe6e6041673db97a72a399971b107ddeab6342394473f04d01e2fa3",
    ),
    InstallSourcePolicy(
        "shared/adapters/claude.py",
        "eb40c4f9473cde0265aedf7648e6e5cb95fc5c3901fbc6947b5df316e4357db6",
        7,
        "19ccc85d9df4213c36adea338af6a669951e44d5ae737aaf59916ca31d13fc7a",
        15,
        "4c8c8bd31d62a81ae849312e740a45cfb3887242d1ec6785d45db9e1369cb19b",
    ),
    InstallSourcePolicy(
        "shared/adapters/codex.py",
        "c8ce1c3f0a2b661b8e1a1b2a7290b24895b3ae3a7d6707154c62f02e6c96dceb",
        6,
        "af06734cbb58afe82ca003cb6178d2b50458db30ee15a67282add72f58582ca8",
        41,
        "2f04b01c6d001944cc2dc909d3e707f43b2d9f3d51e18d3bc477977bf9181b24",
    ),
    InstallSourcePolicy(
        "shared/cliargs.py",
        "3b4b4053960f87508befe28680079843c51fa22d9ead5556d1290d9ab5b6e7b1",
        3,
        "e4d7624c3c51bfaaf38a12a3014d84e44dd1aa0523394d81f8dcdacfeba4f4a6",
        2,
        "f9df7ce52080f172c7b7f11c5bdb876307015e6891d9df73d8c699f1d97ac0b7",
    ),
    InstallSourcePolicy(
        "shared/config.py",
        "e0d284f4d5374c5df30fb230ad45686fc1335acd6572beb35343260cd4d46b2e",
        3,
        "66ae886a389340ec9573e23611f040d57861820e4dfdf14f03e3051c6c301348",
        12,
        "baa6a64959d781208b415ce2b1e1e77ea24a93f43d76890158cea8bcdb45687e",
    ),
    InstallSourcePolicy(
        "shared/fs.py",
        "13ce836d48f982ea577ead8fee8522e25e7f53c629e47dc6da9c976d155a4889",
        3,
        "249854bff8786466a7207e945ef03a11eb111d173a3b53b32cf2d4afa4dad518",
        12,
        "2bf6ad04d6a28b4bcdd14a10a92629f66606e5e2e626ff2b0ee9c24b729969e6",
    ),
    InstallSourcePolicy(
        "shared/session_capture.py",
        "a37a2c417f7e9c057359385fe93bee52792c73776d4ec5b7319271f0c0d95da2",
        6,
        "c12e7edbadf1c666dbd922f2c8e72c27e30269ed9f6f4ba20e650b5c2b24590a",
        37,
        "3444b4562ed06dd441a314c621e8acc02e1dbff142b9fbf862d55647b62bfe04",
    ),
)

_SOURCE_SHA256_BY_FILE = {
    "__init__.py": "2165d1a9ef7b239f44bdd70310bfdeab264992ba35826d82259caa235ec08a7c",
    "__main__.py": "29c2051d38869e785c3d3d874a160ba7c00409b84d92e1c3666fb41ae185db58",
    "cli.py": "ab8e7de5faa347c8c012d7d2f1a246274fcfc16387852e619febfba2f18d73a7",
    "dev_manifest/__init__.py": "92a71cd05bc65c2f0e04154421d9a038933be88a4047ee61cda7408c9c96cde1",
    "dev_manifest/__main__.py": "2b521921a35b6e91b52000689e37a0d67d070569536086b92bc41b89769a366e",
    "dev_manifest/scanner.py": "c7525fefbaefec41cbeb250327377e6dd0f2db4a91817917fdf105b9f606570f",
    "ext/connectors/coursedump/__init__.py": "ab1653ad56aeb717fd3ebd6cf602967055769a0affcba00a35e0c5b583b7d04a",
    "ext/connectors/coursedump/connector.py": "dad5434ee9c4c93d185bf67e3055247fa69b629f3dc01046cad59d00c32b4299",
    "ext/connectors/gateway/__init__.py": "55d533639c57c94bc9730d49ae0cf8b956211b927d83675ba76c88f4ae75fc27",
    "ext/connectors/gateway/connector.py": "a7530d8f15ef35077e9c7f23302f50b94abd2fa9e3519d4b04f7f2c1a861dd45",
    "ext/connectors/llmwiki/__init__.py": "37364fb75b1111a463c8450b31b1a4799ea4a6077aa771c1e2ab08fd58c3b630",
    "ext/connectors/llmwiki/connector.py": "a7c66f606920db4552129795120471b46923d68bd2d152b01f34b4bc93dde18f",
    "ext/connectors/probes/__init__.py": "1e79e4a42cab229469b6d366f8da94d3cb9873fa7850844f2298942d3c67a500",
    "ext/connectors/probes/capabilities.py": "1e9d3f50bc01256afb9e890e41925cda5939d2460393f00c4dbb5c9892fff487",
    "ext/connectors/researcher/__init__.py": "66ef7353cf7e4882fdf76f37ba187915de56434cbb6267670f8b98e13c961be6",
    "ext/connectors/researcher/connector.py": "b914b30b51b02a71ba20605e68af2585dc683979054f5621e08eea76310b090d",
    "ext/connectors/scheduler/__init__.py": "d6fa32af589c207a6ea53484dfbf6eac56aab952eed275b9d3da904f0cf83ce7",
    "ext/connectors/scheduler/connector.py": "9745395ccdc3083f17cf463e03d439d7a163ee7c4e0bec50f027e79cf8cdd276",
    "ext/connectors/scheduler/installer.py": "dc6abc948f0229dafd06c5fcf289d5c918780ef4ab2d9809c3dc720261d0c8fb",
    "ext/connectors/scheduler/recipes.py": "069128cbb88f0914e0104d48670b9a55b3fe17d6dda201f7b2843db6387616f1",
    "ext/flows/__init__.py": "7e1a13e4541cb3c8e9722a7b6c827c8b2d03182ba9616f746358d044b119dcde",
    "ext/flows/ambient/__init__.py": "b2fc039e3f58560dd674e319c2035687b6a888500fe6b5771984e7f87a6ab22c",
    "ext/flows/ambient/flow.py": "4490ae798d2592c3248f2bfc1b106056e345298f43abb8bd165e34f9ec623089",
    "ext/flows/ask/__init__.py": "992eb0436d4060502cbb788d42890c27a0086766689b156eaa373ea65d994195",
    "ext/flows/ask/flow.py": "9df4eb6dea4951ab7d5b80aec09bd09cd65c89bbb372449ec62a8aabe2632d4b",
    "ext/flows/book/__init__.py": "65223481bfb3bb9bdd6d0b602a909f335d3896709c68437d3aa8c6e4ae2291aa",
    "ext/flows/book/flow.py": "6c919f652f8292c7aa58b87c61e5804f9e8bebdf08e939e75e7b07c235d39176",
    "ext/flows/bundle/__init__.py": "2e89911da06386733a2ee055103049f72606187013d6893b04cc68e6cee786d9",
    "ext/flows/bundle/flow.py": "3ca9deeace86cda5c941b60a0a16f1a11132be4aec3318239bc3539c69804409",
    "ext/flows/distill/__init__.py": "95b240da3d0e302d499222f6e813ff0a44d947d98d028cf147befeddb1b44adb",
    "ext/flows/distill/flow.py": "e9dd7fca2cafbf8df18de14c05cdf96f770537ddadc5283fd4ff999d964c7c12",
    "ext/flows/entities/__init__.py": "04191accb836e6b34763bd603a95b04073b4b13aacd82afbb8eb0c040aa936d6",
    "ext/flows/entities/flow.py": "1baae3b6dcfc258cf961a02effd125d9a8fa815f485d12d650d960e1d84a2849",
    "ext/flows/finalize/__init__.py": "9a89bed5fa1f42ab9ad338168488f9e64fc63927adf241ee9cc7a83fcb542ee6",
    "ext/flows/finalize/flow.py": "0f555be966d59ac7e9a5042be9f8f0b696e5d2f019b43663d526d66c7af7e97a",
    "ext/flows/grill_me/__init__.py": "e395fe617f713fa2baae180e4b1070bd52afd543ef6d56d2db0ee3aaee2dbe79",
    "ext/flows/grill_me/flow.py": "822ccd89438fc36bbf9e9d89ad837dbde4acecddaa1813242cf1ea12ea33430d",
    "ext/flows/ingest/__init__.py": "9a2e574a6af61beb903fbd9a4c6cae402801664beca0a9e1b413f9331cb5c211",
    "ext/flows/ingest/flow.py": "1d9116c904b7c13c4e431118c365259dd5ee60bdd5cb9d2dfb8bbbf5de2efa5c",
    "ext/flows/lint/__init__.py": "8bceee81b7e4c5d9b5640b54df5d8c11dc626f186f81a69a4e83f6d9df136ce1",
    "ext/flows/lint/flow.py": "21fac5b580704447878562b4cfba0bf4e97d56ef4a1893c7e82dd9d288762729",
    "ext/flows/memory/__init__.py": "47d9c6d4e31922a5fa76ef1f410079f45d9d51cedb9134fb484bc5f958c3a608",
    "ext/flows/memory/flow.py": "60375cc7f263a1ac1f8ccebbc8a1786e8450a57f494bbfb29a8157da43d7665f",
    "ext/flows/mentor/__init__.py": "c38165bbafc3fe0634de4b2595b7a3a0c5f6c65dbdf59f3f333311e5d044d4f3",
    "ext/flows/mentor/flow.py": "418b8c0d02f1cc2e394611717559b043436934cda89a4fba5d1c9e1594140a6d",
    "ext/flows/obsidian/__init__.py": "1ddc96212c11ea476f5e55f826e8483a90f88090ac4fbe817e0148c64cba6200",
    "ext/flows/obsidian/flow.py": "7f6b8935c64aeab374f312131bbfcc3eeee1d9d8b360603bcc9be122b19e174d",
    "ext/flows/plan/__init__.py": "512bf3464f5c140e9cde295108cb644e169a5df8308837de9cce01c5b2bfbafe",
    "ext/flows/plan/flow.py": "4abb0e4e2be09f1b3dd19d8c4993b046f8097d7704187aedf4818a23ee5af7cc",
    "ext/flows/project/__init__.py": "ed8ab643b5d4c3a1b2890e4a031b8c06558df2bb4b52bcdb2df97a026d935678",
    "ext/flows/project/flow.py": "77a3242a9c435b2ef34bf7476e5406162625550248862beb31e08b5373eaba6e",
    "ext/flows/report/__init__.py": "0d8ce280ad9e4177e254931fbd24c56068d73065c881f0692d5b81ad36753a08",
    "ext/flows/report/flow.py": "652cb85bcf8eb5ffa02f182c0472a3a5a8a02c170d814fb3ea58d3f28611ef69",
    "ext/review/__init__.py": "057c6de64b174ce362ac0ce9e37b5a2bbdfcbc90fb47d87ca45ed23366d3c1e2",
    "ext/review/apply/__init__.py": "b1e837ca60b22d5cb6f0aedeec5b6d5349d7150ae7aaee66bf517218136aa9cd",
    "ext/review/apply/transaction.py": "9335fa704866ff049d3d2e66cdc00f47e623ee06b9b73640b0bec2620e1cfbd7",
    "ext/review/artifact/__init__.py": "8c68981cf6a01f3e10fef011f9c5db389bce9c55eecff8da3659a42cbfd15323",
    "ext/review/artifact/model.py": "0dbf620278a4ed57048804a154529e59b93662e21a0dde15a5e76f09d2835059",
    "ext/review/authority.py": "11feb95eb3bc5dfe939d34ed544d595bdbef660edca22a87ee43bac725ff5bc1",
    "ext/review/decision/__init__.py": "7e566f95141e6ae7f6324bd5f30094f87da54e8a32d9c51c69a3f36b2b1794f1",
    "ext/review/decision/model.py": "7b6446edabcbd587bd1ab9f2a4b0383801c5dc9f4cba5053bf948c16b08fe6f8",
    "ext/runs/__init__.py": "d72385116783381fad0da23b3804c77c7524ed7ccc2ade197e959db601199f9e",
    "ext/runs/outbox.py": "30bcdc594c7c08bc20c29517844acce948bd7ae9159b6d6d23e2f278e30e17f9",
    "ext/runs/store.py": "b821e6bf4d7ebc1c5b720ce66fc324d4823676184491ebc15a6f1f4adc5e187c",
    "ext/skills/__init__.py": "a6d727749a653654e8b0f8568bdee1ad3e3ea1f5f6a65c95f9d9d61a00bec71b",
    "ext/skills/installer.py": "218aed25d7a043d93eeab1ba1f3b7f82ba5b36d3e911d72f574087499b4141e4",
    "ext/skills/resources/__init__.py": "4521a3cb228c0e743f419886d227c826db4a43f06b93d736c2b14154d75470d6",
    "ext/skills/resources/catalog.py": "c92e830488d9c05a823ad9d9446de622cf729984afdefced7ed49157eac1160f",
    "ext/skills/resources/evals.py": "b3906abea5f6f920b6831b27c30d42e8f27d2135eec520c5fbde9b92cdc28054",
    "ext/skills/resources/model.py": "e0df15b001ed1431b4d1d56d5a68e138c1341a28bc2547f63b16fa4d825411bd",
    "ext/vault/config/__init__.py": "61be0378e19535ff9b3cf9a518a8d26ee934d4ffc88e6ea8ca455c464bc0cde2",
    "ext/vault/config/models.py": "f9e138f09a82996950ad4595999fb49af3a19b212bbd4fdf079d00372467dec9",
    "ext/vault/doctor/__init__.py": "9da803f4c40814d9f9e544d0d8d571c1a9e09191c56a34e6426b275286b678eb",
    "ext/vault/doctor/report.py": "35254f7164094a8179dc16615b68eb0b78daa006b39fedd13ef3c8eafbc7617e",
    "ext/vault/migrate/__init__.py": "3360ebd57953cdd009d5f3a6c2fec8c8f496a3802b367121bdaea62bc1e60fe0",
    "ext/vault/migrate/core.py": "db06ac40db4e6ddb31c83ea8616fbd4c4907bc49d92a57374dc1b710f059c8e5",
    "ext/vault/schema/__init__.py": "e5c4238d49b2a92412553177c030a079a2e753f33a7f8de56f3f3af4950ccf95",
    "ext/vault/schema/model.py": "87375e0bca674e4f1e26b807b5745d3e3849550b43701380aab27f2ec9b08ddf",
    "failure_authority/__init__.py": "d097d4ec949bdfd500f71d6c9415e0544ebc3a9dbbf5e75406947f27fdc8bf76",
    "failure_authority/catalog.py": "e34c1bcf6fdfa6e64a1cf9d4bb6748e2c4f893371a72cdfec5d4da3930902035",
    "failure_authority/registry.py": "1bb392925bfc36bf9fa326ee73d2df9da71169a795291fcae3c4ad3e695ff137",
    "failure_authority/render.py": "2308489c32b56a16539c9249be7a6666812f7d513463154802b04202a0b3159b",
    "failure_authority/validation.py": "5b6399f0e6d4f9b8ec111435bb8456bd646d5764d56a93c956bfb8c25c2ae4d6",
    "shared/__init__.py": "e3f81bcf2e8738af9bd281e68dc34333ccac5ba108bc6ddd7d6c9d8cf59c07e4",
    "shared/adapters/__init__.py": "301013c2f6bf28a6d4b183599600a83896bc212ccba5a8f8bc3681f7eaccc698",
    "shared/adapters/base.py": "beabe45c4920d59db675eda01fa20e4fd858da4ed87f4a62f4e661d173204247",
    "shared/adapters/claude.py": "48184ec31d8ffed4ca064cbe46e36bf9a046098b00db351fe0d48f66e880b2cb",
    "shared/adapters/codex.py": "1375ea25fcbe7a95c88e1f048ed0f5898ba4444f5fc68e8d3602d47d756bb81d",
    "shared/cliargs.py": "a064ad61d18fd19e534eaf564ad79501ef00bb6e9611a1adeee178879b98ce03",
    "shared/config.py": "264cb8f7db6762bf9c7554f51b6137a6793b11fd681b46abf808a370e88bc43a",
    "shared/fs.py": "2978883e33d16eaad52f9ed9486845fdffab9c2697c88bd3656221fe70e450a1",
    "shared/session_capture.py": "585f3e15f2fee5dcd6986c40155206af1a7f40c9c895b2b8bf5a19304f6f23fc",
}
_SOURCE_POLICIES = tuple(
    replace(
        policy,
        source_sha256=_SOURCE_SHA256_BY_FILE[f"ext/connectors/{policy.source_file}"],
    )
    for policy in _SOURCE_POLICIES
)
_INSTALL_SOURCE_POLICIES = tuple(
    replace(policy, source_sha256=_SOURCE_SHA256_BY_FILE[policy.source_file])
    for policy in _INSTALL_SOURCE_POLICIES
)


_UPSTREAMS = (
    UpstreamSpec(
        "tool-coursedump",
        "4837332bf2fb43ac89a506914ccb3fce30ee76e9",
        (".venv/bin/python", "-m", "pytest", "-q"),
        (
            "python3",
            "../tool-template/harness/run_checks.py",
            "--repo-root",
            ".",
        ),
    ),
    UpstreamSpec(
        "tool-researcher",
        "981de13287a9e7e966600ac1a0b00763e2d6c925",
        ("python3", "-m", "pytest", "-q"),
        (
            "python3",
            "../tool-template/harness/run_checks.py",
            "--repo-root",
            ".",
        ),
    ),
    UpstreamSpec(
        "tool-llm-wiki",
        "d7f72b401b18c9a810abd7afb47ba4897c0db3ba",
        ("python3", "-m", "pytest", "-q"),
        (
            "python3",
            "../tool-template/harness/run_checks.py",
            "--repo-root",
            ".",
        ),
    ),
    UpstreamSpec(
        "tool-scheduler",
        "ee074350b01ab9164dbfc38ed0d9fea268a30922",
        ("python3", "-m", "pytest", "-q"),
        (
            "python3",
            "../tool-template/harness/run_checks.py",
            "--repo-root",
            ".",
        ),
    ),
    UpstreamSpec(
        "tool-gateway",
        "ac970a23c050e2844504c3d1f0f0972e7354aa3f",
        ("python3", "-m", "pytest", "-q"),
        (
            "python3",
            "../tool-template/harness/run_checks.py",
            "--repo-root",
            ".",
        ),
    ),
)


_EXPECTED_SOURCE_POLICY_MANIFEST_SHA256 = (
    "23dc31983d487ac8aff70408e5623e6a3ce093edd5b8a69f87e6d729dae013cf"
)


def canonical_source_policy_manifest() -> bytes:
    """Render the complete reviewed production-source policy as canonical JSON."""

    payload = {
        "schema_version": P4_GATE_SCHEMA_VERSION,
        "connector_sources": [
            {
                "ast_sha256": policy.ast_sha256,
                "call_count": policy.call_count,
                "call_inventory_sha256": policy.call_inventory_sha256,
                "imports": list(policy.imports),
                "source_file": policy.source_file,
                "source_sha256": policy.source_sha256,
            }
            for policy in _SOURCE_POLICIES
        ],
        "install_sources": [
            {
                "ast_sha256": policy.ast_sha256,
                "call_count": policy.call_count,
                "call_inventory_sha256": policy.call_inventory_sha256,
                "import_count": policy.import_count,
                "import_inventory_sha256": policy.import_inventory_sha256,
                "source_file": policy.source_file,
                "source_sha256": policy.source_sha256,
            }
            for policy in _INSTALL_SOURCE_POLICIES
        ],
    }
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def canonical_source_policy_manifest_sha256() -> str:
    """Return the independent acceptance digest for the reviewed policy set."""

    return hashlib.sha256(canonical_source_policy_manifest()).hexdigest()


def _validate_source_policy_manifest() -> None:
    policies: tuple[ConnectorSourcePolicy | InstallSourcePolicy, ...] = (
        *_SOURCE_POLICIES,
        *_INSTALL_SOURCE_POLICIES,
    )
    if any(
        _SHA256.fullmatch(digest) is None
        for policy in policies
        for digest in (
            policy.ast_sha256,
            policy.call_inventory_sha256,
            policy.source_sha256,
        )
    ) or any(
        _SHA256.fullmatch(policy.import_inventory_sha256) is None
        for policy in _INSTALL_SOURCE_POLICIES
    ):
        raise P4GateError("source policy manifest contains an invalid digest")
    if (
        canonical_source_policy_manifest_sha256()
        != _EXPECTED_SOURCE_POLICY_MANIFEST_SHA256
    ):
        raise P4GateError("source policy manifest is not the reviewed artifact")


def canonical_connector_boundaries() -> tuple[ConnectorBoundary, ...]:
    return _BOUNDARIES


def canonical_connector_source_policies() -> tuple[ConnectorSourcePolicy, ...]:
    return _SOURCE_POLICIES


def canonical_install_source_policies() -> tuple[InstallSourcePolicy, ...]:
    return _INSTALL_SOURCE_POLICIES


def canonical_upstream_specs() -> tuple[UpstreamSpec, ...]:
    return _UPSTREAMS


def _import_inventory(tree: ast.AST) -> tuple[str, ...]:
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(
                f"import|{item.name}|{item.asname or ''}" for item in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            imports.extend(
                f"from|{node.level}|{node.module or ''}|{item.name}|{item.asname or ''}"
                for item in node.names
            )
    return tuple(sorted(imports))


def _ast_sha256(tree: ast.AST) -> str:
    dumped = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def _call_inventory(tree: ast.AST) -> tuple[int, str]:
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    calls: list[list[str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        current: ast.AST | None = node
        scope = "<module>"
        while current is not None:
            current = parents.get(current)
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = current.name
                break
        calls.append(
            [
                scope,
                ast.dump(node, annotate_fields=True, include_attributes=False),
            ]
        )
    raw = json.dumps(calls, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return len(calls), hashlib.sha256(raw).hexdigest()


def _import_inventory_sha256(imports: Sequence[str]) -> str:
    raw = json.dumps(list(imports), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()


def _import_bindings(tree: ast.AST) -> tuple[dict[str, str], dict[str, str]]:
    modules: dict[str, str] = {}
    objects: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                bound = item.asname or item.name.split(".", 1)[0]
                modules[bound] = item.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for item in node.names:
                objects[item.asname or item.name] = f"{node.module}.{item.name}"
    return modules, objects


def _call_name(node: ast.Call) -> str:
    current: ast.expr = node.func
    parts: list[str] = []
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _canonical_call_name(
    node: ast.Call, modules: Mapping[str, str], objects: Mapping[str, str]
) -> str:
    name = _call_name(node)
    if name in objects:
        return objects[name]
    first, separator, rest = name.partition(".")
    module = modules.get(first)
    if module is not None:
        return module + (separator + rest if separator else "")
    return name


def _process_calls(tree: ast.AST) -> tuple[tuple[str, str, str], ...]:
    modules, objects = _import_bindings(tree)
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    found: list[tuple[str, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _canonical_call_name(node, modules, objects)
        if name in {
            "__import__",
            "builtins.__import__",
            "eval",
            "builtins.eval",
            "exec",
            "builtins.exec",
        }:
            raise P4GateError("dynamic import or execution is forbidden")
        if name.startswith("subprocess.") and name != "subprocess.Popen":
            raise P4GateError("unregistered subprocess API is forbidden")
        if name.startswith("os.") and name not in _ALLOWED_OS_CALLS:
            raise P4GateError("unregistered os process API is forbidden")
        if name != "subprocess.Popen":
            continue
        shell = next(
            (item.value for item in node.keywords if item.arg == "shell"), None
        )
        if shell is not None and not (
            isinstance(shell, ast.Constant) and shell.value is False
        ):
            raise P4GateError("shell=True is forbidden")
        parent: ast.AST | None = node
        while parent is not None and not isinstance(
            parent, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            parent = parents.get(parent)
        first_argument = ast.unparse(node.args[0]) if node.args else ""
        found.append(
            (name, parent.name if parent is not None else "<module>", first_argument)
        )
    return tuple(found)


def _directory_source_identity(metadata: os.stat_result) -> tuple[int, ...]:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise P4GateError("runtime source parent is unsafe")
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _file_source_identity(metadata: os.stat_result) -> tuple[int, ...]:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > _MAX_RUNTIME_SOURCE_BYTES
    ):
        raise P4GateError("runtime source leaf is unsafe")
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _source_read_observer(_relative: str, _phase: str) -> None:
    """Test seam for replacement-race regressions around an opened source FD."""


def _read_python_sources(root: Path) -> dict[str, str]:
    if not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW")):
        raise P4GateError("secure runtime source traversal is unavailable")
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(root, directory_flags)
    except OSError as error:
        raise P4GateError("runtime source root is unsafe") from error
    sources: dict[str, str] = {}
    total = 0

    def walk(directory_fd: int, prefix: tuple[str, ...]) -> None:
        nonlocal total
        directory_before = _directory_source_identity(os.fstat(directory_fd))
        try:
            with os.scandir(directory_fd) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as error:
            raise P4GateError("runtime source parent is unreadable") from error
        for entry in entries:
            name = entry.name
            if (
                type(name) is not str
                or not name
                or name in {".", ".."}
                or "/" in name
                or "\\" in name
            ):
                raise P4GateError("runtime source name is unsafe")
            try:
                named_before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                raise P4GateError("runtime source entry is unreadable") from error
            if stat.S_ISLNK(named_before.st_mode):
                raise P4GateError("runtime source entry is a symlink")
            relative_parts = (*prefix, name)
            relative = "/".join(relative_parts)
            if stat.S_ISDIR(named_before.st_mode):
                try:
                    child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                except OSError as error:
                    raise P4GateError("runtime source parent is unsafe") from error
                try:
                    opened_before = _directory_source_identity(os.fstat(child_fd))
                    if opened_before != _directory_source_identity(named_before):
                        raise P4GateError("runtime source parent moved while opening")
                    walk(child_fd, relative_parts)
                    opened_after = _directory_source_identity(os.fstat(child_fd))
                    named_after = _directory_source_identity(
                        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    )
                    if opened_after != opened_before or named_after != opened_before:
                        raise P4GateError("runtime source parent changed during read")
                finally:
                    os.close(child_fd)
                continue
            if not name.endswith(".py"):
                continue
            if not stat.S_ISREG(named_before.st_mode):
                raise P4GateError("runtime source leaf is unsafe")
            try:
                file_fd = os.open(name, file_flags, dir_fd=directory_fd)
            except OSError as error:
                raise P4GateError("runtime source leaf is unsafe") from error
            try:
                opened_before = _file_source_identity(os.fstat(file_fd))
                if opened_before != _file_source_identity(named_before):
                    raise P4GateError("runtime source leaf moved while opening")
                _source_read_observer(relative, "opened")
                remaining = _MAX_RUNTIME_SOURCE_BYTES + 1
                chunks: list[bytes] = []
                while remaining:
                    block = os.read(file_fd, min(64 * 1024, remaining))
                    if not block:
                        break
                    chunks.append(block)
                    remaining -= len(block)
                raw = b"".join(chunks)
                opened_after = _file_source_identity(os.fstat(file_fd))
                named_after = _file_source_identity(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                )
                if (
                    opened_after != opened_before
                    or named_after != opened_before
                    or len(raw) != opened_before[4]
                ):
                    raise P4GateError("runtime source leaf changed during read")
                total += len(raw)
                if total > _MAX_RUNTIME_SOURCE_TOTAL_BYTES:
                    raise P4GateError("runtime source tree exceeds bound")
                sources[relative] = raw.decode("utf-8", errors="strict")
                _source_read_observer(relative, "closed")
            except UnicodeError as error:
                raise P4GateError("runtime source is not UTF-8") from error
            finally:
                os.close(file_fd)
        directory_after = _directory_source_identity(os.fstat(directory_fd))
        if directory_after != directory_before:
            raise P4GateError("runtime source parent changed during read")

    try:
        root_before = _directory_source_identity(os.fstat(root_fd))
        root_named_before = _directory_source_identity(
            os.stat(root, follow_symlinks=False)
        )
        if root_before != root_named_before:
            raise P4GateError("runtime source root moved while opening")
        walk(root_fd, ())
        root_after = _directory_source_identity(os.fstat(root_fd))
        root_named_after = _directory_source_identity(
            os.stat(root, follow_symlinks=False)
        )
        if root_after != root_before or root_named_after != root_before:
            raise P4GateError("runtime source root changed during read")
    except OSError as error:
        raise P4GateError("runtime source tree is unreadable") from error
    finally:
        os.close(root_fd)
    return sources


def audit_connector_boundaries(
    connector_root: str | os.PathLike[str],
    boundaries: Sequence[ConnectorBoundary] | None = None,
) -> tuple[ConnectorBoundary, ...]:
    """Audit every connector source, not only files named by a caller."""

    root = Path(connector_root)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise P4GateError("invalid connector root")
    records = tuple(_BOUNDARIES if boundaries is None else boundaries)
    if records != _BOUNDARIES:
        raise P4GateError("connector boundary registry must be exact")
    _validate_source_policy_manifest()
    sources = _read_python_sources(root)
    actual = tuple(sorted(sources))
    if actual != _CONNECTOR_SOURCE_FILES:
        raise P4GateError("connector source inventory is not registered")
    by_source = {record.source_file: record for record in records}
    if len(by_source) != len(records):
        raise P4GateError("duplicate connector boundary")
    policies = {policy.source_file: policy for policy in _SOURCE_POLICIES}
    if (
        len(policies) != len(_SOURCE_POLICIES)
        or tuple(sorted(policies)) != _CONNECTOR_SOURCE_FILES
    ):
        raise P4GateError("connector source policy registry is not exact")

    for relative in actual:
        try:
            source = sources[relative]
            tree = ast.parse(source, filename=relative)
        except (KeyError, SyntaxError) as error:
            raise P4GateError("connector source is unreadable") from error
        policy = policies[relative]
        if _import_inventory(tree) != policy.imports:
            raise P4GateError("connector import inventory is not allowlisted")
        calls = _process_calls(tree)
        record = by_source.get(relative)
        if record is None:
            if calls:
                raise P4GateError("subprocess boundary is not exact")
        else:
            if calls != (
                (
                    "subprocess.Popen",
                    record.process_function,
                    record.popen_argv_expression,
                ),
            ):
                raise P4GateError("subprocess boundary is not exact")
            literals = {
                node.value
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            }
            if not set(record.operations).issubset(literals):
                raise P4GateError("machine argv operation is not statically bound")
            if record.output_mode == "json":
                if (
                    "json" not in source
                    or "json.loads" not in source
                    or "--json" not in literals
                ):
                    raise P4GateError("JSON boundary has no strict JSON decoder")
            elif record.output_mode == "exit-code-only":
                if "without parsing human output" not in source:
                    raise P4GateError("exit-only boundary lacks non-parsing contract")
            else:
                raise P4GateError("unsupported connector output mode")
        call_count, call_sha256 = _call_inventory(tree)
        if (
            call_count != policy.call_count
            or call_sha256 != policy.call_inventory_sha256
        ):
            raise P4GateError("connector call inventory is not allowlisted")
        if _ast_sha256(tree) != policy.ast_sha256:
            raise P4GateError("connector AST is not allowlisted")
        if hashlib.sha256(source.encode("utf-8")).hexdigest() != policy.source_sha256:
            raise P4GateError("connector raw source is not allowlisted")
    return records


def _digest_stream(stream: object) -> tuple[int, str]:
    stream.seek(0)
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > _MAX_UPSTREAM_OUTPUT_BYTES:
            raise P4GateError("upstream command output exceeds gate bound")
        digest.update(chunk)
    return size, digest.hexdigest()


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=1.0)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _execute_command(
    argv: tuple[str, ...], cwd: Path, timeout: float
) -> CommandEvidence:
    actual = (sys.executable, *argv[1:]) if argv[0] == "python3" else argv
    started = time.monotonic()
    timed_out = False
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                actual,
                cwd=cwd,
                env=os.environ.copy(),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise P4GateError("upstream command could not start") from error
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(process)
            returncode = process.returncode if process.returncode is not None else -9
        duration_ms = max(0, int((time.monotonic() - started) * 1000))
        stdout_bytes, stdout_sha256 = _digest_stream(stdout)
        stderr_bytes, stderr_sha256 = _digest_stream(stderr)
    return CommandEvidence(
        argv,
        int(returncode),
        duration_ms,
        stdout_bytes,
        stderr_bytes,
        stdout_sha256,
        stderr_sha256,
        timed_out,
    )


def _git_output(repo: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ("git", "-C", os.fspath(repo), *arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise P4GateError("cannot inspect upstream git identity") from error
    if result.returncode != 0 or len(result.stdout) > 256:
        raise P4GateError("cannot inspect upstream git identity")
    try:
        return result.stdout.decode("ascii", errors="strict").strip()
    except UnicodeError as error:
        raise P4GateError("invalid upstream git identity") from error


def _require_clean_worktree(repo: Path) -> None:
    try:
        status = subprocess.run(
            (
                "git",
                "-C",
                os.fspath(repo),
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10.0,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise P4GateError("cannot inspect upstream worktree") from error
    if status.returncode != 0 or len(status.stdout) > 1024 * 1024:
        raise P4GateError("cannot inspect upstream worktree")
    if status.stdout:
        raise P4GateError("upstream worktree is dirty")


def _repository_snapshot(repo: Path) -> RepositorySnapshot:
    """Read a stable HEAD/tree pair and reject every tracked or untracked change."""

    _require_clean_worktree(repo)
    first_head = _git_output(repo, "rev-parse", "HEAD")
    first_tree = _git_output(repo, "rev-parse", "HEAD^{tree}")
    second_head = _git_output(repo, "rev-parse", "HEAD")
    second_tree = _git_output(repo, "rev-parse", "HEAD^{tree}")
    _require_clean_worktree(repo)
    if (
        _GIT_HEAD.fullmatch(first_head) is None
        or _GIT_HEAD.fullmatch(first_tree) is None
        or first_head != second_head
        or first_tree != second_tree
    ):
        raise P4GateError("upstream repository changed during snapshot")
    return RepositorySnapshot(first_head, first_tree, True)


def run_upstream_evidence(
    workspace_root: str | os.PathLike[str],
    *,
    timeout_per_command: float = 1800.0,
    executor: Callable[[tuple[str, ...], Path, float], CommandEvidence] | None = None,
) -> tuple[UpstreamEvidence, ...]:
    """Execute tests and baseline in every exact P4 upstream repository."""

    root = Path(workspace_root)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise P4GateError("invalid workspace root")
    if (
        isinstance(timeout_per_command, bool)
        or not isinstance(timeout_per_command, (int, float))
        or not 1 <= float(timeout_per_command) <= 7200
    ):
        raise P4GateError("invalid upstream timeout")
    run = executor or _execute_command
    evidence: list[UpstreamEvidence] = []
    for spec in _UPSTREAMS:
        repo = root / spec.repo
        if not repo.is_dir() or repo.is_symlink() or not (repo / ".git").exists():
            raise P4GateError("required upstream repository is absent")
        before_tests = _repository_snapshot(repo)
        ancestor = (
            _git_output(
                repo,
                "merge-base",
                "--is-ancestor",
                spec.accepted_head,
                before_tests.head,
            )
            == ""
        )
        tests = run(spec.test_argv, repo, float(timeout_per_command))
        after_tests = _repository_snapshot(repo)
        if after_tests != before_tests:
            raise P4GateError("upstream repository changed during tests")
        baseline = run(spec.baseline_argv, repo, float(timeout_per_command))
        after_baseline = _repository_snapshot(repo)
        if after_baseline != before_tests:
            raise P4GateError("upstream repository changed during baseline")
        evidence.append(
            UpstreamEvidence(
                1,
                spec.repo,
                spec.accepted_head,
                ancestor,
                before_tests,
                after_tests,
                after_baseline,
                tests,
                baseline,
            )
        )
    result = tuple(evidence)
    validate_upstream_evidence(result)
    return result


def validate_upstream_evidence(
    evidence: Sequence[UpstreamEvidence],
) -> tuple[UpstreamEvidence, ...]:
    """Validate observations; specs alone are deliberately insufficient."""

    records = tuple(evidence)
    if len(records) != len(_UPSTREAMS):
        raise P4GateError("upstream evidence inventory is incomplete")
    for record, spec in zip(records, _UPSTREAMS, strict=True):
        snapshots = (
            (
                record.before_tests,
                record.after_tests,
                record.after_baseline,
            )
            if isinstance(record, UpstreamEvidence)
            else ()
        )
        if (
            not isinstance(record, UpstreamEvidence)
            or type(record.schema_version) is not int
            or record.schema_version != 1
            or type(record.repo) is not str
            or record.repo != spec.repo
            or type(record.accepted_head) is not str
            or record.accepted_head != spec.accepted_head
            or record.accepted_head_is_ancestor is not True
            or len(snapshots) != 3
            or any(
                not isinstance(snapshot, RepositorySnapshot)
                or type(snapshot.head) is not str
                or _GIT_HEAD.fullmatch(snapshot.head) is None
                or type(snapshot.tree) is not str
                or _GIT_HEAD.fullmatch(snapshot.tree) is None
                or snapshot.clean is not True
                for snapshot in snapshots
            )
            or snapshots[1:] != snapshots[:1] * 2
        ):
            raise P4GateError("upstream repository evidence mismatch")
        for observed, expected in (
            (record.tests, spec.test_argv),
            (record.baseline, spec.baseline_argv),
        ):
            if (
                not isinstance(observed, CommandEvidence)
                or type(observed.argv) is not tuple
                or any(type(item) is not str for item in observed.argv)
                or observed.argv != expected
                or type(observed.returncode) is not int
                or observed.returncode != 0
                or type(observed.duration_ms) is not int
                or observed.duration_ms < 0
                or type(observed.stdout_bytes) is not int
                or not 0 <= observed.stdout_bytes <= _MAX_UPSTREAM_OUTPUT_BYTES
                or type(observed.stderr_bytes) is not int
                or not 0 <= observed.stderr_bytes <= _MAX_UPSTREAM_OUTPUT_BYTES
                or type(observed.stdout_sha256) is not str
                or _SHA256.fullmatch(observed.stdout_sha256) is None
                or type(observed.stderr_sha256) is not str
                or _SHA256.fullmatch(observed.stderr_sha256) is None
                or observed.timed_out is not False
            ):
                raise P4GateError("upstream command evidence mismatch")
    return records


def _snapshot_payload(snapshot: RepositorySnapshot) -> dict[str, object]:
    return {
        "clean": snapshot.clean,
        "head": snapshot.head,
        "tree": snapshot.tree,
    }


def _command_payload(command: CommandEvidence) -> dict[str, object]:
    return {
        "argv": list(command.argv),
        "duration_ms": command.duration_ms,
        "returncode": command.returncode,
        "stderr_bytes": command.stderr_bytes,
        "stderr_sha256": command.stderr_sha256,
        "stdout_bytes": command.stdout_bytes,
        "stdout_sha256": command.stdout_sha256,
        "timed_out": command.timed_out,
    }


def render_upstream_evidence(evidence: Sequence[UpstreamEvidence]) -> bytes:
    """Render validated evidence as one canonical, portable JSON artifact."""

    records = validate_upstream_evidence(evidence)
    return (
        _canonical(
            {
                "schema_version": P4_GATE_SCHEMA_VERSION,
                "upstreams": [
                    {
                        "accepted_head": record.accepted_head,
                        "accepted_head_is_ancestor": (record.accepted_head_is_ancestor),
                        "after_baseline": _snapshot_payload(record.after_baseline),
                        "after_tests": _snapshot_payload(record.after_tests),
                        "baseline": _command_payload(record.baseline),
                        "before_tests": _snapshot_payload(record.before_tests),
                        "repo": record.repo,
                        "schema_version": record.schema_version,
                        "tests": _command_payload(record.tests),
                    }
                    for record in records
                ],
            }
        )
        + b"\n"
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise P4GateError("duplicate upstream evidence field")
        result[key] = value
    return result


def _exact_object(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise P4GateError(f"invalid {label}")
    return value


def _parse_snapshot(value: object) -> RepositorySnapshot:
    row = _exact_object(value, frozenset({"head", "tree", "clean"}), "snapshot")
    return RepositorySnapshot(
        head=row["head"],  # type: ignore[arg-type]
        tree=row["tree"],  # type: ignore[arg-type]
        clean=row["clean"],  # type: ignore[arg-type]
    )


def _parse_command(value: object) -> CommandEvidence:
    row = _exact_object(
        value,
        frozenset(
            {
                "argv",
                "returncode",
                "duration_ms",
                "stdout_bytes",
                "stderr_bytes",
                "stdout_sha256",
                "stderr_sha256",
                "timed_out",
            }
        ),
        "command",
    )
    argv = row["argv"]
    if type(argv) is not list or any(type(item) is not str for item in argv):
        raise P4GateError("invalid command")
    return CommandEvidence(
        argv=tuple(argv),
        returncode=row["returncode"],  # type: ignore[arg-type]
        duration_ms=row["duration_ms"],  # type: ignore[arg-type]
        stdout_bytes=row["stdout_bytes"],  # type: ignore[arg-type]
        stderr_bytes=row["stderr_bytes"],  # type: ignore[arg-type]
        stdout_sha256=row["stdout_sha256"],  # type: ignore[arg-type]
        stderr_sha256=row["stderr_sha256"],  # type: ignore[arg-type]
        timed_out=row["timed_out"],  # type: ignore[arg-type]
    )


def parse_upstream_evidence(raw: bytes) -> tuple[UpstreamEvidence, ...]:
    """Strictly parse the canonical artifact; reject aliases and rewrites."""

    if type(raw) is not bytes or not raw.endswith(b"\n") or len(raw) > 1024 * 1024:
        raise P4GateError("invalid upstream evidence artifact")
    try:
        payload = json.loads(
            raw[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                P4GateError("invalid upstream evidence number")
            ),
        )
    except P4GateError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise P4GateError("invalid upstream evidence artifact") from error
    root = _exact_object(
        payload, frozenset({"schema_version", "upstreams"}), "evidence root"
    )
    rows = root["upstreams"]
    if (
        type(root["schema_version"]) is not int
        or root["schema_version"] != P4_GATE_SCHEMA_VERSION
        or type(rows) is not list
    ):
        raise P4GateError("invalid evidence root")
    records: list[UpstreamEvidence] = []
    keys = frozenset(
        {
            "schema_version",
            "repo",
            "accepted_head",
            "accepted_head_is_ancestor",
            "before_tests",
            "after_tests",
            "after_baseline",
            "tests",
            "baseline",
        }
    )
    for value in rows:
        row = _exact_object(value, keys, "upstream record")
        records.append(
            UpstreamEvidence(
                schema_version=row["schema_version"],  # type: ignore[arg-type]
                repo=row["repo"],  # type: ignore[arg-type]
                accepted_head=row["accepted_head"],  # type: ignore[arg-type]
                accepted_head_is_ancestor=row[  # type: ignore[arg-type]
                    "accepted_head_is_ancestor"
                ],
                before_tests=_parse_snapshot(row["before_tests"]),
                after_tests=_parse_snapshot(row["after_tests"]),
                after_baseline=_parse_snapshot(row["after_baseline"]),
                tests=_parse_command(row["tests"]),
                baseline=_parse_command(row["baseline"]),
            )
        )
    result = validate_upstream_evidence(records)
    if render_upstream_evidence(result) != raw:
        raise P4GateError("upstream evidence artifact is not canonical")
    return result


_ACTIVATION_NAMES = frozenset(
    {"GatewayConnector", "GatewayDeliveryService", "install_recipes"}
)


def _audit_install_source_policies(sources: Mapping[str, str]) -> None:
    connector_policies = {
        f"ext/connectors/{policy.source_file}": policy for policy in _SOURCE_POLICIES
    }
    install_policies = {
        policy.source_file: policy for policy in _INSTALL_SOURCE_POLICIES
    }
    if (
        len(connector_policies) != len(_SOURCE_POLICIES)
        or len(install_policies) != len(_INSTALL_SOURCE_POLICIES)
        or set(connector_policies).intersection(install_policies)
    ):
        raise P4GateError("install source policy registry is not exact")
    expected = tuple(sorted((*connector_policies, *install_policies)))
    actual = tuple(
        sorted(
            relative for relative in sources if not relative.startswith("ext/gates/")
        )
    )
    if actual != expected:
        raise P4GateError("runtime install source inventory is not allowlisted")
    for relative in actual:
        try:
            source = sources[relative]
            tree = ast.parse(source, filename=relative)
        except (KeyError, SyntaxError) as error:
            raise P4GateError("runtime install source is unreadable") from error
        imports = _import_inventory(tree)
        call_count, call_sha256 = _call_inventory(tree)
        connector_policy = connector_policies.get(relative)
        if connector_policy is not None:
            if (
                hashlib.sha256(source.encode("utf-8")).hexdigest()
                != connector_policy.source_sha256
                or imports != connector_policy.imports
                or _ast_sha256(tree) != connector_policy.ast_sha256
                or call_count != connector_policy.call_count
                or call_sha256 != connector_policy.call_inventory_sha256
            ):
                raise P4GateError("runtime connector source is not allowlisted")
            continue
        policy = install_policies[relative]
        if (
            hashlib.sha256(source.encode("utf-8")).hexdigest() != policy.source_sha256
            or len(imports) != policy.import_count
            or _import_inventory_sha256(imports) != policy.import_inventory_sha256
            or _ast_sha256(tree) != policy.ast_sha256
            or call_count != policy.call_count
            or call_sha256 != policy.call_inventory_sha256
        ):
            raise P4GateError("runtime install source is not allowlisted")


def _static_string(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_string(node.left)
        right = _static_string(node.right)
        return left + right if left is not None and right is not None else None
    return None


def _activation_references(sources: Mapping[str, str]) -> tuple[str, ...]:
    found: list[str] = []
    for relative in sorted(sources):
        if (
            relative.startswith("ext/connectors/gateway/")
            or relative.startswith("ext/connectors/scheduler/")
            or relative == "ext/gates/p4/registry.py"
        ):
            continue
        try:
            tree = ast.parse(sources[relative], filename=relative)
        except (KeyError, SyntaxError) as error:
            raise P4GateError("runtime source is unreadable") from error
        aliases: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(
                    item.name.split(".", 1)[0] in {"builtins", "importlib", "runpy"}
                    for item in node.names
                ):
                    found.append(f"{relative}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                for item in node.names:
                    if (
                        node.level == 0
                        and (node.module or "").split(".", 1)[0]
                        in {"builtins", "importlib", "runpy"}
                        and not (
                            relative == "ext/skills/installer.py"
                            and node.module == "importlib"
                            and item.name == "metadata"
                            and item.asname is None
                        )
                    ):
                        found.append(f"{relative}:{node.lineno}")
                    if item.name in _ACTIVATION_NAMES or (
                        item.name == "*"
                        and (node.module or "").rsplit(".", 1)[-1]
                        in {"gateway", "scheduler"}
                    ):
                        aliases.add(item.asname or item.name)
                        found.append(f"{relative}:{node.lineno}")
            elif isinstance(node, ast.Call):
                call_name = _call_name(node)
                leaf = call_name.rsplit(".", 1)[-1]
                if leaf in _ACTIVATION_NAMES or leaf in aliases:
                    found.append(f"{relative}:{node.lineno}")
                if call_name in {
                    "__import__",
                    "builtins.__import__",
                    "importlib.import_module",
                    "runpy.run_module",
                    "runpy.run_path",
                }:
                    found.append(f"{relative}:{node.lineno}")
                if call_name in {"getattr", "builtins.getattr"}:
                    attribute = node.args[1] if len(node.args) > 1 else None
                    if _static_string(attribute) in _ACTIVATION_NAMES:
                        found.append(f"{relative}:{node.lineno}")
            elif isinstance(node, ast.Subscript):
                if _static_string(node.slice) in _ACTIVATION_NAMES:
                    found.append(f"{relative}:{node.lineno}")
            value: ast.expr | None = None
            if isinstance(node, (ast.Assign, ast.NamedExpr)):
                value = node.value
            elif isinstance(node, ast.AnnAssign):
                value = node.value
            if isinstance(value, ast.Name) and (
                value.id in _ACTIVATION_NAMES or value.id in aliases
            ):
                found.append(f"{relative}:{node.lineno}")
            elif isinstance(value, ast.Attribute) and value.attr in _ACTIVATION_NAMES:
                found.append(f"{relative}:{node.lineno}")
    return tuple(found)


def audit_safe_install_defaults(
    package_root: str | os.PathLike[str],
) -> SafeInstallEvidence:
    """Prove defaults cannot install a runnable schedule or gateway transport."""

    root = Path(package_root)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise P4GateError("invalid runtime package root")
    _validate_source_policy_manifest()
    sources = _read_python_sources(root)
    _audit_install_source_policies(sources)
    recipes = canonical_recipe_descriptors()
    if not recipes or any(
        recipe.integration_status != "integration_required"
        or recipe.argv
        or recipe.every is not None
        or recipe.at is not None
        for recipe in recipes
    ):
        raise P4GateError("scheduler clean defaults are executable")
    required = tuple(
        name
        for name, parameter in inspect.signature(GatewayConnector).parameters.items()
        if parameter.default is inspect.Parameter.empty
    )
    if required != ("gateway_home", "target", "command", "cwd", "env"):
        raise P4GateError("gateway connector has an implicit configuration")
    service_required = tuple(
        name
        for name, parameter in inspect.signature(
            GatewayDeliveryService
        ).parameters.items()
        if parameter.default is inspect.Parameter.empty
    )
    if service_required != ("outbox_store", "connector", "policy"):
        raise P4GateError("gateway delivery has an implicit activation path")
    activation = _activation_references(sources)
    if activation:
        raise P4GateError("clean runtime imports an activation call")
    return SafeInstallEvidence(
        1,
        tuple(recipe.recipe_id for recipe in recipes),
        tuple(recipe.integration_status for recipe in recipes),
        required,
        activation,
    )


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise P4GateError("noncanonical gate data") from error


def _tree_digest(root: Path, *, allow_absent: bool = False) -> str:
    if not root.exists() and allow_absent:
        return hashlib.sha256(b"absent\n").hexdigest()
    try:
        metadata = root.stat(follow_symlinks=False)
    except OSError as error:
        raise P4GateError("cannot inventory protected root") from error
    if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
        raise P4GateError("protected root is not a plain directory")
    digest = hashlib.sha256()
    for path in sorted(
        root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
    ):
        try:
            relative = path.relative_to(root).as_posix()
            item = path.stat(follow_symlinks=False)
        except (OSError, ValueError) as error:
            raise P4GateError("cannot inventory protected root") from error
        if path.is_symlink() or not (
            stat.S_ISDIR(item.st_mode) or stat.S_ISREG(item.st_mode)
        ):
            raise P4GateError("protected root contains unsafe entry")
        digest.update(("d:" if stat.S_ISDIR(item.st_mode) else "f:").encode("ascii"))
        digest.update(relative.encode("utf-8", errors="strict"))
        digest.update(b"\0")
        if stat.S_ISREG(item.st_mode):
            try:
                raw = path.read_bytes()
            except OSError as error:
                raise P4GateError("cannot inventory protected root") from error
            digest.update(hashlib.sha256(raw).digest())
    return digest.hexdigest()


def _forbidden_identity(root: Path) -> str:
    """Observe only root metadata; contents remain unreadable to the E2E child."""

    try:
        metadata = root.stat(follow_symlinks=False)
    except OSError as error:
        raise P4GateError("cannot inspect forbidden-root identity") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or root.is_symlink()
        or stat.S_IMODE(metadata.st_mode) != 0
    ):
        raise P4GateError("forbidden root must be a non-traversable tripwire")
    return hashlib.sha256(
        _canonical(
            {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "mode": stat.S_IMODE(metadata.st_mode),
                "size": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
            }
        )
    ).hexdigest()


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _python_env(*roots: Path) -> dict[str, str]:
    values = os.pathsep.join(os.fspath(root) for root in roots)
    result = {"PYTHONPATH": values}
    for name in ("PATH", "LANG", "LC_ALL", "TMPDIR"):
        value = os.environ.get(name)
        if value is not None:
            result[name] = value
    return result


def _run_llmwiki_audit(
    repo: Path,
    topic: Path,
    env: Mapping[str, str],
    timeout: float,
) -> tuple[int, str]:
    """Run the real audit CLI and accept only one bounded empty JSON finding set."""

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                (sys.executable, "-m", "llmwiki", "audit", os.fspath(topic)),
                cwd=repo,
                env=dict(env),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise P4GateError("llmwiki audit could not start") from error
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            _kill_group(process)
            raise P4GateError("llmwiki audit timed out") from error
        stdout.seek(0, os.SEEK_END)
        stderr.seek(0, os.SEEK_END)
        stdout_bytes = stdout.tell()
        stderr_bytes = stderr.tell()
        if stdout_bytes > 64 * 1024 or stderr_bytes > 64 * 1024:
            raise P4GateError("llmwiki audit output exceeds bound")
        stdout.seek(0)
        stderr.seek(0)
        raw = stdout.read()
        error_raw = stderr.read()
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise P4GateError("llmwiki audit output is not JSON") from error
    if returncode != 0 or error_raw or payload != []:
        raise P4GateError("llmwiki audit found incomplete topic")
    return len(payload), hashlib.sha256(raw).hexdigest()


_RESEARCHER_IMPORT_DRIVER = r"""
import json
from pathlib import Path
import sys

import llmwiki
from researcher import checkpoint
from researcher.sources import ImportPlan, import_verified_corpus

QUOTE = "Synthetic course fact supports a bounded local workflow."
CLAIM = "A synthetic course fact supports a bounded local workflow."


class Extract:
    role = "p4-extract"

    def __call__(self, window):
        local_start = window["text"].index(QUOTE)
        start = window["start_offset"] + local_start
        return [{
            "text": CLAIM,
            "confidence": "high",
            "evidence": [{
                "window_id": window["window_id"],
                "quote": QUOTE,
                "start_offset": start,
                "end_offset": start + len(QUOTE),
            }],
            "tags": ["p4-synthetic-course"],
        }]


class Verify:
    role = "p4-verify"

    def __call__(self, candidate, window):
        accepted = candidate["text"] == CLAIM and QUOTE in window["text"]
        return {"accepted": accepted, "reason": "exact synthetic quote binding"}


payload = json.load(sys.stdin)
if type(payload) is not dict or set(payload) != {"schema_version", "plan"}:
    raise ValueError("invalid machine request")
if payload["schema_version"] != 1:
    raise ValueError("unsupported machine request")
plan = ImportPlan.from_dict(payload["plan"])
source = Path(sys.argv[1])
topics = Path(sys.argv[2])
topic = llmwiki.init_topic(
    topics,
    "Synthetic local course gate",
    slug="synthetic-course-gate",
)
receipt = import_verified_corpus(
    topic,
    source,
    plan=plan,
    approval=plan.plan_id,
    extractor=Extract(),
    verifier=Verify(),
    wiki=llmwiki,
)
claims = llmwiki.list_claims(topic, zone="staging", fields=["*"])
sources = llmwiki.read_sources(topic)
if len(claims) != 1 or len(sources) != 1:
    raise ValueError("unexpected imported corpus cardinality")
claim_id = claims[0]["id"]
source_id = sources[0]["id"]
llmwiki.promote_claims(topic, [claim_id])
page = llmwiki.put_wiki_page(
    topic,
    title="Synthetic course gate",
    claims=[claim_id],
    slug="course",
    body=("Bounded synthetic evidence context remains anchored and reviewable. " * 14)
    + f" ({claim_id})\n",
)
errors = llmwiki.validate_topic(topic)
checkpoint.save(
    topic,
    {
        "phase": "done",
        "topic": "Synthetic local course gate",
        "queue": [],
        "done": [],
        "sessions": {},
    },
)
result = {
    "schema_version": 1,
    "status": "imported",
    "topic_name": topic.name,
    "receipt": receipt.to_dict(),
    "source": {
        "id": source_id,
        "meta": sources[0].get("meta"),
    },
    "claim": {
        "id": claim_id,
        "evidence_source_id": claims[0]["evidence"][0]["source_id"],
    },
    "page": {"id": page["id"], "result": page["result"]},
    "validation_errors": errors,
}
print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
"""


def _source_plan_payload(plan: object) -> dict[str, object]:
    documents = getattr(plan, "documents", ())
    return {
        "schema_version": getattr(plan, "schema_version", None),
        "plan_id": getattr(plan, "plan_id", None),
        "status": getattr(plan, "status", None),
        "source_kind": getattr(plan, "source_kind", None),
        "corpus_sha256": getattr(plan, "corpus_sha256", None),
        "window": {
            "max_chars": getattr(plan, "window_chars", None),
            "overlap_chars": getattr(plan, "overlap_chars", None),
        },
        "documents": [
            {
                "document_id": getattr(document, "document_id", None),
                "relative_path": getattr(document, "relative_path", None),
                "title": getattr(document, "title", None),
                "sha256": getattr(document, "sha256", None),
                "size_bytes": getattr(document, "size_bytes", None),
                "window_count": getattr(document, "window_count", None),
            }
            for document in documents
        ],
    }


def _run_researcher_import(
    repo: Path,
    source: Path,
    topics: Path,
    plan: object,
    env: Mapping[str, str],
    timeout: float,
) -> tuple[dict[str, object], str]:
    request = (
        _canonical({"schema_version": 1, "plan": _source_plan_payload(plan)}) + b"\n"
    )
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                (
                    sys.executable,
                    "-c",
                    _RESEARCHER_IMPORT_DRIVER,
                    os.fspath(source),
                    os.fspath(topics),
                ),
                cwd=repo,
                env=dict(env),
                stdin=subprocess.PIPE,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise P4GateError("researcher import could not start") from error
        try:
            process.communicate(input=request, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            _kill_group(process)
            raise P4GateError("researcher import timed out") from error
        stdout.seek(0, os.SEEK_END)
        stderr.seek(0, os.SEEK_END)
        stdout_bytes = stdout.tell()
        stderr_bytes = stderr.tell()
        if stdout_bytes > 64 * 1024 or stderr_bytes > 64 * 1024:
            raise P4GateError("researcher import output exceeds bound")
        stdout.seek(0)
        stderr.seek(0)
        raw = stdout.read()
        error_raw = stderr.read()
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise P4GateError("researcher import output is not JSON") from error
    if (
        process.returncode != 0
        or error_raw
        or type(payload) is not dict
        or raw != _canonical(payload) + b"\n"
    ):
        raise P4GateError("researcher import machine boundary failed")
    return payload, hashlib.sha256(raw).hexdigest()


def _before_llmwiki_audit(_topic: Path) -> None:
    """Test seam after public writers and before the real audit command."""


def run_research_review_e2e(
    workspace_root: str | os.PathLike[str],
    scratch_root: str | os.PathLike[str],
    *,
    forbidden_roots: Sequence[str | os.PathLike[str]] = (),
    timeout: float = 20.0,
) -> E2EEvidence:
    """Run a synthetic local source through real sibling CLIs and review adapter."""

    workspace = Path(workspace_root)
    scratch = Path(scratch_root)
    if (
        not workspace.is_absolute()
        or not workspace.is_dir()
        or workspace.is_symlink()
        or not scratch.is_absolute()
        or scratch.exists()
        or scratch.parent.is_symlink()
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 1 <= float(timeout) <= 300
    ):
        raise P4GateError("invalid E2E roots or timeout")
    researcher_repo = workspace / "tool-researcher"
    llmwiki_repo = workspace / "tool-llm-wiki"
    if not researcher_repo.is_dir() or not llmwiki_repo.is_dir():
        raise P4GateError("required sibling repository is absent")
    researcher_before = _repository_snapshot(researcher_repo)
    llmwiki_before = _repository_snapshot(llmwiki_repo)
    forbidden = tuple(Path(item) for item in forbidden_roots)
    for root in forbidden:
        if (
            not root.is_absolute()
            or not root.is_dir()
            or root.is_symlink()
            or _is_within(scratch, root)
            or _is_within(root, scratch)
        ):
            raise P4GateError("unsafe forbidden-root relation")
    forbidden_before = tuple(
        (f"forbidden-{index}", _forbidden_identity(root))
        for index, root in enumerate(forbidden)
    )
    scratch_before = _tree_digest(scratch, allow_absent=True)
    try:
        scratch.mkdir(mode=0o700)
        corpus = scratch / "corpus"
        topics = scratch / "topics"
        corpus.mkdir()
        topics.mkdir()
        content = b"Synthetic course fact supports a bounded local workflow.\n"
        (corpus / "lesson.md").write_bytes(content)
        env = _python_env(researcher_repo, llmwiki_repo)
        wiki = LlmWikiConnector(
            topics_root=topics,
            command=(sys.executable, "-m", "llmwiki.cli"),
            cwd=llmwiki_repo,
            env=env,
            timeout=float(timeout),
        )
        researcher = ResearcherConnector(
            topics_root=topics,
            command=(
                sys.executable,
                "-c",
                "from researcher.cli import main; raise SystemExit(main())",
            ),
            cwd=researcher_repo,
            env=env,
            topic_boundary=wiki,
            timeout=float(timeout),
        )
        plan = researcher.source_plan(corpus, kind="local-markdown")
        if (
            plan.status != "waiting_human"
            or plan.source_kind != "local-markdown"
            or plan.upstream_exit_code != 76
            or plan.runtime_exit_code != 0
            or len(plan.documents) != 1
            or plan.documents[0].sha256 != hashlib.sha256(content).hexdigest()
        ):
            raise P4GateError("real researcher source-plan mismatch")
        topic = topics / "synthetic-course-gate"
        machine, import_sha256 = _run_researcher_import(
            researcher_repo,
            corpus,
            topics,
            plan,
            env,
            float(timeout),
        )
        machine = _exact_object(
            machine,
            frozenset(
                {
                    "schema_version",
                    "status",
                    "topic_name",
                    "receipt",
                    "source",
                    "claim",
                    "page",
                    "validation_errors",
                }
            ),
            "researcher import output",
        )
        receipt = _exact_object(
            machine["receipt"],
            frozenset(
                {
                    "schema_version",
                    "plan_id",
                    "status",
                    "documents",
                    "windows",
                    "candidates",
                    "verified",
                    "duplicates",
                }
            ),
            "researcher import receipt",
        )
        machine_source = _exact_object(
            machine["source"], frozenset({"id", "meta"}), "imported source"
        )
        machine_claim = _exact_object(
            machine["claim"],
            frozenset({"id", "evidence_source_id"}),
            "imported claim",
        )
        page = _exact_object(
            machine["page"], frozenset({"id", "result"}), "imported page"
        )
        document = plan.documents[0]
        expected_source_meta = {
            "document_id": document.document_id,
            "relative_path": document.relative_path,
            "sha256": document.sha256,
            "source_kind": plan.source_kind,
        }
        if (
            machine["schema_version"] != 1
            or machine["status"] != "imported"
            or machine["topic_name"] != topic.name
            or machine["validation_errors"] != []
            or receipt
            != {
                "schema_version": 1,
                "plan_id": plan.plan_id,
                "status": "imported",
                "documents": 1,
                "windows": 1,
                "candidates": 1,
                "verified": 1,
                "duplicates": 0,
            }
            or type(machine_source["id"]) is not str
            or _SOURCE_ID.fullmatch(machine_source["id"]) is None
            or machine_source["meta"] != expected_source_meta
            or type(machine_claim["id"]) is not str
            or _CLAIM_ID.fullmatch(machine_claim["id"]) is None
            or machine_claim["evidence_source_id"] != machine_source["id"]
            or type(page["id"]) is not str
            or page["result"] != "created"
        ):
            raise P4GateError("real researcher import output mismatch")
        before_audit = wiki.load_topic(topic)
        if (
            len(before_audit.sources) != 1
            or before_audit.sources[0].record_id != machine_source["id"]
            or before_audit.sources[0].payload.get("meta") != expected_source_meta
            or len(before_audit.final_claims) != 1
            or before_audit.final_claims[0].record_id != machine_claim["id"]
            or before_audit.final_claims[0].payload.get("evidence")
            != [
                {
                    "source_id": machine_source["id"],
                    "quote": content.decode("utf-8").strip(),
                    "stance": "supports",
                    "locator": {"type": "line", "value": "1-1"},
                }
            ]
            or len(before_audit.wiki_pages) != 1
            or before_audit.wiki_pages[0].frontmatter.get("id") != page["id"]
            or before_audit.wiki_pages[0].frontmatter.get("claims")
            != [machine_claim["id"]]
            or machine_claim["id"] not in before_audit.wiki_pages[0].body
        ):
            raise P4GateError("imported topic is not bound to source-plan")
        _before_llmwiki_audit(topic)
        audit_findings, audit_sha256 = _run_llmwiki_audit(
            llmwiki_repo, topic, env, float(timeout)
        )
        after_audit = wiki.load_topic(topic)
        if before_audit != after_audit:
            raise P4GateError("llmwiki audit changed its topic")
        imported = researcher.import_topic(topic.name)
        if (
            imported.status != "proposed"
            or imported.review.source_kind != "researcher-topic"
            or imported.review.source_ref != imported.registration.topic_ref
            or imported.review.source_sha256
            != imported.registration.topic_snapshot.sha256
            or imported.review.topic_snapshot.snapshot_sha256
            != imported.registration.topic_snapshot.sha256
            or imported.review.topic_snapshot != after_audit
        ):
            raise P4GateError("runtime review adapter mismatch")
    except P4GateError:
        raise
    except Exception as error:
        raise P4GateError("integrated research review E2E failed") from error
    forbidden_after = tuple(
        (f"forbidden-{index}", _forbidden_identity(root))
        for index, root in enumerate(forbidden)
    )
    if forbidden_after != forbidden_before:
        raise P4GateError("forbidden root changed during E2E")
    researcher_after = _repository_snapshot(researcher_repo)
    llmwiki_after = _repository_snapshot(llmwiki_repo)
    if researcher_after != researcher_before or llmwiki_after != llmwiki_before:
        raise P4GateError("sibling repository changed during E2E")
    evidence = E2EEvidence(
        schema_version=1,
        status="passed",
        researcher_head_before=researcher_before.head,
        researcher_head_after=researcher_after.head,
        llmwiki_head_before=llmwiki_before.head,
        llmwiki_head_after=llmwiki_after.head,
        source_kind=plan.source_kind,
        plan_id=plan.plan_id,
        corpus_sha256=plan.corpus_sha256,
        document_count=len(plan.documents),
        researcher_import_status=machine["status"],
        researcher_import_output_sha256=import_sha256,
        researcher_import_windows=receipt["windows"],
        researcher_import_candidates=receipt["candidates"],
        researcher_import_verified=receipt["verified"],
        researcher_import_duplicates=receipt["duplicates"],
        topic_ref=imported.registration.topic_ref,
        topic_snapshot_sha256=imported.review.topic_snapshot.snapshot_sha256,
        llmwiki_audit_status="passed",
        llmwiki_audit_findings=audit_findings,
        llmwiki_audit_sha256=audit_sha256,
        llmwiki_audited_snapshot_sha256=after_audit.snapshot_sha256,
        review_status=imported.status,
        review_source_ref=imported.review.source_ref,
        review_source_sha256=imported.review.source_sha256,
        scratch_before_sha256=scratch_before,
        scratch_after_sha256=_tree_digest(scratch),
        forbidden_before_sha256=forbidden_before,
        forbidden_after_sha256=forbidden_after,
    )
    rendered = _canonical(evidence.__dict__).decode("utf-8")
    private_markers = ("/Users/", "/home/", "file:")
    if any(marker.casefold() in rendered.casefold() for marker in private_markers):
        raise P4GateError("E2E evidence leaks a private path")
    return evidence
