from __future__ import annotations

import json
from pathlib import Path

import pytest

from tool_life_os_runtime.ext.vault.config import (
    ConfigError,
    load_runtime_config,
    load_vault_config,
    render_redacted,
    resolve_precedence,
    resolve_vault,
)


def _runtime_text(
    target: Path,
    topics: Path,
    legacy: Path,
    *,
    tool_section: str = "",
) -> str:
    return f'''schema_version = 1
default_vault = "main"

[vaults.main]
path = "{target}"

[machine_knowledge]
topics_root = "{topics}"

[migration.legacy_vault]
path = "{legacy}"
read_only = true
{tool_section}
'''


def _write_runtime(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text, "utf-8")
    return path


def _valid_runtime(tmp_path: Path, *, tool_section: str = "") -> Path:
    return _write_runtime(
        tmp_path,
        _runtime_text(
            tmp_path / "clean-vault",
            tmp_path / "machine-topics",
            tmp_path / "legacy-vault",
            tool_section=tool_section,
        ),
    )


def test_public_runtime_example_is_compatible() -> None:
    config = load_runtime_config(Path(__file__).parents[1] / "deploy/config.example.toml")
    assert config.schema_version == 1
    assert config.default_vault == "main"
    assert {entry.name for entry in config.migration} == {
        "legacy_machine_knowledge",
        "legacy_vault",
    }
    assert all(entry.read_only for entry in config.migration)


@pytest.mark.parametrize("fixture", ["vault-minimal", "vault-populated"])
def test_canonical_vault_profiles_are_compatible(fixture: str) -> None:
    profile = load_vault_config(Path(__file__).parent / "fixtures" / fixture)
    assert profile.schema_version == 1
    assert profile.surface == "gated"
    assert profile.zone("knowledge").as_posix() == "knowledge"


def test_runtime_config_parses_argv_and_env_names(tmp_path: Path) -> None:
    path = _valid_runtime(
        tmp_path,
        tool_section=f'''

[tools.researcher]
argv = ["{tmp_path / 'bin' / 'researcher'}", "status", "--json"]
cwd = "{tmp_path / 'tool-researcher'}"
env = ["RESEARCH_API_TOKEN", "MODEL_ENDPOINT"]
''',
    )
    config = load_runtime_config(path)
    command = config.tools[0]
    assert command.name == "researcher"
    assert command.argv[1:] == ("status", "--json")
    assert command.env_names == ("RESEARCH_API_TOKEN", "MODEL_ENDPOINT")


def test_shell_command_string_is_rejected(tmp_path: Path) -> None:
    path = _valid_runtime(
        tmp_path,
        tool_section='''

[tools.researcher]
argv = "researcher status --json"
''',
    )
    with pytest.raises(ConfigError, match="array of strings"):
        load_runtime_config(path)


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda text: text.replace("schema_version = 1", "schema_version = true"), "schema_version"),
        (lambda text: text.replace('default_vault = "main"', 'default_vault = "missing"'), "default_vault"),
        (lambda text: text.replace("read_only = true", "read_only = false"), "read_only"),
        (lambda text: text.replace("read_only = true", "read_only = 1"), "read_only"),
        (lambda text: text.replace("read_only = true", ""), "required"),
        (lambda text: text.replace("[machine_knowledge]", 'unknown_security_field = "value"\n\n[machine_knowledge]'), "unknown"),
        (lambda text: text.replace("read_only = true", 'read_only = true\nwrite_enabled = true'), "unknown"),
    ],
)
def test_runtime_config_fails_closed_on_fields_and_types(
    tmp_path: Path, mutate, expected: str
) -> None:
    text = _runtime_text(tmp_path / "target", tmp_path / "topics", tmp_path / "legacy")
    with pytest.raises(ConfigError, match=expected):
        load_runtime_config(_write_runtime(tmp_path, mutate(text)))


@pytest.mark.parametrize("field", ["vaults", "migration"])
def test_dynamic_runtime_tables_reject_non_tables_as_config_error(
    tmp_path: Path, field: str
) -> None:
    values = {
        "vaults": f'{{ main = {{ path = "{tmp_path / "target"}" }} }}',
        "migration": f'{{ legacy = {{ path = "{tmp_path / "legacy"}", read_only = true }} }}',
    }
    values[field] = "3"
    path = _write_runtime(
        tmp_path,
        f'''schema_version = 1
default_vault = "main"
vaults = {values["vaults"]}
machine_knowledge = {{ topics_root = "{tmp_path / 'topics'}" }}
migration = {values["migration"]}
''',
    )
    with pytest.raises(ConfigError, match=field):
        load_runtime_config(path)


@pytest.mark.parametrize(
    "tool_section",
    [
        '''

[tools.researcher]
argv = ["researcher", 2]
''',
        '''

[tools.researcher]
argv = []
''',
        '''

[tools.researcher]
argv = ["researcher"]
env = ["VALID_NAME", "bad-name"]
''',
        '''

[tools.researcher]
argv = ["researcher"]
env = ["DUPLICATE", "DUPLICATE"]
''',
        '''

[tools.researcher]
argv = ["researcher"]
shell = true
''',
        '''

[tools.researcher]
argv = ["   ", "status"]
''',
    ],
)
def test_tool_contract_rejects_unsafe_shapes(tmp_path: Path, tool_section: str) -> None:
    with pytest.raises(ConfigError):
        load_runtime_config(_valid_runtime(tmp_path, tool_section=tool_section))


@pytest.mark.parametrize("relation", ["equal", "target_parent", "target_child"])
def test_vault_write_target_cannot_overlap_migration_root(
    tmp_path: Path, relation: str
) -> None:
    base = tmp_path / "shared"
    if relation == "equal":
        target, legacy = base, base
    elif relation == "target_parent":
        target, legacy = base, base / "legacy"
    else:
        target, legacy = base / "target", base
    path = _write_runtime(tmp_path, _runtime_text(target, tmp_path / "topics", legacy))
    with pytest.raises(ConfigError, match="overlaps"):
        load_runtime_config(path)


def test_machine_topics_cannot_overlap_migration_root(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy"
    path = _write_runtime(
        tmp_path,
        _runtime_text(tmp_path / "target", legacy / "topics", legacy),
    )
    with pytest.raises(ConfigError, match="overlaps"):
        load_runtime_config(path)


def test_tool_cwd_cannot_overlap_migration_root(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy"
    path = _valid_runtime(
        tmp_path,
        tool_section=f'''

[tools.researcher]
argv = ["researcher"]
cwd = "{legacy / 'child'}"
''',
    )
    text = path.read_text("utf-8").replace(str(tmp_path / "legacy-vault"), str(legacy))
    path.write_text(text, "utf-8")
    with pytest.raises(ConfigError, match="overlaps"):
        load_runtime_config(path)


def test_symlink_alias_to_migration_root_is_rejected(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    alias = tmp_path / "clean-link"
    alias.symlink_to(legacy, target_is_directory=True)
    path = _write_runtime(tmp_path, _runtime_text(alias, tmp_path / "topics", legacy))
    with pytest.raises(ConfigError, match="overlaps"):
        load_runtime_config(path)


def test_relative_runtime_path_is_rejected_without_echoing_value(tmp_path: Path) -> None:
    marker = "private-relative-marker"
    path = _write_runtime(
        tmp_path,
        _runtime_text(tmp_path / "target", tmp_path / "topics", tmp_path / "legacy").replace(
            str(tmp_path / "target"), marker
        ),
    )
    with pytest.raises(ConfigError) as caught:
        load_runtime_config(path)
    assert marker not in str(caught.value)


def test_tilde_path_is_not_treated_as_absolute(tmp_path: Path) -> None:
    text = _runtime_text(tmp_path / "target", tmp_path / "topics", tmp_path / "legacy")
    path = _write_runtime(tmp_path, text.replace(str(tmp_path / "target"), "~/clean-vault"))
    with pytest.raises(ConfigError, match="absolute"):
        load_runtime_config(path)


def test_runtime_path_control_character_is_rejected(tmp_path: Path) -> None:
    text = _runtime_text(tmp_path / "target", tmp_path / "topics", tmp_path / "legacy")
    path = _write_runtime(
        tmp_path,
        text.replace(str(tmp_path / "target"), str(tmp_path) + r"\u000bprivate"),
    )
    with pytest.raises(ConfigError, match="bounded string"):
        load_runtime_config(path)


@pytest.mark.parametrize(
    "old,new",
    [
        ('locale = "en"', r'locale = "en\u000bprivate"'),
        ('timezone = "UTC"', r'timezone = "UTC\u000bprivate"'),
        ('inbox = "inbox"', r'inbox = "inbox\u000bprivate"'),
    ],
)
def test_vault_profile_rejects_control_characters(
    tmp_path: Path, old: str, new: str
) -> None:
    source = (Path(__file__).parent / "fixtures/vault-minimal/lifeos.toml").read_text("utf-8")
    path = tmp_path / "lifeos.toml"
    path.write_text(source.replace(old, new), "utf-8")
    with pytest.raises(ConfigError, match="bounded string"):
        load_vault_config(path)


@pytest.mark.parametrize("position", [0, 1])
def test_tool_argv_rejects_control_characters(tmp_path: Path, position: int) -> None:
    argv = ["researcher", "status"]
    argv[position] += r"\u000bprivate"
    section = f'''

[tools.researcher]
argv = ["{argv[0]}", "{argv[1]}"]
'''
    with pytest.raises(ConfigError, match="bounded string"):
        load_runtime_config(_valid_runtime(tmp_path, tool_section=section))


def test_redacted_render_is_deterministic_and_contains_no_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_value = "runtime-only-sensitive-value"
    monkeypatch.setenv("RESEARCH_API_TOKEN", env_value)
    path = _valid_runtime(
        tmp_path,
        tool_section=f'''

[tools.researcher]
argv = ["{tmp_path / 'private-bin'}", "--credential", "configured-sensitive-value"]
cwd = "{tmp_path / 'private-cwd'}"
env = ["RESEARCH_API_TOKEN"]
''',
    )
    config = load_runtime_config(path)
    first = render_redacted(config)
    second = render_redacted(config)
    payload = json.loads(first)
    assert first == second
    assert payload["tools"][0]["env_names"] == ["RESEARCH_API_TOKEN"]
    assert str(tmp_path) not in first
    assert "private-bin" not in first
    assert "configured-sensitive-value" not in first
    assert env_value not in first


def test_precedence_is_cli_then_profile_then_env_then_default() -> None:
    env = {"LIFE_OS_VALUE": "from-env"}
    cli = resolve_precedence(
        cli="from-cli", profile="from-profile", env_name="LIFE_OS_VALUE", environ=env, default="default"
    )
    profile = resolve_precedence(
        cli=None, profile="from-profile", env_name="LIFE_OS_VALUE", environ=env, default="default"
    )
    environment = resolve_precedence(
        cli=None, profile=None, env_name="LIFE_OS_VALUE", environ=env, default="default"
    )
    default = resolve_precedence(
        cli=None, profile=None, env_name="LIFE_OS_VALUE", environ={}, default="default"
    )
    assert (cli.value, cli.source) == ("from-cli", "cli")
    assert (profile.value, profile.source) == ("from-profile", "profile")
    assert (environment.value, environment.source) == ("from-env", "env")
    assert (default.value, default.source) == ("default", "default")


def test_invalid_env_is_redacted_from_error() -> None:
    secret = "invalid-secret-value"
    with pytest.raises(ConfigError) as caught:
        resolve_precedence(
            cli=None,
            profile=None,
            env_name="LIFE_OS_NUMBER",
            environ={"LIFE_OS_NUMBER": secret},
            default=1,
            parse_env=int,
        )
    assert secret not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_arbitrary_env_parser_failure_cannot_leak_secret() -> None:
    secret = "runtime-parser-sensitive-value"

    def broken_parser(value: str) -> int:
        raise RuntimeError(f"cannot parse {value}")

    with pytest.raises(ConfigError) as caught:
        resolve_precedence(
            cli=None,
            profile=None,
            env_name="LIFE_OS_NUMBER",
            environ={"LIFE_OS_NUMBER": secret},
            default=1,
            parse_env=broken_parser,
        )
    assert secret not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_invalid_environment_name_and_non_string_value_fail_closed() -> None:
    with pytest.raises(ConfigError, match="name"):
        resolve_precedence(cli=None, profile=None, env_name="bad-name", environ={}, default="safe")
    with pytest.raises(ConfigError, match="value"):
        resolve_precedence(
            cli=None,
            profile=None,
            env_name="LIFE_OS_VALUE",
            environ={"LIFE_OS_VALUE": 3},  # type: ignore[dict-item]
            default="safe",
        )


def test_malformed_toml_does_not_chain_private_parser_diagnostic(tmp_path: Path) -> None:
    marker = "private-malformed-marker"
    path = _write_runtime(tmp_path, f'credential = "{marker}\n')
    with pytest.raises(ConfigError) as caught:
        load_runtime_config(path)
    assert marker not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_resolve_vault_obeys_precedence_and_rejects_unknown(tmp_path: Path) -> None:
    text = _runtime_text(tmp_path / "main", tmp_path / "topics", tmp_path / "legacy").replace(
        "[machine_knowledge]",
        f'''[vaults.secondary]
path = "{tmp_path / 'secondary'}"

[machine_knowledge]''',
    )
    config = load_runtime_config(_write_runtime(tmp_path, text))
    assert resolve_vault(
        config,
        cli_alias="main",
        profile_alias="secondary",
        environ={"LIFE_OS_VAULT": "secondary"},
    ).name == "main"
    assert resolve_vault(
        config,
        profile_alias="secondary",
        environ={"LIFE_OS_VAULT": "main"},
    ).name == "secondary"
    assert resolve_vault(config, environ={"LIFE_OS_VAULT": "secondary"}).name == "secondary"
    assert resolve_vault(config, environ={}).name == "main"
    with pytest.raises(ConfigError, match="unknown vault alias"):
        resolve_vault(config, environ={"LIFE_OS_VAULT": "legacy_vault"})


def test_vault_defaults_are_safe_when_optional_profile_values_are_absent(
    tmp_path: Path,
) -> None:
    lifeos = tmp_path / "lifeos.toml"
    lifeos.write_text(
        '''schema_version = 1

[zones]
inbox = "inbox"
review = "review"
tasks = "tasks"
projects = "projects"
knowledge = "knowledge"
memory = "agent/memory"
runs = "agent/runs"
outbox = "agent/outbox"

[surface]
default = "gated"
''',
        "utf-8",
    )
    profile = load_vault_config(lifeos)
    assert (profile.locale, profile.timezone, profile.enabled_flows) == ("ru", "UTC", ())


@pytest.mark.parametrize(
    "old,new",
    [
        ('inbox = "inbox"', 'inbox = "../escape"'),
        ('inbox = "inbox"', 'inbox = "/absolute"'),
        ('inbox = "inbox"', 'inbox = "windows\\\\escape"'),
        ('review = "review"', 'review = "inbox"'),
        ('runs = "agent/runs"', 'runs = "agent"'),
        ('default = "gated"', 'default = "automatic"'),
        ('enabled_flows = []', 'enabled_flows = ["distill", "distill"]'),
        ('[surface]', 'unexpected = true\n\n[surface]'),
    ],
)
def test_vault_profile_rejects_unsafe_or_unknown_shapes(
    tmp_path: Path, old: str, new: str
) -> None:
    source = (Path(__file__).parent / "fixtures/vault-minimal/lifeos.toml").read_text("utf-8")
    path = tmp_path / "lifeos.toml"
    path.write_text(source.replace(old, new), "utf-8")
    with pytest.raises(ConfigError):
        load_vault_config(path)


@pytest.mark.parametrize(
    "payload",
    [
        "value = " + "[" * 500 + "0" + "]" * 500,
        "schema_version = " + "9" * 5000,
    ],
)
def test_public_config_loaders_normalize_bounded_toml_decoder_failures(
    tmp_path: Path, payload: str
) -> None:
    runtime = tmp_path / "config.toml"
    profile = tmp_path / "lifeos.toml"
    runtime.write_text(payload, "utf-8")
    profile.write_text(payload, "utf-8")

    with pytest.raises(ConfigError):
        load_runtime_config(runtime)
    with pytest.raises(ConfigError):
        load_vault_config(profile)
