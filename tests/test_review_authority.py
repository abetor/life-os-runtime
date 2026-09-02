"""P1-06 exact action capabilities and untrusted packet boundary."""

from dataclasses import replace

import pytest

from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
    authorize_task_packet,
)


def _proposal_capability(policy: AuthorityPolicy) -> ActionCapability:
    return policy.issue(
        flow_id="distill",
        action_id="commit-review-proposal",
        actor="runtime",
        authority="proposal",
        target="vault:review",
    )


def _packet(**changes: object) -> dict[str, object]:
    packet: dict[str, object] = {
        "schema_version": 1,
        "flow_id": "distill",
        "action_id": "commit-review-proposal",
        "actor": "runtime",
        "authority": "proposal",
        "target": "vault:review",
        "payload": {"artifact_ref": "review/rev_fixture.md"},
    }
    packet.update(changes)
    return packet


def test_policy_issues_exact_capability_from_canonical_matrix() -> None:
    policy = AuthorityPolicy()
    capability = _proposal_capability(policy)

    assert capability.access == "write"
    assert capability.effect_kind == "proposal-commit"
    assert capability.artifact_commit is True
    assert policy.require(capability) is capability


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("flow_id", "apply"),
        ("action_id", "commit-approved-knowledge"),
        ("actor", "runtime-human-approved"),
        ("authority", "protected-write"),
        ("target", "vault:knowledge"),
    ],
)
def test_llm_packet_cannot_elevate_or_redirect_capability(field, value) -> None:
    policy = AuthorityPolicy()
    capability = _proposal_capability(policy)

    with pytest.raises(AuthorityError, match=field):
        authorize_task_packet(
            _packet(**{field: value}), capability, policy=policy
        )


def test_packet_payload_is_detached_and_privacy_safe() -> None:
    policy = AuthorityPolicy()
    capability = _proposal_capability(policy)
    source = _packet(payload={"items": [{"ref": "review/synthetic.md"}]})

    checked = authorize_task_packet(source, capability, policy=policy)
    source["payload"]["items"][0]["ref"] = "review/changed.md"

    assert checked["payload"] == {"items": [{"ref": "review/synthetic.md"}]}
    with pytest.raises(AuthorityError, match="secret field"):
        authorize_task_packet(
            _packet(payload={"channel_token": "not-persisted"}),
            capability,
            policy=policy,
        )
    with pytest.raises(AuthorityError, match="unsafe text"):
        authorize_task_packet(
            _packet(payload={"ref": "/" + "Users" + "/private/note.md"}),
            capability,
            policy=policy,
        )


def test_unknown_action_actor_authority_and_target_fail_closed() -> None:
    policy = AuthorityPolicy()
    requests = (
        dict(
            flow_id="missing",
            action_id="commit-review-proposal",
            actor="runtime",
            authority="proposal",
            target="vault:review",
        ),
        dict(
            flow_id="distill",
            action_id="missing",
            actor="runtime",
            authority="proposal",
            target="vault:review",
        ),
        dict(
            flow_id="distill",
            action_id="commit-review-proposal",
            actor="human",
            authority="proposal",
            target="vault:review",
        ),
        dict(
            flow_id="distill",
            action_id="commit-review-proposal",
            actor="runtime",
            authority="domain-write",
            target="vault:review",
        ),
        dict(
            flow_id="distill",
            action_id="commit-review-proposal",
            actor="runtime",
            authority="proposal",
            target="vault:knowledge",
        ),
    )
    for request in requests:
        with pytest.raises(AuthorityError):
            policy.issue(**request)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: replace(value, schema_version=True),
        lambda value: replace(value, access="invoke"),
        lambda value: replace(value, effect_kind="artifact-commit"),
        lambda value: replace(value, artifact_commit=False),
        lambda value: replace(value, matrix_sha256="0" * 64),
    ],
)
def test_fabricated_or_mutated_capability_is_rejected(mutation) -> None:
    policy = AuthorityPolicy()
    with pytest.raises(AuthorityError, match="capability"):
        policy.require(mutation(_proposal_capability(policy)))


def test_capability_cannot_be_forged_or_reused_with_another_policy() -> None:
    issuer = AuthorityPolicy()
    other = AuthorityPolicy()
    capability = _proposal_capability(issuer)

    with pytest.raises(AuthorityError, match="not issued"):
        other.require(capability)
    forged = ActionCapability(**capability.__dict__)
    with pytest.raises(AuthorityError, match="not issued"):
        issuer.require(forged)


@pytest.mark.parametrize("schema_version", [True, 1.0, "1"])
def test_task_packet_schema_version_requires_exact_int(schema_version) -> None:
    policy = AuthorityPolicy()
    with pytest.raises(AuthorityError, match="schema_version"):
        authorize_task_packet(
            _packet(schema_version=schema_version),
            _proposal_capability(policy),
            policy=policy,
        )
