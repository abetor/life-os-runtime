"""Crash-reconcilable application of exact approved knowledge plans.

The public review plan is the only mutation description.  This module writes
an independent canonical apply journal under the configured run zone and uses
fd-anchored, no-follow filesystem operations for every knowledge access.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from dataclasses import dataclass, replace
from datetime import datetime
import fcntl
import hashlib
import os
from pathlib import PurePosixPath
import re
import stat
from typing import Iterator, Literal
import unicodedata
import uuid

from tool_life_os_runtime.ext.review.artifact import (
    APPLICATION_SCHEMA_VERSION,
    APPLY_JOURNAL_SCHEMA_VERSION,
    ApplicationEvidence,
    ApplyJournalEvidence,
    ApplyJournalOperation,
    MutationOperation,
    MutationPlan,
    ReviewArtifact,
    ReviewArtifactError,
    apply_journal_sha256,
    mutation_plan_sha256,
    parse_apply_journal,
    render_apply_journal,
    validate_artifact_plan,
    validate_apply_journal,
)
from tool_life_os_runtime.ext.review.authority import (
    ActionCapability,
    AuthorityError,
    AuthorityPolicy,
)
from tool_life_os_runtime.ext.review.decision import (
    ReviewDecisionError,
    require_current_approval,
)
from tool_life_os_runtime.ext.vault.schema import VaultPathResolver, VaultSchemaError


APPLY_CRASH_SEAMS = frozenset(
    {
        "before-first-replace",
        "between-replaces",
        "after-all-replaces-before-journal-committed",
        "after-journal-before-review-finalization",
    }
)

_APPLY_GRANT = {
    "flow_id": "apply",
    "action_id": "commit-approved-knowledge",
    "actor": "runtime-human-approved",
    "authority": "protected-write",
    "target": "vault:knowledge",
}
_JOURNAL_ID = re.compile(r"^apply_[a-z0-9][a-z0-9_-]{0,62}$")
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_DIRECTORY_ENTRIES = 4096
_JOURNAL_DIRECTORY = "apply-journals"
_JOURNAL_NAME = "journal.json"
_LOCK_NAME = ".lock"
_MISSING = object()


class ApplyError(ValueError):
    """An apply request is unauthorized, stale, unsafe, or unreconcilable."""


class ApplyCrash(BaseException):
    """Deterministic test-only crash raised at an explicit transaction seam."""


@dataclass(frozen=True)
class OperationPreview:
    sequence: int
    op: str
    path: str
    destination_path: str | None
    precondition_sha256: str | None
    postcondition_sha256: str


@dataclass(frozen=True)
class ApplyPreview:
    review_id: str
    plan_sha256: str
    status: str
    operations: tuple[OperationPreview, ...]


@dataclass(frozen=True)
class _ObservedFile:
    data: bytes
    digest: str
    identity: tuple[int, int, int, int, int, int]


def _fail(message: str) -> None:
    raise ApplyError(message)


def _portable_key(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail("filesystem namespace contains non-UTF-8 text")
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    ):
        _fail("filesystem namespace contains non-portable text")
    return unicodedata.normalize("NFC", value).casefold()


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _list_directory(directory_fd: int) -> tuple[str, ...]:
    try:
        entries = os.listdir(directory_fd)
    except OSError:
        _fail("vault directory cannot be inspected")
    if len(entries) > _MAX_DIRECTORY_ENTRIES:
        _fail("vault directory has too many entries")
    for entry in entries:
        _portable_key(entry)
    return tuple(entries)


def _exact_entry(directory_fd: int, name: str) -> bool:
    wanted = _portable_key(name)
    matches = [entry for entry in _list_directory(directory_fd) if _portable_key(entry) == wanted]
    if len(matches) > 1 or (matches and matches[0] != name):
        _fail("vault contains a portable namespace collision")
    return bool(matches)


def _open_directory_at(directory_fd: int, name: str) -> int:
    if not _exact_entry(directory_fd, name):
        _fail("required vault directory is missing")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    child_fd: int | None = None
    try:
        child_fd = os.open(name, flags, dir_fd=directory_fd)
        opened = os.fstat(child_fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        if child_fd is not None:
            os.close(child_fd)
        _fail("vault path is not a safe directory")
    if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != _identity(named):
        os.close(child_fd)
        _fail("vault directory changed while it was opened")
    return child_fd


def _open_or_create_directory_at(directory_fd: int, name: str) -> int:
    exists = _exact_entry(directory_fd, name)
    if not exists:
        try:
            os.mkdir(name, 0o700, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except FileExistsError:
            _fail("vault directory appeared during creation")
        except OSError:
            _fail("vault directory cannot be created")
    return _open_directory_at(directory_fd, name)


def _read_fd_bounded(fd: int) -> tuple[bytes, os.stat_result]:
    try:
        before = os.fstat(fd)
    except OSError:
        _fail("vault file cannot be inspected")
    if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_FILE_BYTES:
        _fail("vault file must be a bounded regular file")
    chunks: list[bytes] = []
    remaining = _MAX_FILE_BYTES + 1
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
    except OSError:
        _fail("vault file cannot be read")
    data = b"".join(chunks)
    if len(data) > _MAX_FILE_BYTES or _identity(before) != _identity(after):
        _fail("vault file changed during bounded read")
    return data, after


def _observe_at(directory_fd: int, name: str) -> _ObservedFile | None:
    if not _exact_entry(directory_fd, name):
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError:
        _fail("vault leaf is not a safe regular file")
    try:
        data, opened = _read_fd_bounded(fd)
        try:
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            _fail("vault leaf changed during bounded read")
        if _identity(opened) != _identity(named):
            _fail("vault leaf changed during bounded read")
        return _ObservedFile(data, hashlib.sha256(data).hexdigest(), _identity(opened))
    finally:
        os.close(fd)


def _write_exclusive_at(directory_fd: int, name: str, data: bytes) -> None:
    if len(data) > _MAX_FILE_BYTES:
        _fail("prepared apply blob is too large")
    if _exact_entry(directory_fd, name):
        _fail("prepared apply blob already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except FileExistsError:
        _fail("prepared apply blob already exists")
    except OSError:
        _fail("prepared apply blob cannot be created")
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                _fail("prepared apply blob cannot be written")
            offset += written
        os.fsync(fd)
    except OSError:
        _fail("prepared apply blob cannot be written")
    finally:
        os.close(fd)
    os.fsync(directory_fd)


def _ensure_blob(directory_fd: int, name: str, data: bytes) -> None:
    existing = _observe_at(directory_fd, name)
    if existing is None:
        _write_exclusive_at(directory_fd, name, data)
    elif existing.data != data:
        _fail("prepared apply blob conflicts with durable state")


def _atomic_write_at(
    directory_fd: int,
    name: str,
    data: bytes,
    *,
    expected: bytes | object = _MISSING,
) -> None:
    current = _observe_at(directory_fd, name)
    if expected is _MISSING:
        if current is not None:
            _fail("durable apply journal appeared unexpectedly")
    elif current is None or current.data != expected:
        _fail("durable apply journal changed unexpectedly")
    temporary = f".{name}.{uuid.uuid4().hex}.tmp"
    _write_exclusive_at(directory_fd, temporary, data)
    try:
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        _fail("durable apply journal cannot be committed")


def _rename_noreplace(
    source_fd: int, source: str, destination_fd: int, destination: str
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source_raw = os.fsencode(source)
    destination_raw = os.fsencode(destination)
    if hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(
            source_fd,
            ctypes.c_char_p(source_raw),
            destination_fd,
            ctypes.c_char_p(destination_raw),
            0x00000004,
        )
        if result == 0:
            return
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    if hasattr(libc, "renameat2"):
        result = libc.renameat2(
            source_fd,
            ctypes.c_char_p(source_raw),
            destination_fd,
            ctypes.c_char_p(destination_raw),
            1,
        )
        if result == 0:
            return
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    os.link(
        source,
        destination,
        src_dir_fd=source_fd,
        dst_dir_fd=destination_fd,
        follow_symlinks=False,
    )
    source_metadata = os.stat(source, dir_fd=source_fd, follow_symlinks=False)
    destination_metadata = os.stat(
        destination, dir_fd=destination_fd, follow_symlinks=False
    )
    if (source_metadata.st_dev, source_metadata.st_ino) != (
        destination_metadata.st_dev,
        destination_metadata.st_ino,
    ):
        os.unlink(destination, dir_fd=destination_fd)
        _fail("vault leaf changed during exclusive rename")
    os.unlink(source, dir_fd=source_fd)


def _publish_bytes(directory_fd: int, name: str, data: bytes, token: str) -> None:
    temporary = f".lifeos-apply-{token}-{uuid.uuid4().hex}.new"
    _write_exclusive_at(directory_fd, temporary, data)
    try:
        os.link(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        _fail("knowledge target appeared during publish")


def _remove_exact(
    directory_fd: int,
    name: str,
    expected_digest: str,
    quarantine: str,
) -> None:
    if _exact_entry(directory_fd, quarantine):
        _fail("apply quarantine name is occupied")
    try:
        _rename_noreplace(directory_fd, name, directory_fd, quarantine)
    except OSError:
        _fail("knowledge target changed during removal")
    moved = _observe_at(directory_fd, quarantine)
    if moved is None or moved.digest != expected_digest:
        try:
            _rename_noreplace(directory_fd, quarantine, directory_fd, name)
        except OSError:
            pass
        _fail("foreign knowledge replacement was preserved")
    try:
        os.unlink(quarantine, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError:
        _fail("verified knowledge target cannot be removed")


class AtomicApply:
    """Apply one exact approved plan and reconcile its durable journal."""

    def __init__(self, resolver: VaultPathResolver, policy: AuthorityPolicy) -> None:
        if not isinstance(resolver, VaultPathResolver):
            _fail("atomic apply requires a vault path resolver")
        if not isinstance(policy, AuthorityPolicy):
            _fail("atomic apply requires its issuing authority policy")
        self._resolver = resolver
        self._policy = policy
        self._zone_identities: dict[str, tuple[int, int]] = {}
        for symbolic_zone in ("knowledge", "agent/runs"):
            try:
                path = resolver.resolve(
                    symbolic_zone,
                    ".",
                    for_write=True,
                    allow_archive=True,
                    must_exist=True,
                )
                metadata = os.stat(path, follow_symlinks=False)
            except (OSError, VaultSchemaError) as error:
                raise ApplyError("configured vault zone cannot be bound safely") from error
            if not stat.S_ISDIR(metadata.st_mode):
                _fail("configured vault zone cannot be bound safely")
            self._zone_identities[symbolic_zone] = (
                metadata.st_dev,
                metadata.st_ino,
            )

    def _require_capability(self, capability: ActionCapability) -> None:
        try:
            grant = self._policy.require(capability)
        except AuthorityError as error:
            raise ApplyError(str(error)) from None
        for field, expected in _APPLY_GRANT.items():
            if getattr(grant, field) != expected:
                _fail("capability does not authorize protected knowledge apply")
        if grant.access != "write" or not grant.artifact_commit:
            _fail("capability does not authorize protected knowledge commit")

    def _validate_gate(
        self,
        artifact: ReviewArtifact,
        plan: MutationPlan,
        capability: ActionCapability,
        *,
        journal: ApplyJournalEvidence | None = None,
    ) -> str:
        self._require_capability(capability)
        try:
            if artifact.status == "applied":
                if journal is None:
                    _fail("applied retry requires its exact committed journal")
                validate_artifact_plan(artifact, plan, apply_journal=journal)
            else:
                require_current_approval(artifact, plan)
                validate_artifact_plan(artifact, plan)
        except (ReviewArtifactError, ReviewDecisionError) as error:
            raise ApplyError(str(error)) from None
        return mutation_plan_sha256(plan)

    @contextmanager
    def _open_zone(self, symbolic_zone: str) -> Iterator[int]:
        try:
            resolved = self._resolver.resolve(
                symbolic_zone, ".", for_write=True, allow_archive=True, must_exist=True
            )
        except VaultSchemaError as error:
            raise ApplyError(str(error)) from None
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd: int | None = None
        try:
            fd = os.open(resolved, flags)
            opened = os.fstat(fd)
            named = os.stat(resolved, follow_symlinks=False)
        except OSError:
            if fd is not None:
                os.close(fd)
            _fail("configured vault zone is not a safe directory")
        if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != _identity(named):
            os.close(fd)
            _fail("configured vault zone changed while it was opened")
        if (opened.st_dev, opened.st_ino) != self._zone_identities[symbolic_zone]:
            os.close(fd)
            _fail("configured vault zone identity changed")
        try:
            yield fd
        finally:
            os.close(fd)

    @staticmethod
    def _relative_parts(path: str) -> tuple[str, ...]:
        parts = PurePosixPath(path).parts
        if len(parts) < 2 or parts[0] != "knowledge":
            _fail("mutation path is outside knowledge")
        return parts[1:]

    @contextmanager
    def _open_parent(self, knowledge_fd: int, path: str) -> Iterator[tuple[int, str]]:
        parts = self._relative_parts(path)
        current_fd = os.dup(knowledge_fd)
        try:
            for part in parts[:-1]:
                child_fd = _open_directory_at(current_fd, part)
                os.close(current_fd)
                current_fd = child_fd
            yield current_fd, parts[-1]
        finally:
            os.close(current_fd)

    @contextmanager
    def _transaction(self, journal_id: str, *, create: bool) -> Iterator[int]:
        if not isinstance(journal_id, str) or _JOURNAL_ID.fullmatch(journal_id) is None:
            _fail("journal_id has invalid syntax")
        with self._open_zone("agent/runs") as runs_fd:
            if create:
                journals_fd = _open_or_create_directory_at(runs_fd, _JOURNAL_DIRECTORY)
            else:
                journals_fd = _open_directory_at(runs_fd, _JOURNAL_DIRECTORY)
            try:
                if create:
                    transaction_fd = _open_or_create_directory_at(journals_fd, journal_id)
                else:
                    transaction_fd = _open_directory_at(journals_fd, journal_id)
            finally:
                os.close(journals_fd)
            lock_fd: int | None = None
            try:
                flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                _exact_entry(transaction_fd, _LOCK_NAME)
                lock_fd = os.open(_LOCK_NAME, flags, 0o600, dir_fd=transaction_fd)
                lock_opened = os.fstat(lock_fd)
                lock_named = os.stat(
                    _LOCK_NAME, dir_fd=transaction_fd, follow_symlinks=False
                )
                if not stat.S_ISREG(lock_opened.st_mode) or _identity(lock_opened) != _identity(lock_named):
                    _fail("apply transaction lock is unsafe")
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                yield transaction_fd
            finally:
                try:
                    if lock_fd is not None:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                        os.close(lock_fd)
                finally:
                    os.close(transaction_fd)

    @staticmethod
    def _blob_name(sequence: int, kind: str) -> str:
        return f"op-{sequence:03d}.{kind}.bin"

    @staticmethod
    def _backup_name(journal_id: str, sequence: int) -> str:
        token = hashlib.sha256(journal_id.encode("ascii")).hexdigest()[:12]
        return f".lifeos-apply-{token}-{sequence:03d}.old"

    @staticmethod
    def _quarantine_name(journal_id: str, sequence: int, side: str) -> str:
        token = hashlib.sha256(journal_id.encode("ascii")).hexdigest()[:12]
        return f".lifeos-apply-{token}-{sequence:03d}-{side}.remove"

    @staticmethod
    def _journal_for_plan(
        artifact: ReviewArtifact,
        plan: MutationPlan,
        *,
        journal_id: str,
        committed_at: str,
    ) -> ApplyJournalEvidence:
        if not artifact.decisions:
            _fail("apply journal requires explicit approval evidence")
        try:
            journal_time = datetime.fromisoformat(committed_at[:-1] + "+00:00")
            approval_time = datetime.fromisoformat(
                artifact.decisions[-1].at[:-1] + "+00:00"
            )
        except (AttributeError, TypeError, ValueError):
            _fail("apply journal timestamp is invalid")
        if journal_time < approval_time:
            _fail("apply journal timestamp cannot precede approval")
        return ApplyJournalEvidence(
            schema_version=APPLY_JOURNAL_SCHEMA_VERSION,
            journal_id=journal_id,
            review_id=artifact.review_id,
            plan_sha256=mutation_plan_sha256(plan),
            status="prepared",
            committed_at=committed_at,
            operations=tuple(
                ApplyJournalOperation(
                    sequence=index,
                    op=operation.op,
                    path=operation.path,
                    destination_path=operation.destination_path,
                    precondition_sha256=operation.precondition_sha256,
                    postcondition_sha256=operation.postcondition_sha256,
                    status="pending",
                )
                for index, operation in enumerate(plan.operations, start=1)
            ),
        )

    @staticmethod
    def _journal_bytes(journal: ApplyJournalEvidence) -> bytes:
        try:
            return render_apply_journal(journal)
        except ReviewArtifactError as error:
            raise ApplyError(str(error)) from None

    @staticmethod
    def _load_journal(transaction_fd: int) -> tuple[ApplyJournalEvidence, bytes]:
        observed = _observe_at(transaction_fd, _JOURNAL_NAME)
        if observed is None:
            _fail("durable apply journal is missing")
        try:
            return parse_apply_journal(observed.data), observed.data
        except ReviewArtifactError as error:
            raise ApplyError(str(error)) from None

    @staticmethod
    def _store_journal(
        transaction_fd: int,
        journal: ApplyJournalEvidence,
        *,
        previous: bytes | object,
    ) -> bytes:
        raw = AtomicApply._journal_bytes(journal)
        _atomic_write_at(
            transaction_fd,
            _JOURNAL_NAME,
            raw,
            expected=previous,
        )
        return raw

    def _operation_bytes(
        self, knowledge_fd: int, operation: MutationOperation
    ) -> tuple[bytes | None, bytes]:
        with self._open_parent(knowledge_fd, operation.path) as (parent_fd, leaf):
            source = _observe_at(parent_fd, leaf)
        if operation.op == "create":
            if source is not None:
                _fail("create precondition requires an absent knowledge target")
            assert operation.content is not None
            return None, operation.content.encode("utf-8")
        if source is None or source.digest != operation.precondition_sha256:
            _fail("knowledge precondition hash does not match")
        if operation.op == "update":
            assert operation.content is not None
            new = operation.content.encode("utf-8")
        else:
            new = source.data
        if hashlib.sha256(new).hexdigest() != operation.postcondition_sha256:
            _fail("knowledge postcondition bytes do not match the plan")
        if operation.destination_path is not None:
            with self._open_parent(
                knowledge_fd, operation.destination_path
            ) as (destination_fd, destination_leaf):
                if _observe_at(destination_fd, destination_leaf) is not None:
                    _fail("move/archive destination must be absent")
        return source.data, new

    def dry_run(
        self,
        artifact: ReviewArtifact,
        plan: MutationPlan,
        *,
        capability: ActionCapability,
    ) -> ApplyPreview:
        """Validate approval, authority, namespace, and all current hashes."""

        plan_hash = self._validate_gate(artifact, plan, capability)
        with self._open_zone("knowledge") as knowledge_fd:
            for operation in plan.operations:
                self._operation_bytes(knowledge_fd, operation)
        return ApplyPreview(
            review_id=artifact.review_id,
            plan_sha256=plan_hash,
            status="ready",
            operations=tuple(
                OperationPreview(
                    sequence=index,
                    op=operation.op,
                    path=operation.path,
                    destination_path=operation.destination_path,
                    precondition_sha256=operation.precondition_sha256,
                    postcondition_sha256=operation.postcondition_sha256,
                )
                for index, operation in enumerate(plan.operations, start=1)
            ),
        )

    def prepare(
        self,
        artifact: ReviewArtifact,
        plan: MutationPlan,
        *,
        journal_id: str,
        committed_at: str,
        capability: ActionCapability,
    ) -> ApplyJournalEvidence:
        """Durably stage every old/new blob before the first knowledge replace."""

        self._validate_gate(artifact, plan, capability)
        candidate = self._journal_for_plan(
            artifact, plan, journal_id=journal_id, committed_at=committed_at
        )
        candidate_raw = self._journal_bytes(candidate)
        try:
            with self._transaction(journal_id, create=False) as transaction_fd:
                journal, _raw = self._load_journal(transaction_fd)
                self._validate_journal_binding(artifact, plan, journal)
                if journal.committed_at != committed_at:
                    _fail("retry changed the journal timestamp")
                self._verify_staged_blobs(transaction_fd, plan)
                return journal
        except ApplyError as error:
            if str(error) not in {
                "required vault directory is missing",
                "durable apply journal is missing",
            }:
                raise
        with self._open_zone("knowledge") as knowledge_fd:
            staged = tuple(
                self._operation_bytes(knowledge_fd, operation)
                for operation in plan.operations
            )
        with self._transaction(journal_id, create=True) as transaction_fd:
            existing = _observe_at(transaction_fd, _JOURNAL_NAME)
            if existing is not None:
                try:
                    journal = parse_apply_journal(existing.data)
                except ReviewArtifactError as error:
                    raise ApplyError(str(error)) from None
                self._validate_journal_binding(artifact, plan, journal)
                if journal.committed_at != committed_at:
                    _fail("retry changed the journal timestamp")
                self._verify_staged_blobs(transaction_fd, plan, staged)
                return journal
            for index, (old, new) in enumerate(staged, start=1):
                if old is not None:
                    _ensure_blob(transaction_fd, self._blob_name(index, "old"), old)
                _ensure_blob(transaction_fd, self._blob_name(index, "new"), new)
            self._store_journal(transaction_fd, candidate, previous=_MISSING)
        return parse_apply_journal(candidate_raw)

    def _verify_staged_blobs(
        self,
        transaction_fd: int,
        plan: MutationPlan,
        staged: tuple[tuple[bytes | None, bytes], ...] | None = None,
    ) -> None:
        for index, operation in enumerate(plan.operations, start=1):
            old_expected = None if staged is None else staged[index - 1][0]
            new_expected = None if staged is None else staged[index - 1][1]
            old = _observe_at(transaction_fd, self._blob_name(index, "old"))
            new = _observe_at(transaction_fd, self._blob_name(index, "new"))
            if operation.op == "create":
                if old is not None:
                    _fail("create transaction contains an unexpected old blob")
            elif old is None or old.digest != operation.precondition_sha256:
                _fail("prepared old blob does not match the plan")
            if new is None or new.digest != operation.postcondition_sha256:
                _fail("prepared new blob does not match the plan")
            if old_expected is not None and old.data != old_expected:
                _fail("prepared old blob changed since validation")
            if new_expected is not None and new.data != new_expected:
                _fail("prepared new blob changed since validation")

    @staticmethod
    def _validate_journal_binding(
        artifact: ReviewArtifact,
        plan: MutationPlan,
        journal: ApplyJournalEvidence,
    ) -> None:
        if journal.review_id != artifact.review_id:
            _fail("apply journal belongs to another review")
        if journal.plan_sha256 != mutation_plan_sha256(plan):
            _fail("apply journal belongs to another mutation plan")
        if not artifact.decisions:
            _fail("apply journal requires explicit approval evidence")
        if datetime.fromisoformat(
            journal.committed_at[:-1] + "+00:00"
        ) < datetime.fromisoformat(
            artifact.decisions[-1].at[:-1] + "+00:00"
        ):
            _fail("apply journal timestamp cannot precede approval")
        if len(journal.operations) != len(plan.operations):
            _fail("apply journal operation count changed")
        for evidence, operation in zip(journal.operations, plan.operations):
            if (
                evidence.op,
                evidence.path,
                evidence.destination_path,
                evidence.precondition_sha256,
                evidence.postcondition_sha256,
            ) != (
                operation.op,
                operation.path,
                operation.destination_path,
                operation.precondition_sha256,
                operation.postcondition_sha256,
            ):
                _fail("apply journal operation differs from the mutation plan")

    def _observe_path(self, knowledge_fd: int, path: str) -> _ObservedFile | None:
        with self._open_parent(knowledge_fd, path) as (parent_fd, leaf):
            return _observe_at(parent_fd, leaf)

    def _observe_backup(
        self,
        knowledge_fd: int,
        operation: MutationOperation,
        journal_id: str,
        sequence: int,
    ) -> _ObservedFile | None:
        with self._open_parent(knowledge_fd, operation.path) as (parent_fd, _leaf):
            return _observe_at(parent_fd, self._backup_name(journal_id, sequence))

    def _classify(
        self,
        knowledge_fd: int,
        operation: MutationOperation,
        journal_id: str,
        sequence: int,
    ) -> Literal["old", "partial", "new", "foreign"]:
        source = self._observe_path(knowledge_fd, operation.path)
        backup = self._observe_backup(
            knowledge_fd, operation, journal_id, sequence
        )
        destination = (
            None
            if operation.destination_path is None
            else self._observe_path(knowledge_fd, operation.destination_path)
        )
        pre = operation.precondition_sha256
        post = operation.postcondition_sha256
        if backup is not None and backup.digest != pre:
            return "foreign"
        if operation.op == "create":
            if backup is not None:
                return "foreign"
            if source is None:
                return "old"
            return "new" if source.digest == post else "foreign"
        if operation.op == "update":
            if source is not None and source.digest == pre and backup is None:
                return "old"
            if source is None and backup is not None:
                return "partial"
            if source is not None and source.digest == post and (
                backup is None or backup.digest == pre
            ):
                return "new"
            return "foreign"
        if source is not None and source.digest == pre and destination is None and backup is None:
            return "old"
        if source is None and destination is None and backup is not None:
            return "partial"
        if source is None and destination is not None and destination.digest == post and (
            backup is None or backup.digest == pre
        ):
            return "new"
        return "foreign"

    def _move_source_to_backup(
        self,
        knowledge_fd: int,
        operation: MutationOperation,
        journal_id: str,
        sequence: int,
    ) -> None:
        backup = self._backup_name(journal_id, sequence)
        with self._open_parent(knowledge_fd, operation.path) as (parent_fd, leaf):
            if _exact_entry(parent_fd, backup):
                _fail("apply backup name is occupied")
            try:
                _rename_noreplace(parent_fd, leaf, parent_fd, backup)
            except OSError:
                _fail("knowledge source changed during commit")
            moved = _observe_at(parent_fd, backup)
            if moved is None or moved.digest != operation.precondition_sha256:
                try:
                    _rename_noreplace(parent_fd, backup, parent_fd, leaf)
                except OSError:
                    pass
                _fail("foreign knowledge replacement was preserved")
            os.fsync(parent_fd)

    def _publish_new(
        self,
        knowledge_fd: int,
        operation: MutationOperation,
        data: bytes,
        journal_id: str,
        sequence: int,
    ) -> None:
        target = operation.path if operation.destination_path is None else operation.destination_path
        token = f"{hashlib.sha256(journal_id.encode('ascii')).hexdigest()[:12]}-{sequence:03d}"
        with self._open_parent(knowledge_fd, target) as (parent_fd, leaf):
            if _observe_at(parent_fd, leaf) is not None:
                _fail("knowledge destination appeared during commit")
            _publish_bytes(parent_fd, leaf, data, token)

    def _commit_operation(
        self,
        knowledge_fd: int,
        transaction_fd: int,
        operation: MutationOperation,
        journal_id: str,
        sequence: int,
        state: Literal["old", "partial", "new", "foreign"],
    ) -> None:
        new = _observe_at(transaction_fd, self._blob_name(sequence, "new"))
        if new is None or new.digest != operation.postcondition_sha256:
            _fail("prepared new blob is missing or changed")
        if state == "new":
            return
        if state == "foreign":
            _fail("foreign knowledge replacement prevents reconciliation")
        if state == "old" and operation.op != "create":
            self._move_source_to_backup(
                knowledge_fd, operation, journal_id, sequence
            )
        self._publish_new(
            knowledge_fd, operation, new.data, journal_id, sequence
        )
        if self._classify(
            knowledge_fd, operation, journal_id, sequence
        ) != "new":
            _fail("knowledge postcondition was not established")

    def _cleanup_backup(
        self,
        knowledge_fd: int,
        transaction_fd: int,
        operation: MutationOperation,
        journal_id: str,
        sequence: int,
    ) -> None:
        if operation.op == "create":
            return
        backup = self._backup_name(journal_id, sequence)
        with self._open_parent(knowledge_fd, operation.path) as (parent_fd, _leaf):
            observed = _observe_at(parent_fd, backup)
            if observed is None:
                return
            if observed.digest != operation.precondition_sha256:
                _fail("foreign apply backup prevents cleanup")
            durable_name = self._blob_name(sequence, "live-old")
            durable = _observe_at(transaction_fd, durable_name)
            if durable is not None:
                if durable.digest != operation.precondition_sha256:
                    _fail("durable apply backup conflicts with knowledge")
                _fail("apply backup unexpectedly exists in both namespaces")
            try:
                _rename_noreplace(parent_fd, backup, transaction_fd, durable_name)
                os.fsync(parent_fd)
                os.fsync(transaction_fd)
            except OSError:
                _fail("verified apply backup cannot be made durable")
            moved = _observe_at(transaction_fd, durable_name)
            if moved is None or moved.digest != operation.precondition_sha256:
                try:
                    _rename_noreplace(
                        transaction_fd, durable_name, parent_fd, backup
                    )
                except OSError:
                    pass
                _fail("foreign apply backup was preserved")

    def commit(
        self,
        artifact: ReviewArtifact,
        plan: MutationPlan,
        *,
        journal_id: str,
        capability: ActionCapability,
        crash_at: str | None = None,
    ) -> ApplyJournalEvidence:
        """Commit all prepared replacements; retry always converges to all-new."""

        if crash_at is not None and crash_at not in APPLY_CRASH_SEAMS:
            _fail("unknown apply crash seam")
        with self._transaction(journal_id, create=False) as transaction_fd:
            journal, journal_raw = self._load_journal(transaction_fd)
            self._validate_gate(
                artifact, plan, capability, journal=journal if artifact.status == "applied" else None
            )
            self._validate_journal_binding(artifact, plan, journal)
            self._verify_staged_blobs(transaction_fd, plan)
            if journal.status == "rolled_back":
                _fail("rolled-back apply journal cannot be committed")
            with self._open_zone("knowledge") as knowledge_fd:
                states = tuple(
                    self._classify(knowledge_fd, operation, journal_id, index)
                    for index, operation in enumerate(plan.operations, start=1)
                )
                if "foreign" in states:
                    _fail("foreign knowledge replacement prevents commit")
                if journal.status == "committed":
                    if any(state != "new" for state in states):
                        _fail("committed journal disagrees with knowledge bytes")
                    return journal
                committing = replace(journal, status="committing")
                journal_raw = self._store_journal(
                    transaction_fd, committing, previous=journal_raw
                )
                journal = committing
                if crash_at == "before-first-replace":
                    raise ApplyCrash(crash_at)
                for index, (operation, state) in enumerate(
                    zip(plan.operations, states), start=1
                ):
                    self._commit_operation(
                        knowledge_fd,
                        transaction_fd,
                        operation,
                        journal_id,
                        index,
                        state,
                    )
                    updated_operations = tuple(
                        replace(item, status="committed")
                        if item.sequence == index
                        else item
                        for item in journal.operations
                    )
                    journal = replace(journal, operations=updated_operations)
                    journal_raw = self._store_journal(
                        transaction_fd, journal, previous=journal_raw
                    )
                    if crash_at == "between-replaces" and index < len(plan.operations):
                        raise ApplyCrash(crash_at)
                for index, operation in enumerate(plan.operations, start=1):
                    self._cleanup_backup(
                        knowledge_fd,
                        transaction_fd,
                        operation,
                        journal_id,
                        index,
                    )
                if any(
                    self._classify(knowledge_fd, operation, journal_id, index) != "new"
                    for index, operation in enumerate(plan.operations, start=1)
                ):
                    _fail("knowledge transaction did not converge to all-new")
                if crash_at == "after-all-replaces-before-journal-committed":
                    raise ApplyCrash(crash_at)
                journal = replace(
                    journal,
                    status="committed",
                    operations=tuple(
                        replace(item, status="committed")
                        for item in journal.operations
                    ),
                )
                self._store_journal(transaction_fd, journal, previous=journal_raw)
                if crash_at == "after-journal-before-review-finalization":
                    raise ApplyCrash(crash_at)
                return journal

    def _rollback_operation(
        self,
        knowledge_fd: int,
        transaction_fd: int,
        operation: MutationOperation,
        journal_id: str,
        sequence: int,
        state: Literal["old", "partial", "new", "foreign"],
    ) -> None:
        if state == "old":
            return
        if state == "foreign":
            _fail("foreign knowledge replacement prevents rollback")
        if operation.op == "create":
            with self._open_parent(knowledge_fd, operation.path) as (parent_fd, leaf):
                _remove_exact(
                    parent_fd,
                    leaf,
                    operation.postcondition_sha256,
                    self._quarantine_name(journal_id, sequence, "created"),
                )
            return
        if operation.destination_path is None:
            target = operation.path
        else:
            target = operation.destination_path
        target_observed = self._observe_path(knowledge_fd, target)
        if target_observed is not None:
            if target_observed.digest != operation.postcondition_sha256:
                _fail("foreign knowledge replacement prevents rollback")
            with self._open_parent(knowledge_fd, target) as (parent_fd, leaf):
                _remove_exact(
                    parent_fd,
                    leaf,
                    operation.postcondition_sha256,
                    self._quarantine_name(journal_id, sequence, "new"),
                )
        old = _observe_at(transaction_fd, self._blob_name(sequence, "old"))
        if old is None or old.digest != operation.precondition_sha256:
            _fail("prepared rollback blob is missing or changed")
        backup = self._backup_name(journal_id, sequence)
        with self._open_parent(knowledge_fd, operation.path) as (parent_fd, leaf):
            if _observe_at(parent_fd, leaf) is not None:
                _fail("knowledge source appeared during rollback")
            backup_observed = _observe_at(parent_fd, backup)
            if backup_observed is not None:
                if backup_observed.digest != operation.precondition_sha256:
                    _fail("foreign apply backup prevents rollback")
                try:
                    _rename_noreplace(parent_fd, backup, parent_fd, leaf)
                    os.fsync(parent_fd)
                except OSError:
                    _fail("knowledge source appeared during rollback")
            else:
                token = f"rollback-{sequence:03d}"
                _publish_bytes(parent_fd, leaf, old.data, token)
        if self._classify(
            knowledge_fd, operation, journal_id, sequence
        ) != "old":
            _fail("knowledge precondition was not restored")

    def rollback(
        self,
        artifact: ReviewArtifact,
        plan: MutationPlan,
        *,
        journal_id: str,
        capability: ActionCapability,
    ) -> ApplyJournalEvidence:
        """Restore the exact all-old set without overwriting foreign bytes."""

        with self._transaction(journal_id, create=False) as transaction_fd:
            journal, journal_raw = self._load_journal(transaction_fd)
            self._validate_gate(
                artifact, plan, capability, journal=journal if artifact.status == "applied" else None
            )
            self._validate_journal_binding(artifact, plan, journal)
            self._verify_staged_blobs(transaction_fd, plan)
            with self._open_zone("knowledge") as knowledge_fd:
                states = tuple(
                    self._classify(knowledge_fd, operation, journal_id, index)
                    for index, operation in enumerate(plan.operations, start=1)
                )
                if "foreign" in states:
                    _fail("foreign knowledge replacement prevents rollback")
                for index in range(len(plan.operations), 0, -1):
                    self._rollback_operation(
                        knowledge_fd,
                        transaction_fd,
                        plan.operations[index - 1],
                        journal_id,
                        index,
                        states[index - 1],
                    )
                if any(
                    self._classify(knowledge_fd, operation, journal_id, index) != "old"
                    for index, operation in enumerate(plan.operations, start=1)
                ):
                    _fail("knowledge transaction did not converge to all-old")
            rolled_back = replace(
                journal,
                status="rolled_back",
                operations=tuple(
                    replace(operation, status="rolled_back")
                    for operation in journal.operations
                ),
            )
            if rolled_back != journal:
                self._store_journal(
                    transaction_fd, rolled_back, previous=journal_raw
                )
            return rolled_back

    def reconcile(
        self,
        artifact: ReviewArtifact,
        plan: MutationPlan,
        *,
        journal_id: str,
        capability: ActionCapability,
        strategy: Literal["rollback", "commit"] = "rollback",
    ) -> ApplyJournalEvidence:
        """Converge an interrupted transaction to an exact old or new set."""

        if strategy == "commit":
            return self.commit(
                artifact,
                plan,
                journal_id=journal_id,
                capability=capability,
            )
        if strategy != "rollback":
            _fail("reconcile strategy is unsupported")
        with self._transaction(journal_id, create=False) as transaction_fd:
            journal, _raw = self._load_journal(transaction_fd)
        if journal.status == "committed":
            return self.commit(
                artifact,
                plan,
                journal_id=journal_id,
                capability=capability,
            )
        return self.rollback(
            artifact,
            plan,
            journal_id=journal_id,
            capability=capability,
        )

    def read_journal(self, journal_id: str) -> ApplyJournalEvidence:
        """Read bounded canonical durable evidence without following links."""

        with self._transaction(journal_id, create=False) as transaction_fd:
            journal, _raw = self._load_journal(transaction_fd)
            return journal

    def finalize(
        self,
        artifact: ReviewArtifact,
        plan: MutationPlan,
        journal: ApplyJournalEvidence,
        *,
        capability: ActionCapability,
    ) -> ReviewArtifact:
        """Return applied review metadata bound to exact committed journal bytes."""

        if journal.status != "committed":
            _fail("review can only finalize from a committed apply journal")
        self._validate_gate(artifact, plan, capability)
        with self._transaction(journal.journal_id, create=False) as transaction_fd:
            durable, _raw = self._load_journal(transaction_fd)
            if durable != journal or apply_journal_sha256(durable) != apply_journal_sha256(
                journal
            ):
                _fail("supplied apply journal differs from durable evidence")
            self._validate_journal_binding(artifact, plan, durable)
            self._verify_staged_blobs(transaction_fd, plan)
            with self._open_zone("knowledge") as knowledge_fd:
                if any(
                    self._classify(
                        knowledge_fd,
                        operation,
                        durable.journal_id,
                        index,
                    )
                    != "new"
                    for index, operation in enumerate(plan.operations, start=1)
                ):
                    _fail("durable apply journal disagrees with knowledge bytes")
        application = ApplicationEvidence(
            schema_version=APPLICATION_SCHEMA_VERSION,
            applied_at=durable.committed_at,
            plan_sha256=durable.plan_sha256,
            journal_id=durable.journal_id,
            journal_sha256=apply_journal_sha256(durable),
        )
        updated = replace(artifact, status="applied", application=application)
        try:
            validate_apply_journal(updated, plan, durable)
        except ReviewArtifactError as error:
            raise ApplyError(str(error)) from None
        return updated
