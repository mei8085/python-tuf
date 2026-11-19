# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Differential harness for numeric JSON parsing in the two envelope entries.

TUF metadata reaches a client through one of two envelope formats:

* traditional metadata envelopes (``{"signed": ..., "signatures": ...}``),
  unpacked by ``_load_from_metadata`` (``Metadata.from_bytes``)
* DSSE/Simple envelopes (``{"payload": ..., "payloadType": ...}``), whose
  payload is unpacked by ``_load_from_simple_envelope``
  (``SimpleEnvelope.from_bytes``/``get_signed``)

Both entries must reach the same security conclusion about every numeric value
they consume (versions, lengths, thresholds, ``bit_length``, ...). Otherwise a
repository could ship metadata that is accepted in one envelope format and
rejected in the other.

The harness feeds the same raw payload -- including duplicate keys and
alternative numeric encodings -- through both entries and classifies the
result:

``agree``
    Both entries accepted and consumed exactly the same numbers, or both
    rejected the payload.  Rejection *reasons* may differ (a malformed document
    fails in ``json`` on both sides but is wrapped in different exceptions);
    the conclusion does not.
``spec-rejection``
    Exactly one entry accepted, and the other rejected solely because the
    canonical JSON encoding used by traditional metadata cannot represent a
    number literal present in the payload (``1.0``, ``NaN``, ``1e400``, ...).
    Both parsers read the same literal value, so this is a limitation of the
    traditional format, not a differing security conclusion.  It is reported
    separately and is only a failure in ``--strict`` mode.
``security-difference``
    Anything else: acceptance/rejection disagreement for another reason, or
    both entries accepting but consuming different numbers.  Always a failure.

The corpus is deterministic and every payload is minimal.  A failing sample is
shrunken further with :func:`minimize` and persisted, together with a JSON
sidecar describing both conclusions, by :func:`save_reproducer`.

Run the sweep locally (no network, no clock, repeatable)::

    python3 -m tests.numeric_differential [--artifact-dir DIR] [--strict]

The unittest wrapper is ``python3 -m unittest tests.test_numeric_differential``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tuf.api.metadata import Root, Signed, Snapshot, T, Targets, Timestamp
from tuf.ngclient._internal.trusted_metadata_set import (
    _load_from_metadata,
    _load_from_simple_envelope,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

    # Maps a raw payload to both entry conclusions.
    Evaluator = Callable[[bytes], tuple["Consumption", "Consumption"]]

DEFAULT_PAYLOAD_TYPE = "application/vnd.tuf+json"

# Integers that exceed IEEE-754 exact range but are still exact Python ints.
TWO_POW_53_PLUS_ONE = "9007199254740993"
TWO_POW_63 = "9223372036854775808"
TWO_POW_64 = "18446744073709551616"
LONG_DECIMAL = "1" + "234567890123456789" * 3


class Entry(Enum):
    """The two envelope entry points under test."""

    METADATA = "metadata"
    SIMPLE = "simple"


class VerdictKind(Enum):
    """Classification of a differential sample."""

    AGREE = "agree"
    SPEC_REJECTION = "spec-rejection"
    SECURITY_DIFFERENCE = "security-difference"


# (path, python type name, repr of the value)
Number = tuple[str, str, str]


@dataclass(frozen=True)
class Consumption:
    """What one entry concluded about one raw payload.

    Attributes:
        entry: Entry that produced this result.
        accepted: Whether the payload was deserialized successfully.
        numbers: Every numeric value in the accepted payload, as
            ``(path, type name, repr)`` triples.  Recording the type is
            essential: ``1``, ``1.0`` and ``true`` compare equal in Python but
            are different wire values.
        errors: ``(exception type name, message)`` pairs along the cause chain
            of a rejection.
    """

    entry: Entry
    accepted: bool
    numbers: tuple[Number, ...] = ()
    errors: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Verdict:
    """Differential verdict for a single sample."""

    kind: VerdictKind
    detail: str


@dataclass(frozen=True)
class Sample:
    """A single raw signed payload fed to both entries."""

    name: str
    role: str
    field: str
    tokens: tuple[str, ...]
    payload: bytes


@dataclass(frozen=True)
class SampleResult:
    """Both entry consumptions and the resulting verdict."""

    sample: Sample
    metadata: Consumption
    simple: Consumption
    verdict: Verdict


@dataclass(frozen=True)
class RoleSpec:
    """Deserialization entry point and payload builder for one role."""

    load: Callable[[Entry, bytes], Signed]
    build: Callable[[str, str], bytes]


# --- envelope wrapping ------------------------------------------------------


def wrap_payload(entry: Entry, payload: bytes) -> bytes:
    """Wrap a raw signed payload in the envelope ``entry`` expects.

    The payload bytes are spliced (or base64-encoded) verbatim, so duplicate
    object keys and alternative numeric encodings survive unwrapping: both
    entries see byte-identical payload content.
    """
    if entry is Entry.SIMPLE:
        return json.dumps(
            {
                "payload": base64.b64encode(payload).decode("ascii"),
                "payloadType": DEFAULT_PAYLOAD_TYPE,
                "signatures": [],
            },
            separators=(",", ":"),
        ).encode()
    return b'{"signed":' + payload + b',"signatures":[]}'


def _make_loader(role_cls: type[T]) -> Callable[[Entry, bytes], Signed]:
    """Bind a concrete role class to both envelope entry points."""

    def load(entry: Entry, payload: bytes) -> Signed:
        data = wrap_payload(entry, payload)
        if entry is Entry.SIMPLE:
            return _load_from_simple_envelope(role_cls, data)[0]
        return _load_from_metadata(role_cls, data)[0]

    return load


# --- conclusion recording ---------------------------------------------------


def _walk_numbers(value: object, path: str = "") -> list[Number]:
    """Collect every number in ``value`` as ``(path, type name, repr)``."""
    numbers: list[Number] = []
    if isinstance(value, bool):
        numbers.append((path, "bool", repr(value)))
    elif isinstance(value, int):
        numbers.append((path, "int", repr(value)))
    elif isinstance(value, float):
        numbers.append((path, "float", repr(value)))
    elif isinstance(value, dict):
        for key in sorted(value):
            child = f"{path}/{key}" if path else str(key)
            numbers.extend(_walk_numbers(value[key], child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            numbers.extend(_walk_numbers(item, f"{path}[{index}]"))
    return numbers


def literal_numbers(payload: bytes) -> tuple[Number, ...]:
    """Return the numbers literally present in ``payload``, uninterpreted.

    Returns an empty tuple when ``payload`` is not valid JSON.
    """
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ()
    return tuple(_walk_numbers(document))


def _error_chain(exc: BaseException) -> tuple[tuple[str, str], ...]:
    """Return the cause/context chain of ``exc`` as ``(type name, message)``."""
    chain: list[tuple[str, str]] = []
    current: BaseException | None = exc
    while current is not None and len(chain) < 8:
        chain.append((type(current).__name__, str(current)))
        current = current.__cause__ or current.__context__
    return tuple(chain)


def consume(spec: RoleSpec, entry: Entry, payload: bytes) -> Consumption:
    """Deserialize ``payload`` through ``entry`` and record the conclusion."""
    try:
        signed = spec.load(entry, payload)
        numbers = tuple(_walk_numbers(signed.to_dict()))
    except Exception as exc:  # noqa: BLE001 - every failure is a conclusion
        return Consumption(
            entry=entry, accepted=False, errors=_error_chain(exc)
        )

    return Consumption(entry=entry, accepted=True, numbers=numbers)


def _is_canonical_encoding_rejection(consumption: Consumption) -> bool:
    """True if the rejection came from the canonical JSON encoder.

    The canonical encoder refuses every non-integer number; that is the only
    numeric representation the traditional metadata format cannot express.
    """
    return any(
        name == "FormatError" and "I cannot encode" in message
        for name, message in consumption.errors
    )


def classify(
    payload: bytes, metadata: Consumption, simple: Consumption
) -> Verdict:
    """Compare the two entry conclusions for the same raw payload."""
    if metadata.accepted and simple.accepted:
        if metadata.numbers == simple.numbers:
            return Verdict(
                VerdictKind.AGREE, "both entries consumed the same numbers"
            )
        return Verdict(
            VerdictKind.SECURITY_DIFFERENCE,
            "entries consumed different numbers: "
            f"{_describe_numbers(metadata.numbers)} != "
            f"{_describe_numbers(simple.numbers)}",
        )

    if metadata.accepted == simple.accepted:
        errors = metadata.errors or simple.errors
        return Verdict(
            VerdictKind.AGREE,
            f"both entries rejected ({_describe_errors(errors)})",
        )

    accepting, rejecting = (
        (metadata, simple) if metadata.accepted else (simple, metadata)
    )
    literals = literal_numbers(payload)
    if (
        rejecting.entry is Entry.METADATA
        and _is_canonical_encoding_rejection(rejecting)
        and any(kind == "float" for _, kind, _ in literals)
        and accepting.numbers == literals
    ):
        return Verdict(
            VerdictKind.SPEC_REJECTION,
            f"{rejecting.entry.value} cannot encode a non-integer number "
            "that is legal JSON; both parsers read the same literal value",
        )

    return Verdict(
        VerdictKind.SECURITY_DIFFERENCE,
        f"{accepting.entry.value} accepted, {rejecting.entry.value} rejected "
        f"({_describe_errors(rejecting.errors)})",
    )


def _describe_numbers(numbers: tuple[Number, ...]) -> str:
    body = ", ".join(f"{path}<{kind}>={value}" for path, kind, value in numbers)
    return "{" + body + "}"


def _describe_errors(errors: tuple[tuple[str, str], ...]) -> str:
    return " <- ".join(f"{name}: {message}" for name, message in errors)


def run_sample(
    sample: Sample, evaluator: Evaluator | None = None
) -> SampleResult:
    """Feed one sample through both entries and classify the outcome.

    Args:
        sample: Raw payload and its role.
        evaluator: Optional replacement for the built-in entry evaluation,
            mapping a payload to ``(metadata, simple)`` consumptions.  It is
            used by tests that need to simulate a divergence without changing
            library code.
    """
    if evaluator is None:
        evaluate = _default_evaluator(sample.role)
    else:
        evaluate = evaluator
    metadata, simple = evaluate(sample.payload)
    return SampleResult(
        sample=sample,
        metadata=metadata,
        simple=simple,
        verdict=classify(sample.payload, metadata, simple),
    )


def _default_evaluator(role: str) -> Evaluator:
    """Return the evaluator that uses the real entry points for ``role``."""
    spec = ROLES[role]

    def evaluate(payload: bytes) -> tuple[Consumption, Consumption]:
        return (
            consume(spec, Entry.METADATA, payload),
            consume(spec, Entry.SIMPLE, payload),
        )

    return evaluate


# --- payload builders -------------------------------------------------------
#
# Every builder emits a compact payload that is valid apart from the single
# numeric token under test.

_BASE = (
    '{{"_type":"{role}","spec_version":"1.0.0","version":{version},'
    '"expires":"2050-01-01T00:00:00Z"{rest}}}'
)


def _role_payload(role: str, version: str, rest: str) -> bytes:
    return _BASE.format(role=role, version=version, rest=rest).encode()


def _timestamp_payload(field: str, token: str) -> bytes:
    version = token if field == "version" else "1"
    meta_version = token if field == "meta_version" else "1"
    length = f',"length":{token}' if field == "meta_length" else ""
    rest = f',"meta":{{"snapshot.json":{{"version":{meta_version}{length}}}}}'
    return _role_payload("timestamp", version, rest)


def _snapshot_payload(field: str, token: str) -> bytes:
    version = token if field == "version" else "1"
    meta_version = token if field == "meta_version" else "1"
    length = f',"length":{token}' if field == "meta_length" else ""
    rest = f',"meta":{{"targets.json":{{"version":{meta_version}{length}}}}}'
    return _role_payload("snapshot", version, rest)


def _targets_payload(field: str, token: str) -> bytes:
    version = token if field == "version" else "1"
    if field == "targets_length":
        rest = (
            ',"targets":{"f.txt":{"length":'
            + token
            + ',"hashes":{"sha256":"aa"}}}'
        )
    elif field == "delegated_threshold":
        rest = (
            ',"targets":{},"delegations":{"keys":{},"roles":['
            '{"name":"r","keyids":[],"threshold":'
            + token
            + ',"terminating":true,"paths":["x"]}]}'
        )
    elif field == "succinct_bit_length":
        rest = (
            ',"targets":{},"delegations":{"keys":{},"succinct_roles":'
            '{"keyids":[],"threshold":1,"bit_length":'
            + token
            + ',"name_prefix":"b"}}'
        )
    else:
        rest = ',"targets":{}'
    return _role_payload("targets", version, rest)


def _root_payload(field: str, token: str) -> bytes:
    version = token if field == "version" else "1"
    threshold = token if field == "role_threshold" else "1"
    rest = (
        ',"keys":{},"roles":{"root":{"keyids":[],"threshold":1},'
        f'"snapshot":{{"keyids":[],"threshold":{threshold}}},'
        '"targets":{"keyids":[],"threshold":1},'
        '"timestamp":{"keyids":[],"threshold":1}},'
        '"consistent_snapshot":true'
    )
    return _role_payload("root", version, rest)


ROLES: dict[str, RoleSpec] = {
    "timestamp": RoleSpec(_make_loader(Timestamp), _timestamp_payload),
    "snapshot": RoleSpec(_make_loader(Snapshot), _snapshot_payload),
    "targets": RoleSpec(_make_loader(Targets), _targets_payload),
    "root": RoleSpec(_make_loader(Root), _root_payload),
}

FIELDS: dict[str, tuple[str, ...]] = {
    "timestamp": ("version", "meta_version", "meta_length"),
    "snapshot": ("version", "meta_version", "meta_length"),
    "targets": (
        "version",
        "targets_length",
        "delegated_threshold",
        "succinct_bit_length",
    ),
    "root": ("version", "role_threshold"),
}

# Values every field must accept and consume exactly as written.
LEGAL_TOKENS: dict[str, tuple[str, ...]] = {
    "version": (
        "1",
        "2",
        TWO_POW_53_PLUS_ONE,
        TWO_POW_63,
        TWO_POW_64,
        LONG_DECIMAL,
    ),
    "meta_version": (
        "1",
        "2",
        TWO_POW_53_PLUS_ONE,
        TWO_POW_63,
        TWO_POW_64,
        LONG_DECIMAL,
    ),
    "meta_length": ("0", "1", TWO_POW_64, LONG_DECIMAL),
    "targets_length": ("0", "1", TWO_POW_64, LONG_DECIMAL),
    "delegated_threshold": ("1", "2", TWO_POW_64),
    "role_threshold": ("1", "2", TWO_POW_64),
    "succinct_bit_length": ("1", "32"),
}

# Alternative encodings of the same mathematical value.
NON_INTEGER_TOKENS: tuple[str, ...] = (
    "1.0",
    "1e0",
    "1E+0",
    "1.5",
    "0.1",
    "1e-1",
    "1e-400",
    "1e400",
    "-1e400",
    "NaN",
    "Infinity",
    "-Infinity",
    "1.0000000000000002",
)

# Integers that violate the field's range requirements.
RANGE_TOKENS: dict[str, tuple[str, ...]] = {
    "version": ("0", "-1", "-0"),
    "meta_version": ("0", "-1", "-0"),
    "meta_length": ("-1",),
    "targets_length": ("-1",),
    "delegated_threshold": ("0", "-1"),
    "role_threshold": ("0", "-1"),
    "succinct_bit_length": ("0", "33"),
}

# JSON values that are not numbers at all.
NON_NUMBER_TOKENS: tuple[str, ...] = ("true", "false", "null", '"1"')

# Tokens that are not valid JSON numbers (or, at the end, not valid JSON).
MALFORMED_TOKENS: tuple[str, ...] = (
    "01",
    "+1",
    "1.",
    ".5",
    "0x10",
    "1_0",
    "1e",
    "--1",
)


def tokens_for(field: str) -> tuple[str, ...]:
    """Return all tokens exercised for ``field``, in stable order."""
    ordered = (
        LEGAL_TOKENS[field]
        + RANGE_TOKENS[field]
        + NON_INTEGER_TOKENS
        + NON_NUMBER_TOKENS
        + MALFORMED_TOKENS
    )
    return tuple(dict.fromkeys(ordered))


def is_legal(field: str, token: str) -> bool:
    """True if ``token`` is a legal value for ``field``."""
    return token in LEGAL_TOKENS[field]


def _duplicate_samples() -> list[Sample]:
    """Samples with repeated object keys, including mixed encodings."""
    timestamp = (
        '{"_type":"timestamp","spec_version":"1.0.0","expires":'
        '"2050-01-01T00:00:00Z","version":{first},"version":{second},'
        '"meta":{"snapshot.json":{"version":1}}}'
    )
    snapshot = (
        '{"_type":"snapshot","spec_version":"1.0.0","version":1,'
        '"expires":"2050-01-01T00:00:00Z","meta":'
        '{"targets.json":{"version":{first}}},"meta":'
        '{"targets.json":{"version":{second}}}}'
    )
    root = (
        '{"_type":"root","spec_version":"1.0.0","version":1,"expires":'
        '"2050-01-01T00:00:00Z","keys":{},"roles":{"root":'
        '{"keyids":[],"threshold":1},"snapshot":{"keyids":[],'
        '"threshold":{first},"threshold":{second}},"targets":{"keyids":[],'
        '"threshold":1},"timestamp":{"keyids":[],"threshold":1}},'
        '"consistent_snapshot":true}'
    )

    raw_samples = (
        ("timestamp.version duplicate ints", "timestamp", timestamp, "1", "2"),
        (
            "timestamp.version duplicate int then float",
            "timestamp",
            timestamp,
            "2",
            "1.0",
        ),
        (
            "timestamp.version duplicate float then int",
            "timestamp",
            timestamp,
            "1.0",
            "2",
        ),
        (
            "timestamp.version duplicate floats",
            "timestamp",
            timestamp,
            "1.0",
            "2.5",
        ),
        (
            "snapshot.meta duplicate key int then float",
            "snapshot",
            snapshot,
            "1",
            "1.0",
        ),
        (
            "snapshot.meta duplicate key float then int",
            "snapshot",
            snapshot,
            "1.0",
            "1",
        ),
        (
            "root.roles.snapshot.threshold duplicate int then float",
            "root",
            root,
            "1",
            "1.0",
        ),
        (
            "root.roles.snapshot.threshold duplicate float then int",
            "root",
            root,
            "1.0",
            "1",
        ),
    )

    return [
        Sample(
            name=name,
            role=role,
            field="duplicate-keys",
            tokens=(first, second),
            payload=template.replace("{first}", first)
            .replace("{second}", second)
            .encode(),
        )
        for name, role, template, first, second in raw_samples
    ]


def iter_samples() -> Iterator[Sample]:
    """Yield the full corpus in deterministic order."""
    for role, fields in FIELDS.items():
        spec = ROLES[role]
        for field in fields:
            for token in tokens_for(field):
                yield Sample(
                    name=f"{role}.{field}={token}",
                    role=role,
                    field=field,
                    tokens=(token,),
                    payload=spec.build(field, token),
                )
    yield from _duplicate_samples()


def sweep() -> list[SampleResult]:
    """Feed the corpus through both entries and classify every sample."""
    return [run_sample(sample) for sample in iter_samples()]


# --- minimization and reproducers ------------------------------------------


_NUMBER_RE = re.compile(rb"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_SHRINK_LADDER: tuple[bytes, ...] = (
    b"0",
    b"1",
    b"-1",
    b"1.5",
    b"1e400",
    b"NaN",
    b"1.0000000000000002",
)


def _number_spans(raw: bytes) -> Iterator[tuple[int, int]]:
    """Yield ``(start, end)`` of numeric literals *outside* JSON strings.

    Naive regular expressions would also rewrite digits inside string values
    such as ``"spec_version":"1.0.0"``.  Shrinking those would change the
    document's meaning rather than minimize the numeric finding, so a minimal
    string scanner is used instead.
    """
    index = 0
    length = len(raw)
    while index < length:
        char = raw[index : index + 1]
        if char == b'"':
            index += 1
            while index < length:
                if raw[index : index + 1] == b"\\":
                    index += 2
                    continue
                if raw[index : index + 1] == b'"':
                    index += 1
                    break
                index += 1
            continue
        if char in b"-0123456789":
            match = _NUMBER_RE.match(raw, index)
            if match is not None:
                yield match.start(), match.end()
                index = match.end()
                continue
        index += 1


def _token_candidates(raw: bytes) -> Iterator[bytes]:
    """Yield payloads with individual numeric literals shrunk in place."""
    for start, end in _number_spans(raw):
        token = raw[start:end]
        for replacement in _SHRINK_LADDER:
            if len(replacement) >= len(token):
                continue
            yield raw[:start] + replacement + raw[end:]


def _minimization_candidates(raw: bytes) -> Iterator[bytes]:
    """Yield candidate reductions of ``raw``, cheapest first."""
    trimmed = raw.strip()
    if trimmed != raw:
        yield trimmed
    yield from _token_candidates(trimmed)


def minimize(payload: bytes, predicate: Callable[[bytes], bool]) -> bytes:
    """Greedily shrink ``payload`` while ``predicate`` keeps holding.

    The predicate is re-evaluated for every candidate, so a reduction is only
    kept when it preserves the property under investigation (e.g. "the entries
    still disagree").  The result is deterministic and never longer than
    ``payload``.
    """
    best = payload
    changed = True
    while changed:
        changed = False
        for candidate in _minimization_candidates(best):
            if len(candidate) < len(best) and predicate(candidate):
                best = candidate
                changed = True
                break
    return best


def _slug(name: str) -> str:
    """Turn a sample name into a stable, filesystem-safe identifier."""
    return re.sub(r"[^a-z0-9._-]+", "_", name.lower()).strip("_") or "sample"


def _consumption_to_dict(consumption: Consumption) -> dict[str, Any]:
    return {
        "entry": consumption.entry.value,
        "accepted": consumption.accepted,
        "numbers": [list(number) for number in consumption.numbers],
        "errors": [list(error) for error in consumption.errors],
    }


def _verdict_for(
    result: SampleResult,
    payload: bytes,
    evaluator: Evaluator | None = None,
) -> Verdict:
    """Classify ``payload`` the same way ``result``'s sample was classified."""
    if evaluator is None:
        evaluate = _default_evaluator(result.sample.role)
    else:
        evaluate = evaluator
    metadata, simple = evaluate(payload)
    return classify(payload, metadata, simple)


def reproducer_name(result: SampleResult, payload: bytes) -> str:
    """Return the deterministic basename used for a minimized reproducer."""
    digest = hashlib.sha256(payload).hexdigest()[:8]
    return f"{_slug(result.sample.name)}-{digest}"


def save_reproducer(
    directory: Path,
    result: SampleResult,
    evaluator: Evaluator | None = None,
) -> tuple[Path, Path]:
    """Persist a minimized input and a sidecar; return both paths.

    The payload is shrunk with :func:`minimize` while the verdict kind stays
    the same, then written verbatim as ``<name>-<sha>.payload.json`` next to a
    ``<name>-<sha>.meta.json`` describing both entry conclusions.  Running this
    twice for the same result writes identical bytes.
    """
    if result.verdict.kind is VerdictKind.AGREE:
        raise ValueError("refusing to save an agreeing sample")

    def still_fails(candidate: bytes) -> bool:
        return (
            _verdict_for(result, candidate, evaluator).kind
            is result.verdict.kind
        )

    payload = minimize(result.sample.payload, still_fails)
    minimized = _verdict_for(result, payload, evaluator)
    basename = reproducer_name(result, payload)
    metadata_consumption, simple_consumption = (
        evaluator(payload)
        if evaluator is not None
        else (
            consume(ROLES[result.sample.role], Entry.METADATA, payload),
            consume(ROLES[result.sample.role], Entry.SIMPLE, payload),
        )
    )

    directory.mkdir(parents=True, exist_ok=True)
    payload_path = directory / f"{basename}.payload.json"
    payload_path.write_bytes(payload)

    metadata = {
        "sample": result.sample.name,
        "role": result.sample.role,
        "field": result.sample.field,
        "tokens": list(result.sample.tokens),
        "verdict": minimized.kind.value,
        "detail": minimized.detail,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_length": len(payload),
        "original_length": len(result.sample.payload),
        "entries": {
            Entry.METADATA.value: _consumption_to_dict(metadata_consumption),
            Entry.SIMPLE.value: _consumption_to_dict(simple_consumption),
        },
    }
    metadata_path = directory / f"{basename}.meta.json"
    metadata_path.write_text(
        json.dumps(metadata, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload_path, metadata_path


def default_artifact_dir() -> Path:
    """Return the artifact directory configured for this run.

    Set ``TUF_NUMERIC_DIFF_ARTIFACT_DIR`` to keep reproducers somewhere
    persistent; otherwise a fresh temporary directory is used so repeated
    local runs do not leave files behind.
    """
    configured = os.environ.get("TUF_NUMERIC_DIFF_ARTIFACT_DIR")
    if configured:
        return Path(configured)
    return Path(tempfile.mkdtemp(prefix="tuf-numeric-diff-"))


def failing_results(
    results: Sequence[SampleResult],
    *,
    include_spec_rejections: bool = False,
) -> list[SampleResult]:
    """Return the results that constitute failures."""
    wanted = {VerdictKind.SECURITY_DIFFERENCE}
    if include_spec_rejections:
        wanted.add(VerdictKind.SPEC_REJECTION)
    return [result for result in results if result.verdict.kind in wanted]


def save_failures(
    results: Sequence[SampleResult],
    directory: Path,
    *,
    include_spec_rejections: bool = False,
    evaluator: Evaluator | None = None,
) -> list[Path]:
    """Save every failing sample as a minimized reproducer."""
    written: list[Path] = []
    for result in failing_results(
        results, include_spec_rejections=include_spec_rejections
    ):
        written.extend(save_reproducer(directory, result, evaluator))
    return written


def main(argv: Sequence[str] | None = None) -> int:
    """Run the sweep and persist failing samples as minimized reproducers."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=None,
        help="directory for minimized reproducers (default: a temp directory)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat spec-rejections as failures too",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print one line per sample",
    )
    args = parser.parse_args(argv)

    results = sweep()
    for result in results:
        if args.verbose or result.verdict.kind is not VerdictKind.AGREE:
            print(
                f"[{result.verdict.kind.value}] {result.sample.name}: "
                f"{result.verdict.detail}"
            )

    for kind in VerdictKind:
        count = sum(1 for result in results if result.verdict.kind is kind)
        print(f"{kind.value}: {count}")

    failures = failing_results(results, include_spec_rejections=args.strict)
    if not failures:
        return 0

    directory = args.artifact_dir or default_artifact_dir()
    paths = save_failures(
        failures, directory, include_spec_rejections=args.strict
    )
    print(f"reproducers written to {directory} ({len(paths)} files)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
