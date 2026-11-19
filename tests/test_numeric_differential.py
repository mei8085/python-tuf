# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Differential integration tests for numeric JSON parsing.

These tests exercise both envelope entry points with the same raw payloads and
only fail when the entries disagree about validity (beyond the documented
canonical JSON limitation) or about the numbers they actually consume.
Legal boundary values must keep identical results on both entries.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import io
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

from tests import numeric_differential as nd
from tests import utils
from tests.generated_data.generate_md import EXPIRY, signers
from tuf.api.metadata import (
    Metadata,
    Root,
    Snapshot,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet
from tuf.ngclient.config import EnvelopeType

if TYPE_CHECKING:
    from securesystemslib.signer import Signer


class TestLegalBoundaries(unittest.TestCase):
    """Legal numeric values must be consumed identically by both entries."""

    def test_legal_tokens_are_accepted_identically(self) -> None:
        checked = 0
        for sample in nd.iter_samples():
            if sample.field == "duplicate-keys":
                continue
            token = sample.tokens[0]
            if not nd.is_legal(sample.field, token):
                continue

            with self.subTest(sample=sample.name):
                result = nd.run_sample(sample)

                # Value must be consumed at all, by both entries.
                self.assertTrue(
                    result.metadata.accepted,
                    f"metadata rejected legal {sample.name}: "
                    f"{result.metadata.errors}",
                )
                self.assertTrue(
                    result.simple.accepted,
                    f"simple envelope rejected legal {sample.name}: "
                    f"{result.simple.errors}",
                )
                # ... and consumed as the very same numbers.
                self.assertEqual(result.metadata.numbers, result.simple.numbers)
                self.assertIs(result.verdict.kind, nd.VerdictKind.AGREE)

                # The value survives unchanged: exact ints stay exact ints.
                consumed = {
                    path: value for path, _, value in result.metadata.numbers
                }
                self.assertIn(str(int(token)), consumed.values())
                checked += 1

        self.assertGreater(checked, 0)

    def test_legal_large_integers_keep_precision(self) -> None:
        """Integers beyond IEEE-754 exact range must not be rounded."""
        for token in (nd.TWO_POW_53_PLUS_ONE, nd.TWO_POW_64, nd.LONG_DECIMAL):
            sample = nd.Sample(
                name=f"timestamp.version={token}",
                role="timestamp",
                field="version",
                tokens=(token,),
                payload=nd.ROLES["timestamp"].build("version", token),
            )
            with self.subTest(token=token):
                result = nd.run_sample(sample)
                self.assertTrue(result.metadata.accepted)
                self.assertTrue(result.simple.accepted)
                for consumption in (result.metadata, result.simple):
                    values = {
                        path: (kind, value)
                        for path, kind, value in consumption.numbers
                    }
                    self.assertEqual(values["version"], ("int", token))

    def test_duplicate_keys_use_the_last_value_on_both_entries(self) -> None:
        """Repeated keys are resolved identically, whichever encoding wins."""
        for sample in nd.iter_samples():
            if sample.field != "duplicate-keys":
                continue
            # Samples that mix in a non-integer are the known format
            # limitation and are covered by the spec-rejection tests.
            if any("." in token or "e" in token for token in sample.tokens):
                continue
            with self.subTest(sample=sample.name):
                result = nd.run_sample(sample)
                self.assertTrue(result.metadata.accepted)
                self.assertTrue(result.simple.accepted)
                self.assertEqual(result.metadata.numbers, result.simple.numbers)


class TestDifferentialSweep(unittest.TestCase):
    """The whole corpus must be free of security-relevant divergence."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.results = nd.sweep()

    def test_no_security_differences(self) -> None:
        differences = [
            result
            for result in self.results
            if result.verdict.kind is nd.VerdictKind.SECURITY_DIFFERENCE
        ]
        self.assertEqual(
            [result.sample.name for result in differences],
            [],
            "\n".join(
                f"{result.sample.name}: {result.verdict.detail}"
                for result in differences
            ),
        )

    def test_known_spec_rejections_are_not_security_differences(self) -> None:
        """Non-integer JSON numbers are rejected by canonical JSON only."""
        spec_rejections = [
            result
            for result in self.results
            if result.verdict.kind is nd.VerdictKind.SPEC_REJECTION
        ]
        self.assertTrue(spec_rejections)

        for result in spec_rejections:
            with self.subTest(sample=result.sample.name):
                # Exactly the traditional entry rejects, and only because the
                # canonical encoder cannot express a float.
                self.assertTrue(result.simple.accepted)
                self.assertFalse(result.metadata.accepted)
                self.assertTrue(
                    nd._is_canonical_encoding_rejection(result.metadata)
                )
                # The accepted side consumed exactly the literal numbers.
                self.assertEqual(
                    result.simple.numbers,
                    nd.literal_numbers(result.sample.payload),
                )

    def test_corpus_is_deterministic(self) -> None:
        first = [(sample.name, sample.payload) for sample in nd.iter_samples()]
        second = [(sample.name, sample.payload) for sample in nd.iter_samples()]
        self.assertEqual(first, second)

    def test_corpus_covers_all_roles_and_number_fields(self) -> None:
        roles = {sample.role for sample in nd.iter_samples()}
        self.assertEqual(roles, set(nd.ROLES))

        fields = {
            sample.field
            for sample in nd.iter_samples()
            if sample.field != "duplicate-keys"
        }
        expected = {field for names in nd.FIELDS.values() for field in names}
        self.assertEqual(fields, expected)


class TestVerdictClassification(unittest.TestCase):
    """Unit-level checks for the classification rules."""

    @staticmethod
    def _consumption(
        entry: nd.Entry,
        numbers: tuple[nd.Number, ...] = (),
        errors: tuple[tuple[str, str], ...] = (),
    ) -> nd.Consumption:
        return nd.Consumption(
            entry=entry,
            accepted=not errors,
            numbers=numbers,
            errors=errors,
        )

    def test_identical_acceptance_agrees(self) -> None:
        numbers = (("version", "int", "1"),)
        verdict = nd.classify(
            b"{}",
            self._consumption(nd.Entry.METADATA, numbers),
            self._consumption(nd.Entry.SIMPLE, numbers),
        )
        self.assertIs(verdict.kind, nd.VerdictKind.AGREE)

    def test_identical_rejection_agrees_despite_different_errors(self) -> None:
        """Rejection reasons may differ; the conclusion may not."""
        verdict = nd.classify(
            b"{}",
            self._consumption(
                nd.Entry.METADATA,
                errors=(
                    ("DeserializationError", "Failed to deserialize JSON"),
                ),
            ),
            self._consumption(
                nd.Entry.SIMPLE, errors=(("ValueError", "version must be > 0"),)
            ),
        )
        self.assertIs(verdict.kind, nd.VerdictKind.AGREE)

    def test_different_consumed_numbers_are_a_security_difference(self) -> None:
        verdict = nd.classify(
            b"{}",
            self._consumption(nd.Entry.METADATA, (("version", "int", "1"),)),
            self._consumption(nd.Entry.SIMPLE, (("version", "int", "2"),)),
        )
        self.assertIs(verdict.kind, nd.VerdictKind.SECURITY_DIFFERENCE)

    def test_same_value_different_type_is_a_security_difference(self) -> None:
        """``1`` and ``true`` compare equal in Python but are not the same."""
        verdict = nd.classify(
            b"{}",
            self._consumption(nd.Entry.METADATA, (("version", "int", "1"),)),
            self._consumption(nd.Entry.SIMPLE, (("version", "bool", "True"),)),
        )
        self.assertIs(verdict.kind, nd.VerdictKind.SECURITY_DIFFERENCE)

    def test_unexplained_acceptance_disagreement_is_a_difference(self) -> None:
        verdict = nd.classify(
            b'{"version": 1}',
            self._consumption(nd.Entry.METADATA, (("version", "int", "1"),)),
            self._consumption(
                nd.Entry.SIMPLE,
                errors=(("DeserializationError", "unrecognized role type"),),
            ),
        )
        self.assertIs(verdict.kind, nd.VerdictKind.SECURITY_DIFFERENCE)

    def test_canonical_float_rejection_is_a_spec_rejection(self) -> None:
        payload = b'{"version": 1.0}'
        verdict = nd.classify(
            payload,
            self._consumption(
                nd.Entry.METADATA,
                errors=(
                    ("SerializationError", ""),
                    ("FormatError", "I cannot encode 1.0"),
                ),
            ),
            self._consumption(nd.Entry.SIMPLE, (("version", "float", "1.0"),)),
        )
        self.assertIs(verdict.kind, nd.VerdictKind.SPEC_REJECTION)

    def test_canonical_rejection_without_float_is_a_difference(self) -> None:
        """A canonical rejection unrelated to floats is still a difference."""
        verdict = nd.classify(
            b'{"custom": {"nested": null}}',
            self._consumption(
                nd.Entry.METADATA,
                errors=(("FormatError", "I cannot encode None"),),
            ),
            self._consumption(nd.Entry.SIMPLE),
        )
        self.assertIs(verdict.kind, nd.VerdictKind.SECURITY_DIFFERENCE)


class TestMinimizationAndReproducers(unittest.TestCase):
    """Failures must be persisted minimal and reproducibly."""

    SAMPLE = "timestamp.version=1"

    @staticmethod
    def _differing_evaluator() -> nd.Evaluator:
        """Return an evaluator where the simple entry consumes a new version.

        The real corpus agrees everywhere, so a divergence can only be
        produced by simulating a storage change: the simple envelope entry
        deserializes the very same payload into a different version.
        """
        default = nd._default_evaluator("timestamp")

        def evaluate(
            payload: bytes,
        ) -> tuple[nd.Consumption, nd.Consumption]:
            metadata, simple = default(payload)
            bumped = tuple(
                (path, kind, str(int(value) + 1))
                if path == "version"
                else (path, kind, value)
                for path, kind, value in simple.numbers
            )
            return metadata, dataclasses.replace(simple, numbers=bumped)

        return evaluate

    def _sample(self) -> nd.Sample:
        return next(
            sample for sample in nd.iter_samples() if sample.name == self.SAMPLE
        )

    def _differing_result(self) -> nd.SampleResult:
        return nd.run_sample(self._sample(), self._differing_evaluator())

    def test_injected_divergence_is_detected(self) -> None:
        result = self._differing_result()
        self.assertIs(result.verdict.kind, nd.VerdictKind.SECURITY_DIFFERENCE)

    def test_minimization_preserves_the_failure(self) -> None:
        evaluator = self._differing_evaluator()
        result = self._differing_result()
        minimized = nd.minimize(
            result.sample.payload,
            lambda payload: (
                nd._verdict_for(result, payload, evaluator).kind
                is nd.VerdictKind.SECURITY_DIFFERENCE
            ),
        )
        self.assertLessEqual(len(minimized), len(result.sample.payload))
        verdict = nd._verdict_for(result, minimized, evaluator)
        self.assertIs(verdict.kind, nd.VerdictKind.SECURITY_DIFFERENCE)
        # Minimization must not invent a payload the entries accepted.
        self.assertTrue(json.loads(minimized.decode()))

    def test_minimization_is_deterministic(self) -> None:
        evaluator = self._differing_evaluator()
        result = self._differing_result()
        predicate = lambda payload: (  # noqa: E731
            nd._verdict_for(result, payload, evaluator).kind
            is nd.VerdictKind.SECURITY_DIFFERENCE
        )
        first = nd.minimize(result.sample.payload, predicate)
        second = nd.minimize(result.sample.payload, predicate)
        self.assertEqual(first, second)

    def test_minimization_ignores_numbers_inside_strings(self) -> None:
        """``spec_version`` must not be shrunk like a numeric field."""
        evaluator = self._differing_evaluator()
        result = self._differing_result()
        minimized = nd.minimize(
            result.sample.payload,
            lambda payload: (
                nd._verdict_for(result, payload, evaluator).kind
                is nd.VerdictKind.SECURITY_DIFFERENCE
            ),
        )
        self.assertIn(b'"spec_version":"1.0.0"', minimized)

    def test_reproducer_is_written_deterministically(self) -> None:
        evaluator = self._differing_evaluator()
        result = self._differing_result()
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            payload_path, meta_path = nd.save_reproducer(
                directory, result, evaluator
            )
            first_payload = payload_path.read_bytes()
            first_meta = meta_path.read_text(encoding="utf-8")

            # Rewriting the same result reproduces identical bytes.
            payload_path2, meta_path2 = nd.save_reproducer(
                directory, result, evaluator
            )
            self.assertEqual(payload_path, payload_path2)
            self.assertEqual(meta_path, meta_path2)
            self.assertEqual(first_payload, payload_path2.read_bytes())
            self.assertEqual(first_meta, meta_path2.read_text(encoding="utf-8"))

            # ... and the sidecar records both conclusions.
            meta = json.loads(first_meta)
            self.assertEqual(meta["verdict"], "security-difference")
            self.assertEqual(meta["sample"], result.sample.name)
            self.assertEqual(meta["entries"]["metadata"]["accepted"], True)
            self.assertEqual(meta["entries"]["simple"]["accepted"], True)
            self.assertNotEqual(
                meta["entries"]["metadata"]["numbers"],
                meta["entries"]["simple"]["numbers"],
            )

    def test_reproducer_is_minimal_against_original(self) -> None:
        """A long number literal is shrunk while the divergence survives."""
        evaluator = self._differing_evaluator()
        sample = nd.Sample(
            name="timestamp.version long",
            role="timestamp",
            field="version",
            tokens=(nd.LONG_DECIMAL,),
            payload=nd.ROLES["timestamp"].build("version", nd.LONG_DECIMAL),
        )
        result = nd.run_sample(sample, evaluator)
        self.assertIs(result.verdict.kind, nd.VerdictKind.SECURITY_DIFFERENCE)
        with TemporaryDirectory() as tmp:
            payload_path, _ = nd.save_reproducer(Path(tmp), result, evaluator)
            self.assertLess(
                len(payload_path.read_bytes()),
                len(result.sample.payload),
            )
            # The surviving literal is the shortest one that diverges.
            stored = payload_path.read_bytes()
            self.assertNotIn(nd.LONG_DECIMAL.encode(), stored)

    def test_refuses_to_save_agreeing_sample(self) -> None:
        result = nd.run_sample(self._sample())
        with (
            TemporaryDirectory() as tmp,
            self.assertRaises(ValueError),
        ):
            nd.save_reproducer(Path(tmp), result)

    def test_save_failures_only_persists_failures(self) -> None:
        evaluator = self._differing_evaluator()
        agreeing = nd.run_sample(self._sample())
        differing = self._differing_result()
        with TemporaryDirectory() as tmp:
            paths = nd.save_failures(
                [agreeing, differing], Path(tmp), evaluator=evaluator
            )
            self.assertEqual(len(paths), 2)
            self.assertEqual({path.suffix for path in paths}, {".json"})


class TestEnvelopeTypeIntegration(unittest.TestCase):
    """End-to-end: the same signed payload through both ``EnvelopeType``s.

    These tests do not stub the entries: they sign real metadata with the
    deterministic ed25519 test keys, load a real root, and let
    ``TrustedMetadataSet`` dispatch on ``EnvelopeType``.  They verify the same
    property as the corpus sweep at the integration level: the entries must
    not disagree on validity (beyond the canonical JSON limitation) or on the
    number that ends up consumed.
    """

    PAYLOAD_TYPE = nd.DEFAULT_PAYLOAD_TYPE
    SIGNERS: dict[str, Signer] = {
        role: signers[index]
        for index, role in enumerate(
            ("root", "timestamp", "snapshot", "targets")
        )
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Metadata(Root(expires=EXPIRY))
        for role, signer in cls.SIGNERS.items():
            cls.root.signed.add_key(signer.public_key, role)
        cls.root.sign(cls.SIGNERS["root"])

        cls.metadata_root = cls.root.to_bytes(JSONSerializer())
        cls.simple_root = cls.dsse_envelope(cls.root_payload(), "root")

    @classmethod
    def root_payload(cls) -> bytes:
        return json.dumps(cls.root.signed.to_dict()).encode()

    @classmethod
    def pae(cls, payload: bytes) -> bytes:
        payload_type = cls.PAYLOAD_TYPE.encode()
        return b"DSSEv1 %d %b %d %b" % (
            len(payload_type),
            payload_type,
            len(payload),
            payload,
        )

    @classmethod
    def dsse_envelope(cls, payload: bytes, role: str) -> bytes:
        signature = cls.SIGNERS[role].sign(cls.pae(payload)).to_dict()
        signature["sig"] = base64.b64encode(
            bytes.fromhex(signature["sig"])
        ).decode()
        return json.dumps(
            {
                "payload": base64.b64encode(payload).decode(),
                "payloadType": cls.PAYLOAD_TYPE,
                "signatures": [signature],
            },
            separators=(",", ":"),
        ).encode()

    @classmethod
    def metadata_envelope(cls, payload: bytes, role: str) -> bytes:
        """Sign ``payload`` and splice it into a traditional envelope.

        The payload bytes are kept verbatim so shared corpus properties (such
        as a long integer literal) reach the traditional entry unchanged.
        """
        parsed = Metadata.from_dict(
            {"signed": json.loads(payload), "signatures": []}
        )
        parsed.sign(cls.SIGNERS[role])
        signatures = json.loads(
            parsed.to_bytes(JSONSerializer()).decode("utf-8")
        )["signatures"]
        return (
            b'{"signatures":'
            + json.dumps(signatures, separators=(",", ":")).encode()
            + b',"signed":'
            + payload
            + b"}"
        )

    @classmethod
    def wrap(
        cls, envelope_type: EnvelopeType, payload: bytes, role: str
    ) -> bytes:
        if envelope_type is EnvelopeType.SIMPLE:
            return cls.dsse_envelope(payload, role)
        return cls.metadata_envelope(payload, role)

    @classmethod
    def bootstrap(cls, envelope_type: EnvelopeType) -> bytes:
        if envelope_type is EnvelopeType.SIMPLE:
            return cls.simple_root
        return cls.metadata_root

    def _load_chain(
        self,
        envelope_type: EnvelopeType,
        role: str,
        version: object,
    ) -> nd.Consumption:
        """Run the update chain up to ``role`` with the given version."""
        payloads = {
            "timestamp": Timestamp(expires=EXPIRY),
            "snapshot": Snapshot(expires=EXPIRY),
            "targets": Targets(expires=EXPIRY),
        }
        try:
            trusted_set = TrustedMetadataSet(
                self.bootstrap(envelope_type), envelope_type
            )
            update_order = ("timestamp", "snapshot", "targets")
            for name in update_order:
                signed = payloads[name].to_dict()
                if name == role:
                    signed["version"] = version
                raw = json.dumps(signed, separators=(",", ":")).encode()
                data = self.wrap(envelope_type, raw, name)
                if name == "timestamp":
                    trusted_set.update_timestamp(data)
                elif name == "snapshot":
                    trusted_set.update_snapshot(data)
                else:
                    trusted_set.update_targets(data)
                if name == role:
                    break
            consumed = getattr(trusted_set, role)
            return nd.Consumption(
                entry=(
                    nd.Entry.SIMPLE
                    if envelope_type is EnvelopeType.SIMPLE
                    else nd.Entry.METADATA
                ),
                accepted=True,
                numbers=tuple(nd._walk_numbers(consumed.to_dict())),
            )
        except Exception as exc:  # noqa: BLE001 - every failure is a conclusion
            return nd.Consumption(
                entry=(
                    nd.Entry.SIMPLE
                    if envelope_type is EnvelopeType.SIMPLE
                    else nd.Entry.METADATA
                ),
                accepted=False,
                errors=nd._error_chain(exc),
            )

    def _both(
        self, role: str, version: object
    ) -> tuple[nd.Consumption, nd.Consumption]:
        return (
            self._load_chain(EnvelopeType.METADATA, role, version),
            self._load_chain(EnvelopeType.SIMPLE, role, version),
        )

    def test_legal_versions_agree_end_to_end(self) -> None:
        """Versions that satisfy the whole workflow agree on both entries.

        Only timestamp version is free-form; snapshot and targets versions are
        pinned by the rollback checks to the value advertised by their parent,
        so the accepted case is exercised with that value.
        """
        for role, version in (
            ("timestamp", 1),
            ("timestamp", 2),
            ("snapshot", 1),
            ("targets", 1),
        ):
            with self.subTest(role=role, version=version):
                metadata, simple = self._both(role, version)
                self.assertTrue(metadata.accepted, metadata.errors)
                self.assertTrue(simple.accepted, simple.errors)
                self.assertEqual(metadata.numbers, simple.numbers)

    def test_rejected_versions_agree_end_to_end(self) -> None:
        """An out-of-range version is rejected by both entries alike."""
        for role in ("snapshot", "targets"):
            with self.subTest(role=role):
                metadata, simple = self._both(role, 2)
                self.assertFalse(metadata.accepted)
                self.assertFalse(simple.accepted)
                verdict = nd.classify(b"{}", metadata, simple)
                self.assertIs(verdict.kind, nd.VerdictKind.AGREE)

    def test_large_integer_version_matches_end_to_end(self) -> None:
        """Both envelopes either accept the exact value or both reject."""
        metadata, simple = self._both("timestamp", int(nd.TWO_POW_53_PLUS_ONE))
        self.assertTrue(metadata.accepted, metadata.errors)
        self.assertTrue(simple.accepted, simple.errors)
        self.assertEqual(metadata.numbers, simple.numbers)

    def test_float_version_is_spec_limitation_not_security_difference(
        self,
    ) -> None:
        """The traditional format cannot express a float; the value matches."""
        raw = json.dumps(
            {**Timestamp(expires=EXPIRY).to_dict(), "version": 1.5},
            separators=(",", ":"),
        ).encode()
        metadata, simple = self._both("timestamp", 1.5)
        self.assertFalse(metadata.accepted)
        self.assertTrue(simple.accepted)
        self.assertTrue(nd._is_canonical_encoding_rejection(metadata))

        verdict = nd.classify(raw, metadata, simple)
        self.assertIs(verdict.kind, nd.VerdictKind.SPEC_REJECTION)

    def test_duplicate_key_payload_agrees_end_to_end(self) -> None:
        """Repeated keys survive both entries identically."""
        raw = (
            b'{"_type":"timestamp","spec_version":"1.0.0","version":1,'
            b'"version":2,"expires":"2050-01-01T00:00:00Z","meta":'
            b'{"snapshot.json":{"version":1}}}'
        )
        consumptions = []
        for envelope_type in (EnvelopeType.METADATA, EnvelopeType.SIMPLE):
            data = self.wrap(envelope_type, raw, "timestamp")
            try:
                trusted_set = TrustedMetadataSet(
                    self.bootstrap(envelope_type), envelope_type
                )
                trusted_set.update_timestamp(data)
                consumptions.append(
                    nd.Consumption(
                        entry=nd.Entry.METADATA
                        if envelope_type is EnvelopeType.METADATA
                        else nd.Entry.SIMPLE,
                        accepted=True,
                        numbers=tuple(
                            nd._walk_numbers(trusted_set.timestamp.to_dict())
                        ),
                    )
                )
            except Exception as exc:  # noqa: BLE001
                consumptions.append(
                    nd.Consumption(
                        entry=nd.Entry.METADATA
                        if envelope_type is EnvelopeType.METADATA
                        else nd.Entry.SIMPLE,
                        accepted=False,
                        errors=nd._error_chain(exc),
                    )
                )

        metadata, simple = consumptions
        self.assertTrue(metadata.accepted, metadata.errors)
        self.assertTrue(simple.accepted, simple.errors)
        self.assertEqual(metadata.numbers, simple.numbers)
        versions = [
            value for path, _, value in metadata.numbers if path == "version"
        ]
        self.assertEqual(versions, ["2"])


class TestCommandLine(unittest.TestCase):
    """The local command must run repeatably and report failures."""

    @staticmethod
    def _run_main(arguments: list[str]) -> int:
        """Run ``nd.main`` with its report output captured."""
        with contextlib.redirect_stdout(io.StringIO()):
            return nd.main(arguments)

    def test_main_succeeds_on_clean_corpus(self) -> None:
        with TemporaryDirectory() as tmp:
            self.assertEqual(self._run_main(["--artifact-dir", tmp]), 0)
            # A clean corpus must not leave reproducers behind.
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_main_is_repeatable(self) -> None:
        """Two runs must reach the same verdicts and write no artifacts."""
        with TemporaryDirectory() as tmp:
            first = self._run_main(["--artifact-dir", tmp, "--verbose"])
            second = self._run_main(["--artifact-dir", tmp, "--verbose"])
            self.assertEqual(first, second)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_main_writes_reproducers_for_failures(self) -> None:
        evaluator = TestMinimizationAndReproducers._differing_evaluator()
        sample = TestMinimizationAndReproducers()._sample()
        result = nd.run_sample(sample, evaluator)
        with TemporaryDirectory() as tmp:
            saved = nd.save_failures([result], Path(tmp), evaluator=evaluator)
            self.assertTrue(saved)
            self.assertTrue(all(path.exists() for path in saved))

    def test_strict_mode_flags_spec_rejections(self) -> None:
        results = [
            result
            for result in nd.sweep()
            if result.verdict.kind is nd.VerdictKind.SPEC_REJECTION
        ]
        self.assertTrue(results)
        self.assertEqual(nd.failing_results(results), [])
        self.assertEqual(
            len(nd.failing_results(results, include_spec_rejections=True)),
            len(results),
        )

    def test_main_strict_mode_exits_nonzero(self) -> None:
        with TemporaryDirectory() as tmp:
            self.assertEqual(
                self._run_main(["--artifact-dir", tmp, "--strict"]), 1
            )
            self.assertTrue(list(Path(tmp).iterdir()))


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
