# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""End-to-end DSSE envelope tests for the ngclient update workflow.

The tests exercise a complete metadata chain (root, timestamp, snapshot and
targets) that is published in the Dead Simple Signing Envelope (DSSE) format
through :class:`~tuf.ngclient.Updater`, using
:class:`~tests.dsse_repository_simulator.DSSERepositorySimulator` as an
in-memory repository.

Three classes of rejection are kept explicitly distinct so that the failure
reason is unambiguous:

1. **Rollback** -> ``BadVersionNumberError``: a version number is decreased
   (timestamp/snapshot rollback, version-number fallback, or a timestamp that
   references an older snapshot).
2. **Freeze** -> ``ExpiredMetadataError``: metadata is past its expiry date.
3. **Envelope mix-and-match** -> ``DeserializationError`` /
   ``UnsignedMetadataError``: DSSE and the classic canonical-JSON Metadata
   format are swapped, or a new payload is presented with stale signatures.

The tests also assert that rejected metadata is never cached, that the
cache write order follows root -> timestamp -> snapshot -> targets, and that
after a failed update a subsequent valid update succeeds. Finally, the
classic (non-DSSE) metadata path is checked for backwards compatibility.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from tests import utils
from tests.dsse_repository_simulator import DSSERepositorySimulator
from tests.repository_simulator import RepositorySimulator
from tuf.api import exceptions
from tuf.api.dsse import SimpleEnvelope
from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
    Metadata,
    Root,
    Snapshot,
    Targets,
    Timestamp,
)
from tuf.api.serialization import DeserializationError
from tuf.ngclient import Updater, UpdaterConfig
from tuf.ngclient.config import EnvelopeType

METADATA_URL = "https://example.com/metadata/"
TARGETS_URL = "https://example.com/targets/"


class TestDSSEUpdater(unittest.TestCase):
    """Updater end-to-end tests against a DSSE envelope repository."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)

        self.sim = DSSERepositorySimulator()
        self.bootstrap = self.sim.signed_roots[0]

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _init_updater(
        self,
        envelope_type: EnvelopeType = EnvelopeType.SIMPLE,
        sim: RepositorySimulator | None = None,
        bootstrap: bytes | None = None,
    ) -> Updater:
        """Create an Updater backed by the in-memory simulator."""
        repository = sim or self.sim
        return Updater(
            self.metadata_dir,
            METADATA_URL,
            self.targets_dir,
            TARGETS_URL,
            repository,
            config=UpdaterConfig(envelope_type=envelope_type),
            bootstrap=self.bootstrap if bootstrap is None else bootstrap,
        )

    def _cached_envelope(self, role: str) -> SimpleEnvelope:
        """Load the cached metadata for ``role`` as a DSSE envelope."""
        path = os.path.join(self.metadata_dir, f"{role}.json")
        with open(path, "rb") as f:
            return SimpleEnvelope.from_bytes(f.read())

    def _cached_version(self, role: str) -> int:
        """Return the payload version stored in the cached envelope."""
        return self._cached_envelope(role).get_signed().version

    def _assert_cached_roles(self, roles: list[str]) -> None:
        """Assert that exactly ``roles`` are cached as metadata files."""
        found = [
            entry.name
            for entry in os.scandir(self.metadata_dir)
            if entry.is_file() and entry.name.endswith(".json")
        ]
        self.assertListEqual(sorted(found), sorted(f"{r}.json" for r in roles))

    # ------------------------------------------------------------------
    # Happy path and backwards compatibility
    # ------------------------------------------------------------------

    def test_dsse_refresh_persists_envelopes(self) -> None:
        """A valid DSSE repository refreshes and caches envelope bytes."""
        updater = self._init_updater()
        updater.refresh()

        self._assert_cached_roles(list(TOP_LEVEL_ROLE_NAMES))

        # Every cached non-root role must be a DSSE envelope, not classic
        # Metadata: parsing it as classic Metadata must fail.
        for role in [Timestamp.type, Snapshot.type, Targets.type]:
            envelope = self._cached_envelope(role)
            self.assertEqual(
                envelope.payload_type, SimpleEnvelope.DEFAULT_PAYLOAD_TYPE
            )
            with (
                open(
                    os.path.join(self.metadata_dir, f"{role}.json"), "rb"
                ) as f,
                self.assertRaises(DeserializationError),
            ):
                Metadata.from_bytes(f.read())

        # The root history stores the enveloped trust anchor
        root_history = os.path.join(self.metadata_dir, "root_history")
        self.assertTrue(
            os.path.exists(os.path.join(root_history, "1.root.json"))
        )

    @patch("tuf.ngclient.updater.os.replace", wraps=os.replace)
    def test_dsse_cache_write_order(self, wrapped_replace: MagicMock) -> None:
        """Cache writes follow root -> timestamp -> snapshot -> targets."""
        updater = self._init_updater()
        updater.refresh()

        # Each atomic persist finalizes a temp file via os.replace(): the
        # destination basenames reveal the cache write order.
        persisted = [
            os.path.basename(call_args.args[1])
            for call_args in wrapped_replace.call_args_list
        ]
        self.assertEqual(
            persisted,
            [
                "1.root.json",
                "timestamp.json",
                "snapshot.json",
                "targets.json",
            ],
        )

    def test_dsse_second_update_uses_cache(self) -> None:
        """A second Updater reuses cached DSSE metadata without re-downloading."""
        self._init_updater().refresh()
        self.sim.fetch_tracker.metadata.clear()

        updater = self._init_updater()
        updater.get_targetinfo("does-not-exist")

        # Only the root probe and the (equal-version) timestamp are fetched;
        # snapshot and targets are trusted from the local cache.
        self.assertEqual(
            self.sim.fetch_tracker.metadata,
            [("root", 2), ("timestamp", None)],
        )

    def test_classic_metadata_path_remains_supported(self) -> None:
        """The traditional canonical-JSON Metadata path stays compatible."""
        classic_sim = RepositorySimulator()
        updater = self._init_updater(
            envelope_type=EnvelopeType.METADATA,
            sim=classic_sim,
            bootstrap=classic_sim.signed_roots[0],
        )
        updater.refresh()

        for role in [Root.type, Timestamp.type, Snapshot.type, Targets.type]:
            path = os.path.join(self.metadata_dir, f"{role}.json")
            # Cached content must parse as classic Metadata, not as DSSE
            metadata = Metadata.from_file(path)
            self.assertEqual(metadata.signed.type, role)
            with (
                open(path, "rb") as f,
                self.assertRaises(DeserializationError),
            ):
                SimpleEnvelope.from_bytes(f.read())

    # ------------------------------------------------------------------
    # 1. Rollback attacks -> BadVersionNumberError
    # ------------------------------------------------------------------

    def test_rollback_timestamp_version(self) -> None:
        """A decreased timestamp version is rejected as a rollback."""
        self.sim.timestamp.version = 2
        self._init_updater().refresh()

        self.sim.timestamp.version = 1
        with self.assertRaises(exceptions.BadVersionNumberError):
            self._init_updater().refresh()

        # The good v2 envelope remains cached; the rolled back one is not stored
        self._assert_cached_roles(list(TOP_LEVEL_ROLE_NAMES))
        self.assertEqual(self._cached_version(Timestamp.type), 2)

    def test_rollback_snapshot_version(self) -> None:
        """A decreased snapshot version is rejected as a rollback."""
        self.sim.snapshot.version = 2
        self.sim.update_timestamp()
        self._init_updater().refresh()

        self.sim.snapshot.version = 1
        self.sim.update_timestamp()
        with self.assertRaises(exceptions.BadVersionNumberError):
            self._init_updater().refresh()

        self.assertEqual(self._cached_version(Snapshot.type), 2)

    def test_rollback_timestamp_references_older_snapshot(self) -> None:
        """A timestamp pointing at an older snapshot is a rollback rejection."""
        self.sim.snapshot.version = 3
        self.sim.update_timestamp()  # timestamp v2 references snapshot v3
        self._init_updater().refresh()

        # New timestamp keeps a fresh version but rolls back the snapshot ref
        self.sim.timestamp.snapshot_meta.version = 1
        self.sim.timestamp.version += 1
        with self.assertRaises(exceptions.BadVersionNumberError):
            self._init_updater().refresh()

        self.assertEqual(self._cached_version(Timestamp.type), 2)

    def test_timestamp_snapshot_version_inconsistency(self) -> None:
        """Timestamp/snapshot disagreement is rejected at the snapshot step."""
        self._init_updater().refresh()

        # Timestamp claims snapshot v5 while the served snapshot stays at v1
        self.sim.timestamp.snapshot_meta.version = 5
        self.sim.timestamp.version += 1

        with self.assertRaises(exceptions.BadVersionNumberError):
            self._init_updater().refresh()

        # The newer timestamp was cached, but the mismatched v1 snapshot was
        # not promoted: the cached snapshot still references the old state.
        self.assertEqual(self._cached_version(Timestamp.type), 2)
        self.assertEqual(self._cached_version(Snapshot.type), 1)

    # ------------------------------------------------------------------
    # 2. Freeze attacks -> ExpiredMetadataError
    # ------------------------------------------------------------------

    def test_freeze_expired_timestamp(self) -> None:
        """An expired timestamp is rejected as a freeze attack."""
        self.sim.timestamp.expires = datetime.now(UTC) - timedelta(days=1)

        with self.assertRaises(exceptions.ExpiredMetadataError):
            self._init_updater().refresh()

        # Nothing beyond the root trust anchor is cached
        self._assert_cached_roles([Root.type])

    def test_freeze_expired_snapshot(self) -> None:
        """An expired snapshot is rejected as a freeze attack."""
        self.sim.snapshot.expires = datetime.now(UTC) - timedelta(days=1)
        self.sim.update_snapshot()

        with self.assertRaises(exceptions.ExpiredMetadataError):
            self._init_updater().refresh()

        # Timestamp is cached before the expired snapshot is rejected
        self._assert_cached_roles([Root.type, Timestamp.type])

    def test_freeze_expired_targets(self) -> None:
        """Expired targets metadata is rejected as a freeze attack."""
        self.sim.targets.expires = datetime.now(UTC) - timedelta(days=1)
        self.sim.update_snapshot()

        with self.assertRaises(exceptions.ExpiredMetadataError):
            self._init_updater().refresh()

        self._assert_cached_roles([Root.type, Timestamp.type, Snapshot.type])

    # ------------------------------------------------------------------
    # 3. Envelope mix-and-match attacks
    # ------------------------------------------------------------------

    def test_mix_classic_timestamp_served_to_dsse_client(self) -> None:
        """Classic Metadata where an envelope is expected fails to parse."""
        self.sim.classic_roles.add(Timestamp.type)

        with self.assertRaises(DeserializationError):
            self._init_updater().refresh()

        self._assert_cached_roles([Root.type])

    def test_mix_classic_snapshot_served_to_dsse_client(self) -> None:
        """A cross-envelope snapshot replacement is rejected at the snapshot."""
        self.sim.classic_roles.add(Snapshot.type)

        with self.assertRaises(DeserializationError):
            self._init_updater().refresh()

        # Timestamp was accepted and cached before the snapshot mismatch
        self._assert_cached_roles([Root.type, Timestamp.type])

    def test_mix_classic_targets_served_to_dsse_client(self) -> None:
        """A cross-envelope targets replacement is rejected at the targets."""
        self.sim.classic_roles.add(Targets.type)

        with self.assertRaises(DeserializationError):
            self._init_updater().refresh()

        self._assert_cached_roles([Root.type, Timestamp.type, Snapshot.type])

    def test_mix_dsse_timestamp_served_to_classic_client(self) -> None:
        """An envelope where classic Metadata is expected fails to parse."""
        dsse_sim = DSSERepositorySimulator()
        classic_sim = RepositorySimulator()

        class CrossEnvelopeSim(RepositorySimulator):
            """Serve classic root but DSSE envelopes for every other role."""

            def fetch_metadata(
                self, role: str, version: int | None = None
            ) -> bytes:
                self.fetch_tracker.metadata.append((role, version))
                if role == Root.type:
                    return super().fetch_metadata(role, version)
                return dsse_sim.fetch_metadata(role, version)

        updater = self._init_updater(
            envelope_type=EnvelopeType.METADATA,
            sim=CrossEnvelopeSim(),
            bootstrap=classic_sim.signed_roots[0],
        )
        with self.assertRaises(DeserializationError):
            updater.refresh()

    def test_mix_new_payload_with_stale_signature(self) -> None:
        """An old signature over a new payload fails signature verification."""
        self._init_updater().refresh()

        # Capture the validly signed envelope, then change the payload without
        # re-signing: the stale signatures no longer match the PAE bytes.
        old_envelope = SimpleEnvelope.from_bytes(
            self.sim.fetch_metadata(Timestamp.type)
        )
        self.sim.timestamp.version += 1
        fresh_envelope = SimpleEnvelope.from_signed(self.sim.timestamp)
        stale_envelope = SimpleEnvelope(
            fresh_envelope.payload,
            fresh_envelope.payload_type,
            old_envelope.signatures,
        )
        self.sim.role_bytes[Timestamp.type] = stale_envelope.to_bytes()

        with self.assertRaises(exceptions.UnsignedMetadataError):
            self._init_updater().refresh()

        # The original, validly signed timestamp remains cached
        self.assertEqual(self._cached_version(Timestamp.type), 1)

    # ------------------------------------------------------------------
    # Failed update: cache integrity and recovery
    # ------------------------------------------------------------------

    def test_failed_update_does_not_poison_cache(self) -> None:
        """A rejected update leaves every cached envelope byte-identical."""
        # Establish a cached v2 timestamp so a later v1 is a real rollback
        self.sim.timestamp.version = 2
        self._init_updater().refresh()

        cached_before = {}
        for role in [Timestamp.type, Snapshot.type, Targets.type]:
            with open(
                os.path.join(self.metadata_dir, f"{role}.json"), "rb"
            ) as f:
                cached_before[role] = f.read()

        # Trigger a rollback rejection against the cached v2 timestamp
        self.sim.timestamp.version = 1
        with self.assertRaises(exceptions.BadVersionNumberError):
            self._init_updater().refresh()

        for role, content in cached_before.items():
            with open(
                os.path.join(self.metadata_dir, f"{role}.json"), "rb"
            ) as f:
                self.assertEqual(f.read(), content, f"cache for {role} changed")

    def test_successful_update_after_failure(self) -> None:
        """After a rejected update, a valid newer update is accepted."""
        # Cache a known-good v2 timestamp
        self.sim.timestamp.version = 2
        self._init_updater().refresh()

        # First attempt rolls the timestamp back and must be rejected
        self.sim.timestamp.version = 1
        with self.assertRaises(exceptions.BadVersionNumberError):
            self._init_updater().refresh()

        # Recover: publish a legitimate newer timestamp + snapshot
        self.sim.timestamp.version = 3
        self.sim.update_snapshot()

        updater = self._init_updater()
        updater.refresh()

        self.assertEqual(self._cached_version(Timestamp.type), 4)
        self.assertEqual(self._cached_version(Snapshot.type), 2)
        self._assert_cached_roles(list(TOP_LEVEL_ROLE_NAMES))


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
