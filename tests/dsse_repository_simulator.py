# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Simulator for a repository that publishes metadata as DSSE envelopes.

``DSSERepositorySimulator`` extends :class:`RepositorySimulator` so that all
metadata (including the explicitly published root versions) is served wrapped
in a :class:`~tuf.api.dsse.SimpleEnvelope` and signed with the same on-demand
signers the base simulator manages.

Per-role overrides make the attack scenarios in
``test_updater_dsse_envelope.py`` expressible without duplicating simulator
logic:

* ``classic_roles`` forces selected roles back into the traditional
  canonical-JSON :class:`~tuf.api.metadata.Metadata` format. This is used to
  serve cross-envelope (mix-and-match) content.
* ``role_bytes`` serves fully attacker-controlled bytes for a role, e.g. a
  fresh payload combined with stale signatures, or an inconsistent
  timestamp/snapshot pair.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.repository_simulator import RepositorySimulator
from tuf.api.dsse import SimpleEnvelope
from tuf.api.exceptions import DownloadHTTPError
from tuf.api.metadata import Metadata, Root
from tuf.api.serialization.json import JSONSerializer

if TYPE_CHECKING:
    from securesystemslib.signer import Signer


class DSSERepositorySimulator(RepositorySimulator):
    """Simulates a repository serving DSSE envelope metadata."""

    def __init__(self) -> None:
        # Initialize overrides before super().__init__(): the base
        # constructor already calls publish_root() for the initial root.
        self.classic_roles: set[str] = set()
        self.role_bytes: dict[str, bytes] = {}

        super().__init__()

        # Re-publish the initial root as a DSSE envelope so that every
        # published root version uses the same envelope format.
        self.signed_roots.clear()
        self.publish_root()

    def _wrap_metadata(self, role: str, md: Metadata) -> bytes:
        """Serialize ``md`` for ``role`` in the configured envelope format."""
        if role in self.classic_roles:
            return md.to_bytes(JSONSerializer())

        envelope = SimpleEnvelope.from_signed(md.signed)
        signers: dict[str, Signer] = self.signers[role]
        for signer in signers.values():
            envelope.sign(signer)
        return envelope.to_bytes()

    def publish_root(self) -> None:
        """Sign and store a new DSSE-enveloped root version."""
        self.md_root.signatures.clear()
        for signer in self.signers[Root.type].values():
            self.md_root.sign(signer, append=True)

        self.signed_roots.append(self._wrap_metadata(Root.type, self.md_root))

    def fetch_metadata(self, role: str, version: int | None = None) -> bytes:
        """Return metadata for ``role`` in DSSE envelope format by default."""
        self.fetch_tracker.metadata.append((role, version))

        # Fully controlled role content (e.g. stale-signature or inconsistent
        # metadata) bypasses signing and envelope wrapping.
        if role in self.role_bytes:
            return self.role_bytes[role]

        if role == Root.type:
            # Root versions are served from the published envelope list
            if version is None or version > len(self.signed_roots):
                raise DownloadHTTPError(f"Unknown root version {version}", 404)
            return self.signed_roots[version - 1]

        # Resolve the in-memory metadata object the way the base class does
        md: Metadata | None
        if role == self.md_timestamp.signed.type:
            md = self.md_timestamp
        elif role == self.md_snapshot.signed.type:
            md = self.md_snapshot
        elif role == self.md_targets.signed.type:
            md = self.md_targets
        else:
            md = self.md_delegates.get(role)

        if md is None:
            raise DownloadHTTPError(f"Unknown role {role}", 404)

        if role in self.classic_roles:
            # Sign in classic form and delegate canonical JSON serialization
            md.signatures.clear()
            for signer in self.signers[role].values():
                md.sign(signer, append=True)
            return md.to_bytes(JSONSerializer())

        return self._wrap_metadata(role, md)
