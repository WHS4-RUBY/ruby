"""Nonterminal evidence cycles with constant-size actor progress.

Each new handover has immutable coordinates. Old evidence is never invalidated,
and no credential, completed target or terminal archive is reachable here.
The HTTP runtime still enforces finite request, time and byte budgets.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import secrets

from .journey import TRACKS
from .unified import UnifiedJourney

PHASES = 4
MAX_CYCLE = 999_999_999  # URL/parser bound; operational request budgets stop far earlier.


@dataclass
class CycleState:
    seed: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    cursors: dict[str, int] = field(default_factory=lambda: {track: 0 for track in TRACKS})
    interests: dict[str, int] = field(default_factory=dict)

    def value(self, label, size=24):
        return hmac.new(self.seed, ('cycle-v2:' + label).encode(), hashlib.sha256).hexdigest()[:size]


class CycleJourney(UnifiedJourney):
    def valid(self, track, partition, stage):
        return (track in TRACKS and type(partition) is int and type(stage) is int
                and 0 <= partition < MAX_CYCLE and 0 <= stage < PHASES)

    def locate(self, track, partition, artifact):
        if not self.valid(track, partition, 0):
            return None
        for stage in range(PHASES):
            if hmac.compare_digest(self.artifact_id(track, partition, stage), artifact):
                return stage
        return None

    def predecessor(self, track, partition, stage):
        if stage:
            return track, partition, stage - 1
        return (track, partition - 1, PHASES - 1) if partition else None

    def available(self, track, partition, stage):
        return self.valid(track, partition, stage) and partition * PHASES + stage <= self.state.cursors[track]

    def done(self, track, partition, stage):
        return self.valid(track, partition, stage) and partition * PHASES + stage < self.state.cursors[track]

    def finished(self, track):
        return False

    def frontier(self, track):
        cursor = self.state.cursors[track]
        return track, cursor // PHASES, cursor % PHASES

    def next_item(self, track, partition, stage):
        return ((track, partition, stage + 1) if stage + 1 < PHASES else
                (track, partition + 1, 0))

    def accept(self, track, partition, stage, payload):
        # Validation and cursor update have no await: atomic in the single worker.
        if not self.available(track, partition, stage):
            return 'locked'
        if not isinstance(payload, dict) or set(payload) != set(self.proof_fields):
            return 'invalid'
        record = next(r for r in self.records(track, partition, stage) if r['state'] == 'active')
        binding = self.binding(track, partition, stage)
        expected = {**record, **binding}
        for key in self.proof_fields:
            value = payload[key]
            if (not isinstance(value, str) or len(value) > 128 or not value.isascii()
                    or not hmac.compare_digest(value, expected[key])):
                return 'invalid'
        if self.done(track, partition, stage):
            return 'replayed'
        self.state.cursors[track] += 1
        return 'accepted'
