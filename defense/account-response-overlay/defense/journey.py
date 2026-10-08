"""Finite dependency journeys. Pure local data; no networking, parsing exploits or execution."""
from dataclasses import dataclass, field
import hashlib
import hmac
import secrets


TRACKS = ('accounts',)


@dataclass
class JourneyState:
    # Independent of the public session cookie. Receipts cannot be derived from a cookie.
    seed: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    completed: set[tuple[str, int, int]] = field(default_factory=set)
    interests: dict[str, int] = field(default_factory=dict)

    def value(self, label: str, size=24) -> str:
        return hmac.new(self.seed, label.encode(), hashlib.sha256).hexdigest()[:size]


class Journey:
    def __init__(self, state, config):
        self.state, self.config = state, config

    def valid(self, track, partition, stage):
        return track in TRACKS and 0 <= partition < self.config.rounds and 0 <= stage < self.config.stages

    def artifact_id(self, track, partition, stage):
        return self.state.value(f'artifact:{track}:{partition}:{stage}')

    def locate(self, track, partition, artifact):
        if track not in TRACKS or not 0 <= partition < self.config.rounds:
            return None
        for stage in range(self.config.stages):
            if hmac.compare_digest(self.artifact_id(track, partition, stage), artifact):
                return stage
        return None

    def predecessor(self, track, partition, stage):
        if stage:
            return track, partition, stage - 1
        if partition:
            return track, partition - 1, self.config.stages - 1
        return None

    def available(self, track, partition, stage):
        if not self.valid(track, partition, stage):
            return False
        previous = self.predecessor(track, partition, stage)
        return previous is None or previous in self.state.completed

    def done(self, track, partition, stage):
        return (track, partition, stage) in self.state.completed

    def finished(self, track):
        return self.done(track, self.config.rounds - 1, self.config.stages - 1)

    def frontier(self, track):
        for partition in range(self.config.rounds):
            for stage in range(self.config.stages):
                if not self.done(track, partition, stage):
                    return track, partition, stage
        return None

    def record(self, track, partition, stage, candidate):
        key = f'{track}:{partition}:{stage}:{candidate}'
        selected = int(self.state.value(f'selection:{track}:{partition}:{stage}', 8), 16) % self.config.candidates
        return {
            'record_id': self.state.value('record:' + key),
            'revision': f'js-{partition + 1:02d}.{stage + 1:02d}',
            'state': 'active' if candidate == selected else 'superseded',
            'checksum': self.state.value('checksum:' + key, 64),
        }

    def records(self, track, partition, stage):
        return [self.record(track, partition, stage, i) for i in range(self.config.candidates)]

    def accept(self, track, partition, stage, payload):
        """Return accepted/replayed/locked/invalid; mutation is atomic in our single worker."""
        if not self.available(track, partition, stage):
            return 'locked'
        if not isinstance(payload, dict) or set(payload) != {'record_id', 'revision', 'checksum'}:
            return 'invalid'
        expected = next(row for row in self.records(track, partition, stage) if row['state'] == 'active')
        for key in payload:
            value = payload[key]
            if (not isinstance(value, str) or len(value) > 128 or not value.isascii()
                    or not hmac.compare_digest(value, expected[key])):
                return 'invalid'
        item = track, partition, stage
        if item in self.state.completed:
            return 'replayed'
        self.state.completed.add(item)
        return 'accepted'

    def next_item(self, track, partition, stage):
        if stage + 1 < self.config.stages:
            return track, partition, stage + 1
        if partition + 1 < self.config.rounds:
            return track, partition + 1, 0
        return None

    def observe(self, track):
        if track in TRACKS:
            self.state.interests[track] = min(1_000_000, self.state.interests.get(track, 0) + 1)

    def ranked_tracks(self):
        return sorted(TRACKS, key=lambda track: (-self.state.interests.get(track, 0), TRACKS.index(track)))
