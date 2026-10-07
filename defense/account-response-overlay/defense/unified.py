"""Shared bounded graph for evidence discovery, registry gates and local outcomes.

No network, payload execution or origin access. Evidence and registry bindings
must describe the same actor, track, partition and stage before progress changes.
"""
import hmac

from .journey import Journey


class UnifiedJourney(Journey):
    proof_fields = ('record_id', 'revision', 'checksum', 'binding_id', 'binding_checksum')

    def record(self, track, partition, stage, candidate):
        row = super().record(track, partition, stage, candidate)
        row['revision'] += f'.r{candidate + 1}'
        return row

    def source_id(self, track, partition, stage, candidate):
        return self.state.value(f'source:{track}:{partition}:{stage}:{candidate}')

    def source_candidate(self, track, partition, stage, source):
        for candidate in range(self.config.candidates):
            if hmac.compare_digest(self.source_id(track, partition, stage, candidate), source):
                return candidate
        return None

    def binding(self, track, partition, stage):
        key = f'{track}:{partition}:{stage}'
        record = next(r for r in self.records(track, partition, stage) if r['state'] == 'active')
        previous = self.predecessor(track, partition, stage)
        return {
            'binding_id': self.state.value('binding:' + key),
            'binding_checksum': self.state.value('binding-checksum:' + key, 64),
            'source_revision': record['revision'],
            'predecessor_reference': self.state.value('resolution:' + ':'.join(map(str, previous)))
                                     if previous else None,
        }

    def accept(self, track, partition, stage, payload):
        if not self.available(track, partition, stage):
            return 'locked'
        if not isinstance(payload, dict) or set(payload) != set(self.proof_fields):
            return 'invalid'
        binding = self.binding(track, partition, stage)
        for key in ('binding_id', 'binding_checksum'):
            value = payload[key]
            if (not isinstance(value, str) or len(value) > 128 or not value.isascii()
                    or not hmac.compare_digest(value, binding[key])):
                return 'invalid'
        return super().accept(track, partition, stage,
                              {k: payload[k] for k in ('record_id', 'revision', 'checksum')})
