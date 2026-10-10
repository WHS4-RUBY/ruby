"""Mechanical JSON windows; retained references never depend on web meaning."""
import base64
import codecs
from hashlib import sha256
import json


def serialized(value):
    return json.dumps(value, ensure_ascii=False)


def nearest_refs(key, sources, limit=12):
    """Existing refs that share the requested prefix or number, closest numbers first."""
    import re
    match = re.match(r'(.*?)(\d+)$', str(key))
    prefix, number = (match.group(1), int(match.group(2))) if match else (str(key), None)
    def distance(name):
        found = re.match(r'.*?(\d+)$', str(name))
        return abs(int(found.group(1)) - number) if found and number is not None else 0
    same_prefix = sorted((name for name in sources if str(name).startswith(prefix)), key=distance)
    same_number = [name for name in sources if number is not None and str(name).endswith(str(number))
                   and name not in same_prefix]
    picked = (same_number + same_prefix)[:limit]
    return picked or list(sources)[:limit]


def unknown_ref(key, sources):
    return {'ref': key, 'unknown_ref': True, 'nearest': nearest_refs(key, sources),
            'available_count': len(sources)}


def find_text(sources, args):
    """Return literal, overlapping positions in the same units as read_sample."""
    needle = args['text']
    if not isinstance(needle, str) or not needle:
        raise ValueError('FindTextEmpty')
    maximum = args.get('max', 20)
    if type(maximum) is not int or maximum < 0:
        raise ValueError('FindMaxInvalid')
    rows, total, searched = [], 0, 0
    for key in dict.fromkeys(args.get('refs', sources)):
        if key not in sources:
            rows.append(unknown_ref(key, sources))
            continue
        searched += 1
        raw = sources[key]
        text = needle.encode('utf-8') if isinstance(raw, bytes) else needle
        offsets, count, start = [], 0, 0
        while True:
            offset = raw.find(text, start)
            if offset < 0:
                break
            count += 1
            if len(offsets) < maximum:
                offsets.append(offset)
            start = offset + 1
        rows.append({'ref': key, 'offsets': offsets, 'count': count,
                     'unit': 'bytes' if isinstance(raw, bytes) else 'characters',
                     'truncated': count > len(offsets)})
        total += count
    # Zero matches is reported only for refs that exist; an unknown ref is not a search with no result.
    return {'text': needle, 'results': rows, 'total_count': total, 'zero_matches': searched > 0 and total == 0,
            'unknown_refs': [row['ref'] for row in rows if row.get('unknown_ref')]}


def replace_leaves(value, replacements):
    """Apply the model's exact replacements to string values, preserving keys."""
    if isinstance(value, str):
        for replacement in replacements:
            value = value.replace(replacement['find'], replacement['replace'])
        return value
    if isinstance(value, list):
        return [replace_leaves(child, replacements) for child in value]
    if isinstance(value, dict):
        return {key: replace_leaves(child, replacements) for key, child in value.items()}
    return value


def replace_leaves_counted(value, replacements):
    """Apply literal replacements to string leaves and dict keys. Returns the value and the finds that
    matched nowhere, so an unmatched or empty fragment is reported instead of releasing the original."""
    pairs = [(item.get('find'), item.get('replace', '')) for item in replacements if isinstance(item, dict)]
    hits = {find: 0 for find, _ in pairs if isinstance(find, str) and find}
    def text(leaf):
        for find, replacement in pairs:
            if find in hits and find in leaf:
                hits[find] += leaf.count(find)
                leaf = leaf.replace(find, str(replacement))
        return leaf
    def walk(node):
        if isinstance(node, str):
            return text(node)
        if isinstance(node, list):
            return [walk(child) for child in node]
        if isinstance(node, dict):
            return {text(key) if isinstance(key, str) else key: walk(child) for key, child in node.items()}
        return node
    result = walk(value)
    unmatched = [find for find, count in hits.items() if not count]
    unmatched += [find for find, _ in pairs if not isinstance(find, str) or not find]
    return result, unmatched


class ReadMemory:
    """Keep read windows and immutable sources for one model conversation."""
    def __init__(self, buffers, namespace, retained_bytes=32000000, max_windows=1000):
        self.buffers, self.namespace = buffers, namespace
        self.retained_bytes, self.max_windows = retained_bytes, max_windows
        self.windows = {}
        self.sequence = 0

    def snapshot(self):
        return {'sequence': self.sequence, 'windows': [[list(key), value] for key, value in self.windows.items()]}

    def restore(self, saved):
        self.sequence = saved['sequence']
        self.windows = {tuple(key): tuple(value) for key, value in saved['windows']}

    def evict_sources(self, incoming):
        """Drop this conversation's oldest copied sources and their windows until a new source fits."""
        def size(value):
            return len(value) if isinstance(value, bytes) else len(value.encode('utf-8'))
        total = sum(size(value) for key, value in self.buffers.items() if ':source:' in key)
        own = [key for key in self.buffers if key.startswith(self.namespace + ':source:')]
        # Refuse a source that cannot fit even after evicting everything this conversation owns, before evicting.
        if total - sum(size(self.buffers[key]) for key in own) + incoming > self.retained_bytes:
            raise ValueError('ReadMemoryRetentionLimit')
        while own and total + incoming > self.retained_bytes:
            oldest = own.pop(0)
            total -= size(self.buffers.pop(oldest))
            for identity in [identity for identity in self.windows if identity[0] == oldest]:
                self.windows.pop(identity)
        if total + incoming > self.retained_bytes:
            raise ValueError('ReadMemoryRetentionLimit')

    def read(self, raw, args, limit):
        digest = sha256(raw if isinstance(raw, bytes) else raw.encode('utf-8')).hexdigest()
        unit = 'bytes' if isinstance(raw, bytes) else 'characters'
        source = self.namespace + ':source:' + unit + ':' + digest
        if source not in self.buffers:
            self.evict_sources(len(raw if isinstance(raw, bytes) else raw.encode('utf-8')))
        overhead = len(serialized({'requested_ref': args['ref']}))
        window = sample_window(raw, {**args, 'ref': source}, limit - overhead)
        window['requested_ref'] = args['ref']
        self.buffers[source] = raw
        identity = (source, window['offset'], window['length'], window.get('encoding'))
        previous = self.windows.get(identity)
        # Older windows have already left the bounded context; drop them first instead of refusing new reads.
        others = [key for key in self.windows if key != identity]
        total = sum(len(serialized(self.windows[key][1]).encode('utf-8')) for key in others)
        incoming = len(serialized(window).encode('utf-8'))
        while others and ((previous is None and len(others) >= self.max_windows) or total + incoming > self.retained_bytes):
            total -= len(serialized(self.windows.pop(others.pop(0))[1]).encode('utf-8'))
        if total + incoming > self.retained_bytes:
            raise ValueError('ReadWindowRetentionLimit')
        self.windows.pop(identity, None)
        self.sequence += 1
        key = previous[0] if previous else self.namespace + ':window:' + str(self.sequence)
        self.windows[identity] = (key, window)
        return window

    def state(self):
        return [{'window_ref': key, **{name: value for name, value in window.items() if name != 'value'}}
                for key, window in reversed(list(self.windows.values()))]

    def entries(self):
        return [(key, 'read_window', window) for key, window in reversed(list(self.windows.values()))]


def feedback_state(value, key):
    """Keep outcome/range metadata first; retain large payload fields by ref."""
    if not value:
        return None
    metadata = {name: item for name, item in value.items()
                if name not in ('detail', 'sample', 'partial_answer', 'partial_answers', 'previous_feedback')}
    if isinstance(value.get('sample'), dict):
        metadata['sample'] = {name: item for name, item in value['sample'].items() if name != 'value'}
    return {'ref': key, **metadata}


def pack_context(state, entries, buffers, limit):
    """Keep state and every ref, then fill in the caller's observation order."""
    refs, retained, route_counts, index_keys = [], [], {}, set()
    entries = list(entries)
    for _, kind, value in entries:
        if kind == 'samples' and isinstance(value, dict):
            route = value.get('route')
            route_counts[route] = route_counts.get(route, 0) + 1
    for key, kind, value in entries:
        if kind == 'observation_index':
            index_keys.add(key)
        raw = value if kind == 'observation_index' else serialized(value)
        buffers[key] = raw
        entry = {'ref': key, 'kind': kind, 'total_chars': len(raw), 'truncated': False}
        if isinstance(value, dict):
            entry['route'] = value.get('route')
            entry['body_refs'] = [value[name]['ref'] for name in ('screen', 'source')
                                  if isinstance(value.get(name), dict) and 'ref' in value[name]]
            if kind == 'samples':
                entry.update(url=value.get('url'), sample_ref=value.get('ref'),
                             route_sample_count=route_counts[value.get('route')],
                             originals=[{'kind': name, 'ref': value[name].get('ref'),
                                         'total': value[name].get('original_size', len(buffers.get(value[name].get('ref'), ''))),
                                         'retained': len(buffers.get(value[name].get('ref'), '')),
                                         'unit': 'bytes' if isinstance(buffers.get(value[name].get('ref')), bytes) else 'characters',
                                         'truncated': bool(value[name].get('truncated') or value[name].get('capture_truncated'))}
                                        for name in ('screen', 'source') if isinstance(value.get(name), dict) and 'ref' in value[name]])
        refs.append(entry)
        retained.append((key, value, raw))
    result = {**state, 'sample_refs': refs, 'included_samples': [], 'omitted_sample_refs': [],
              'instruction': 'State and refs are complete. Read omitted or partial samples with read_sample; '
                             'a window is not evidence of absence.'}
    # Reserve the omitted list up front so adding inline data cannot displace refs.
    result['omitted_sample_refs'] = [key for key, _, _ in retained]
    if len(serialized(result)) > limit:
        # Both state and the manifest remain readable, even if metadata alone
        # exceeds the window. Never return an oversized object to the caller.
        buffers['context:state'] = serialized(state)
        for entry in refs:
            entry['truncated'] = True
        buffers['context:manifest'] = serialized({'sample_refs': refs})
        result = {'state_exceeds_window': True, 'state_ref': 'context:state',
                  'manifest_ref': 'context:manifest', 'total_chars': len(buffers['context:state']),
                  'instruction': 'Read state_ref and manifest_ref with read_sample. No evidence was deleted.',
                  'sample_refs': [], 'included_samples': [], 'omitted_sample_refs': []}
        if 'cost_budget' in state:
            result['cost_budget'] = state['cost_budget']
        for key in ('authority', 'working_notes', 'observation_index_ref'):
            if key in state:
                result[key] = state[key]
        if len(serialized(result)) > limit:
            raise ValueError('ContextWindowTooSmall')
        return result
    for key, value, raw in retained:
        item = {'ref': key, 'value': value, 'truncated': False}
        result['included_samples'].append(item)
        result['omitted_sample_refs'].remove(key)
        if len(serialized(result)) <= limit and (key not in index_keys or len(serialized(item)) <= limit // 4):
            continue
        # A partial window is a labelled string, never a broken JSON object.
        item.update(value='', truncated=True, offset=0, length=0, total_chars=len(raw))
        low, high = 0, min(len(raw), limit // 4) if key in index_keys else len(raw)
        while low < high:
            middle = (low + high + 1) // 2
            item.update(value=raw[:middle], length=middle)
            if len(serialized(result)) <= limit:
                low = middle
            else:
                high = middle - 1
        item.update(value=raw[:low], length=low)
        if not low or len(serialized(result)) > limit:
            result['included_samples'].pop()
            result['omitted_sample_refs'].append(key)
        # Preserve recency order rather than skipping a large recent sample.
        if key not in index_keys:
            break
    included = {item['ref']: item for item in result['included_samples']}
    for entry in refs:
        item = included.get(entry['ref'])
        entry['truncated'] = item is None or item['truncated']
    return result


def sample_window(raw, args, limit):
    offset, count = args.get('offset', 0), args.get('limit', limit)
    if type(offset) is not int or type(count) is not int or offset < 0 or count < 1:
        raise ValueError('InvalidSampleRange')
    count = min(count, limit, max(0, len(raw) - offset))

    def window(size):
        piece = raw[offset:offset + size]
        if isinstance(piece, bytes):
            if args.get('encoding') and args['encoding'] != 'base64':
                decoder = codecs.getincrementaldecoder(args['encoding'])()
                value = decoder.decode(piece, final=False)
                pending = decoder.getstate()[0]
                if pending:
                    piece = piece[:-len(pending)]
            else:
                value = base64.b64encode(piece).decode('ascii')
        else:
            value = piece
        return {'ref': args['ref'], 'offset': offset, 'length': len(piece), 'total': len(raw),
                'unit': 'bytes' if isinstance(raw, bytes) else 'characters', 'value': value,
                'encoding': (args.get('encoding') or 'base64') if isinstance(raw, bytes) else None,
                'truncated': offset + len(piece) < len(raw)}

    # Account for JSON escaping/base64 expansion instead of a fixed half-window.
    result = window(count)
    if len(serialized(result)) > limit:
        low, high = 0, count
        while low < high:
            middle = (low + high + 1) // 2
            candidate = window(middle)
            if len(serialized(candidate)) <= limit:
                low = middle
            else:
                high = middle - 1
        count, result = low, window(low)
    if result['length'] == 0 and offset < len(raw):
        raise ValueError('SampleWindowTooSmall')
    return result
