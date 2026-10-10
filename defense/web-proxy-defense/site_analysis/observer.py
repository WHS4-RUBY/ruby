"""Passive browser observation with structural write and scope boundaries."""
import asyncio
import base64
from dataclasses import dataclass
from pathlib import Path
import json
import os
import inspect
import time
from urllib.parse import urljoin, urlsplit

from .catalog import ACTION_SCHEMA, required
from .model import ModelError
from .prompts import NAVIGATE
from .record import Failures, isolated, isolated_async, measured, now, public_facts, ref
from .windows import ReadMemory, feedback_state, find_text, pack_context, serialized

# Bounded wait for scripts to finish filling a page before it is sampled.
RENDER_WAIT_MS = 3000


def utf16_units(text):
    return len(text.encode('utf-16-le', 'surrogatepass')) // 2


def session_summary(path):
    """Counts only: how many cookies the prepared session holds, how many have expired, local storage origins."""
    state = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    cookies = state.get('cookies') or []
    timed = [cookie for cookie in cookies if (cookie.get('expires') or -1) > 0]
    expired = [cookie for cookie in timed if cookie['expires'] < time.time()]
    origins = state.get('origins') or []
    return {'cookies': len(cookies), 'session_cookies': len(cookies) - len(timed), 'expired_cookies': len(expired),
            'local_storage_origins': len(origins),
            'expired': bool(cookies) and len(expired) == len(cookies) and not origins}


SECRET_HEADERS = {'cookie', 'set-cookie', 'authorization', 'proxy-authorization',
                  'authentication-info', 'proxy-authentication-info'}
# Form metadata without values. Attributes are read through the prototypes, so an input named "action",
# "method" or "elements" cannot shadow the form's own properties.
FORM_READ = """form => {
  const attr = (node, name) => Element.prototype.getAttribute.call(node, name);
  const has = (node, name) => Element.prototype.hasAttribute.call(node, name);
  const elements = Array.from(Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, 'elements').get.call(form));
  const constraint = ['maxlength', 'minlength', 'pattern', 'min', 'max', 'step', 'autocomplete', 'multiple',
                      'accept', 'inputmode', 'size', 'list'];
  return {
    action: new URL(attr(form, 'action') || '', document.baseURI).href,
    method: (attr(form, 'method') || 'get').toUpperCase(),
    enctype: attr(form, 'enctype'),
    field_names: elements.map(element => attr(element, 'name')),
    fields: elements.map(element => ({
      tag: element.tagName.toLowerCase(), name: attr(element, 'name'), type: attr(element, 'type'),
      required: has(element, 'required'), disabled: has(element, 'disabled'), readonly: has(element, 'readonly'),
      constraints: Object.fromEntries(constraint.filter(name => has(element, name)).map(name => [name, attr(element, name)])),
      option_count: element.tagName === 'SELECT' ? element.options.length : null
    }))
  };
}"""
FORM_GUARD = """(() => {
  const read = """ + FORM_READ + """;
  const emit = form => window.__siteAnalysisForm(read(form));
  for (const name of ['submit', 'requestSubmit']) {
    HTMLFormElement.prototype[name] = function() { void emit(this); };
  }
  document.addEventListener('submit', event => {
    event.preventDefault();
    event.stopImmediatePropagation();
    void emit(event.target);
  }, true);
})();"""


def authority(url):
    part = urlsplit(url)
    return part.scheme, part.hostname, part.port or (443 if part.scheme == 'https' else 80)


@dataclass
class Budget:
    requests: int = 3000
    pages: int = 60
    seconds: float = 1800
    sample_chars: int = 600000
    used_requests: int = 0
    used_pages: int = 0
    sent_requests: int = 0
    started: float = 0

    def begin(self):
        self.started = time.monotonic()

    def exhausted(self):
        return self.used_requests >= self.requests or self.used_pages >= self.pages or self.remaining() <= 0

    def remaining(self):
        return max(0, self.seconds - (time.monotonic() - self.started))

    def take_request(self):
        if self.used_requests >= self.requests or self.remaining() <= 0:
            return False
        self.used_requests += 1
        return True

    def take_page(self):
        if self.exhausted():
            return False
        self.used_pages += 1
        return True

    def record(self):
        return {'source': 'observer_counter', 'limits': {'requests': self.requests, 'pages': self.pages,
                'seconds': self.seconds, 'sample_chars': self.sample_chars},
                'used_requests': self.used_requests, 'sent_requests': self.sent_requests,
                'used_pages': self.used_pages, 'elapsed_seconds': round(time.monotonic() - self.started, 3),
                'exhausted': self.exhausted(), 'exhausted_dimensions': [key for key, flag in
                (('requests', self.used_requests >= self.requests), ('pages', self.used_pages >= self.pages),
                 ('seconds', self.remaining() <= 0)) if flag]}


def response_headers(headers):
    return [{'name': item['name'], 'value': None if item['name'].lower() in SECRET_HEADERS else item['value'],
             'value_withheld': item['name'].lower() in SECRET_HEADERS} for item in headers]


def cookie_metadata(headers):
    """Split Set-Cookie mechanically: the first pair names the cookie, every later part is an attribute.
    No attribute list is assumed, so new attributes (Priority, Partitioned, ...) are kept as written."""
    cookies = []
    for header in headers:
        if header['name'].lower() != 'set-cookie':
            continue
        # Browsers join repeated Set-Cookie headers with a newline.
        for line in str(header['value']).split('\n'):
            parts = [part.strip() for part in line.split(';')]
            name, separator, _ = parts[0].partition('=')
            if not separator or not name.strip():
                # A broken cookie cannot discard another header's cookies.
                cookies.append({'status': '못 얻음', 'name': None, 'attributes': [], 'error': 'CookieNameMissing'})
                continue
            attributes = []
            for part in parts[1:]:
                if part:
                    key, separator, value = part.partition('=')
                    attributes.append({'name': key.strip().lower(), 'value': value.strip() if separator else True})
            cookies.append({'status': '관찰됨', 'name': name.strip(), 'attributes': attributes})
    return cookies


class Observer:
    def __init__(self, origin, model, budget, credentials=None, failure_limit=8, axis_questions=(), checkpoint=None,
                 request_seconds=30, body_bytes=2000000, retained_bytes=32000000, stream_messages=1000,
                 session_file=None, extra_origins=()):
        self.origin, self.model, self.budget = origin, model, budget
        # Operator-approved origins of the same web (CDN, api. host); everything else stays out of scope.
        self.extra_authorities = {authority(item) for item in extra_origins}
        self.credentials = credentials or {}
        self.samples, self.responses, self.attempts, self.unopened, self.decisions = [], [], [], [], []
        self.response_bodies, self.form_attempts, self.realtime, self.feedback = [], [], [], []
        self.tasks, self.buffers, self.navigations = set(), {}, []
        self.failures = Failures(failure_limit)
        self.login_attempted = self.login_sent = self.human_gate = self.model_done = False
        self.backend, self.transport_source = 'playwright', 'browser'
        self.page, self.pages, self.context_snapshot = None, [], ''
        self.browser_context = None
        self.axis_questions, self.checkpoint = axis_questions, checkpoint
        self.context_buffers, self.buffer_routes, self.decision_events = {}, {}, []
        self.read_memory = ReadMemory(self.context_buffers, 'navigation-read')
        self.current_http_url, self.browse_stop_reason = None, None
        self.resume_url = None
        self.resume_decision = None
        self.request_seconds, self.body_bytes, self.retained_bytes = request_seconds, body_bytes, retained_bytes
        self.stream_messages, self.stream_count, self.retained_size = stream_messages, 0, 0
        self.sockets, self.cdp_sessions, self.active_bodies = [], [], {}
        self.operator_supplement = None
        self.session_file = session_file
        self.authority_mode = 'session' if session_file is not None else 'anonymous'
        self.working_notes = ''
        self.request_refs = {}

    def request_timeout(self):
        return max(0.001, min(self.request_seconds, self.budget.remaining()))

    def in_scope(self, url):
        part = urlsplit(url)
        scheme = {'ws': 'http', 'wss': 'https'}.get(part.scheme, part.scheme)
        return (part.username is None and part.password is None and
                authority(part._replace(scheme=scheme).geturl()) in {authority(self.origin), *self.extra_authorities})

    def network_stopped(self):
        return self.human_gate or self.model_done or self.model.stopped() or self.budget.remaining() <= 0

    async def stop_sockets(self):
        for socket in self.sockets:
            try:
                await socket.close()
            except Exception as error:
                self.error('websocket_close', error)
        self.sockets.clear()

    def snapshot(self):
        fields = ('samples', 'responses', 'attempts', 'unopened', 'decisions', 'response_bodies',
                  'form_attempts', 'realtime', 'feedback', 'buffers', 'navigations', 'login_attempted',
                  'login_sent', 'human_gate', 'model_done', 'backend', 'transport_source',
                  'context_snapshot', 'context_buffers', 'buffer_routes', 'decision_events',
                  'current_http_url', 'browse_stop_reason', 'working_notes')
        return {'fields': {key: getattr(self, key) for key in fields},
                'pages': [{'url': page.url, 'closed': page.is_closed()} for page in self.pages],
                'current_page_index': self.pages.index(self.page) if self.page in self.pages else None,
                'read_memory': self.read_memory.snapshot(), 'failures': self.failures.record(),
                'budget': self.budget.record()}

    def restore(self, saved):
        from types import SimpleNamespace
        from .resume import restore_failures
        for key, value in saved['fields'].items():
            setattr(self, key, value)
        if self.browse_stop_reason == 'browse_budget':
            self.browse_stop_reason = None
        self.retained_size = sum(len(value) if isinstance(value, bytes) else len(value.encode('utf-8'))
                                 for value in self.buffers.values())
        self.stream_count = sum(len(row['received']) for row in self.realtime)
        self.pages = [SimpleNamespace(url=row['url'], is_closed=lambda closed=row['closed']: closed)
                      for row in saved['pages']]
        index = saved['current_page_index']
        self.page = self.pages[index] if index is not None else None
        self.resume_url = self.page.url if self.page else self.current_http_url
        self.read_memory = ReadMemory(self.context_buffers, 'navigation-read')
        self.read_memory.restore(saved['read_memory'])
        restore_failures(self.failures, saved['failures'])
        for key in ('used_requests', 'used_pages', 'sent_requests'):
            setattr(self.budget, key, saved['budget'][key])
        if self.decision_events and self.decision_events[-1]['status'] == 'pending':
            self.resume_decision = self.decisions[self.decision_events[-1]['index']]

    def context(self):
        return {'origin': self.origin, 'backend': self.backend,
                'available_tools': ['open', 'read_sample', 'find', 'stop'] if self.backend == 'http_client'
                    else ['open', 'click', 'inspect_form', 'read_sample', 'find', 'select_page', 'stop'],
                'authority': {'mode': self.authority_mode, 'operator_prepared_session': self.session_file is not None,
                              'login_sent': False, 'login_submission_allowed': False,
                              'session_state': getattr(self, 'session_state', None)},
                'working_notes': self.working_notes,
                'samples': self.samples, 'responses': self.responses, 'attempts': self.attempts,
                'response_bodies': self.response_bodies, 'form_attempts': self.form_attempts,
                'realtime': self.realtime, 'unopened': self.unopened, 'feedback': self.feedback,
                'navigations': self.navigations,
                'pages': [{'index': i, 'url': page.url, 'closed': page.is_closed()} for i, page in enumerate(self.pages)],
                'budget': self.budget.record()}

    def model_context(self, correction=None, read_memory=None, extra_state=None, extra_entries=()):
        reads = self.read_memory if read_memory is None else read_memory
        data = self.context()
        self.context_buffers.update(self.buffers)
        self.context_snapshot = json.dumps(data, ensure_ascii=False)
        limit = min(self.budget.sample_chars, self.model.context_chars)
        visits = {}
        for request in self.attempts:
            if not request.get('sent') or request.get('resource_type') != 'document':
                continue
            url = request['url']
            visits[url] = visits.get(url, 0) + 1
        # URLs here are model-only; publication never receives this state.
        state = {'origin': self.origin, 'backend': self.backend,
                 'available_tools': data['available_tools'], 'authority': data['authority'],
                 'working_notes': self.working_notes,
                 'current_url': self.page.url if self.page else self.current_http_url,
                 'current_page_index': self.pages.index(self.page) if self.page in self.pages else None,
                 'visited_urls': [{'url': url, 'count': count} for url, count in visits.items()],
                 'pages': data['pages'] if self.backend != 'http_client' else
                     ([{'index': 0, 'url': self.current_http_url, 'closed': False}] if self.current_http_url else []),
                 'feedback': [feedback_state(self.feedback[-1], 'observation:latest-feedback')] if self.feedback else [],
                 'budget': data['budget'], 'budget_scope': 'browsing_only',
                 'cost_budget': self.model.cost_record(), 'axis_questions': self.axis_questions,
                 'context_ref': 'provided-context', 'total_chars': len(self.context_snapshot)}
        state.update(extra_state or {})
        state['read_windows'] = reads.state()
        index_ref = 'observation:index'
        index = self.observation_index()
        reads.buffers.update(self.context_buffers)
        reads.buffers.update(self.buffers)
        state['observation_index_ref'] = index_ref
        # The request index gets the first inline slot after state, before windows and samples.
        entries = [(index_ref, 'observation_index', index), *reads.entries(), *extra_entries]
        if self.operator_supplement is not None:
            state['copy_supplement_ref'] = 'operator:copy-supplement'
            entries.append(('operator:copy-supplement', 'copy_facts', self.operator_supplement))
        if correction is not None:
            state['correction'] = feedback_state(correction, 'observation:correction')
            entries.append(('observation:correction', 'correction', correction))
        if self.feedback:
            entries.append(('observation:latest-feedback', 'feedback', self.feedback[-1]))
        entries.extend((item.get('ref', 'sample-' + str(i + 1)), 'samples', item)
                       for i, item in reversed(list(enumerate(self.samples))))
        for kind in ('response_bodies', 'responses', 'attempts', 'form_attempts', 'realtime', 'unopened', 'feedback', 'navigations'):
            if data[kind]:
                # Resource collections get a ref each, avoiding an unbounded ref
                # manifest that crowds out page samples. Every row remains readable.
                entries.append(('observation:' + kind, kind, list(reversed(data[kind]))))
        return pack_context(state, entries, reads.buffers, limit)

    def observation_index(self, prefix=''):
        responses = {item.get('_private_request_ref'): (i, item) for i, item in enumerate(self.responses)
                     if item.get('_private_request_ref') is not None}
        rows = []
        for i, request in enumerate(self.attempts):
            key = 'observation:request:' + str(i + 1)
            response_index, response = responses.get(key, (None, {}))
            headers = response.get('headers', {}).get('value') or []
            cookies = response.get('cookies', {}).get('value') or []
            bodies = [body for body in self.response_bodies if body.get('route') == request.get('route')]
            self.context_buffers[key] = serialized({'request': request, 'response': response})
            rows.append(serialized({'method': request.get('method'), 'url': request.get('url'),
                'sent': request.get('sent'), 'status_code': response.get('status_code', {}).get('value'),
                'redirect_chain_length': len(response['redirect_chain']['value'])
                    if isinstance(response.get('redirect_chain', {}).get('value'), list) else None,
                'content_type': [header.get('value') for header in headers if header['name'].lower() == 'content-type'],
                'header_names': [header['name'] for header in headers],
                'set_cookie_names': [cookie.get('name') for cookie in cookies], 'ref': prefix + key,
                'response_collection_ref': prefix + 'observation:responses' if response_index is not None else None,
                # The collection is provided newest first, so the position is counted in that order.
                'response_index': len(self.responses) - 1 - response_index if response_index is not None else None,
                # Route equality does not establish which repeated request supplied a body.
                'route_bodies': [{'ref': prefix + body['ref'], 'retained_size': body['body'].get('retained_size'),
                                 'truncated': body['body'].get('truncated')} for body in bodies]}))
        return '\n'.join(rows)

    def readable_sources(self, read_memory=None):
        return {**self.buffers, **self.context_buffers, **(read_memory.buffers if read_memory is not None else {}),
                'provided-context': self.context_snapshot,
                **{'observation:' + kind: serialized(list(reversed(getattr(self, kind))))
                   for kind in ('response_bodies', 'responses', 'attempts', 'form_attempts', 'realtime', 'unopened', 'feedback', 'navigations')
                   if getattr(self, kind)},
                **{item['ref']: serialized(item) for item in self.samples if 'ref' in item}}

    def find(self, args, read_memory=None):
        return find_text(self.readable_sources(read_memory), args)

    def store_body(self, raw, route, kind='response'):
        original_size = len(raw)
        available = max(0, min(self.body_bytes, self.retained_bytes - self.retained_size))
        raw = raw[:available] if isinstance(raw, bytes) else raw[:available].encode('utf-8')[:available].decode('utf-8', 'ignore')
        self.retained_size += len(raw) if isinstance(raw, bytes) else len(raw.encode('utf-8'))
        key = kind + '-' + str(len(self.buffers) + 1)
        self.buffers[key] = raw
        self.buffer_routes[key] = route
        limit = min(self.budget.sample_chars, self.model.context_chars)
        if isinstance(raw, bytes):
            # Both representations share the actual serialized character budget.
            low, high = 0, min(len(raw), limit)
            while low < high:
                middle = (low + high + 1) // 2
                head = raw[:middle]
                value = {'utf8': head.decode('utf-8', 'replace'), 'base64': base64.b64encode(head).decode('ascii')}
                if len(json.dumps(value, ensure_ascii=False)) <= limit:
                    low = middle
                else:
                    high = middle - 1
            head = raw[:low]
            value = {'utf8': head.decode('utf-8', 'replace'), 'base64': base64.b64encode(head).decode('ascii')}
            size = len(raw)
            truncated = len(head) < size
        else:
            value, size, truncated = raw[:limit], len(raw), len(raw) > limit
        return {'ref': key, 'route': route, 'body': {**measured(value), 'original_size': original_size,
                'retained_size': size, 'capture_truncated': len(raw) < original_size,
                'capture_error': 'retention_limit' if len(raw) < original_size else None,
                'truncated': truncated or len(raw) < original_size, 'read_sample_available': bool(raw)}}

    def read_sample(self, args, read_memory=None):
        required(args, 'ref')
        reads = self.read_memory if read_memory is None else read_memory
        raw = self.readable_sources(reads)[args['ref']]
        return reads.read(raw, args, min(self.budget.sample_chars, self.model.context_chars))

    def browse_finished(self):
        return self.browse_stop_reason is not None

    def begin_decision(self, decision):
        if 'working_notes' in decision:
            self.working_notes = decision['working_notes']
        self.decisions.append({'source': 'model', **decision})
        # A read or find request runs instead of the named tool, so the event records what actually ran.
        tool = 'read_sample' if '_read_sample' in decision else 'find' if '_find' in decision else decision.get('tool')
        allowed = ACTION_SCHEMA['properties']['tool']['enum']
        route = None
        try:
            args = json.loads(decision['args']) if isinstance(decision.get('args'), str) else decision.get('args', {})
            current = self.page.url if self.page else self.current_http_url or self.origin
            if tool == 'open':
                route = ref(urljoin(current, args['url']))
            elif tool == 'select_page':
                route = ref(self.pages[args['index']].url)
            elif tool in ('click', 'inspect_form'):
                route = ref(current)
            elif tool == 'read_sample':
                key = args.get('ref')
                route = self.buffer_routes.get(key)
                if route is None and key in self.context_buffers:
                    value = json.loads(self.context_buffers[key])
                    route = value.get('route') if isinstance(value, dict) else None
        except (KeyError, IndexError, TypeError, ValueError):
            pass
        event = {'index': len(self.decisions) - 1, 'tool': tool if tool in allowed else 'unknown',
                 'target_route': route, 'status': 'pending', 'reason_present': bool(decision.get('reason'))}
        self.decision_events.append(event)
        return event

    async def checkpoint_decisions(self):
        if self.checkpoint is not None:
            await self.checkpoint()

    def block(self, url, reason, category='blocked'):
        self.unopened.append({'source': self.transport_source, 'route': ref(url), 'category': category,
                              'status': '못 얻음', 'reason': reason, 'timestamp': now()})

    def error(self, operation, error):
        code = getattr(error, 'code', type(error).__name__)
        detail = getattr(error, 'detail', None) or str(error)
        self.feedback.append({'operation': operation, 'status': '못 얻음', 'error': code, 'detail': detail})
        self.block(self.page.url if self.page else self.origin, code, 'item_error')
        if self.failures.add(operation, code):
            self.block(self.origin, 'same_failure_limit', 'limit')

    @staticmethod
    def report_model_error(error):
        # Raw provider/browser diagnostics may contain values. They remain in memory.
        import sys
        print('못 얻음: ' + getattr(error, 'code', type(error).__name__), file=sys.stderr)

    def spawn(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        def finished(done):
            self.tasks.discard(done)
            if not done.cancelled() and done.exception() is not None:
                self.error('observer_callback', done.exception())
        task.add_done_callback(finished)

    async def drain(self):
        if not self.tasks:
            return
        done, pending = await asyncio.wait(list(self.tasks), timeout=self.request_timeout())
        for task in pending:
            task.cancel()
        if pending:
            self.block(self.origin, 'time_budget', 'budget')
        await asyncio.gather(*done, *pending, return_exceptions=True)

    async def route(self, route, request):
        url = request.url
        descriptor = {'url': url, 'method': request.method, 'resource_type': request.resource_type,
                      'navigation': request.is_navigation_request(), 'route': ref(url),
                      'sent': False, 'timestamp': now(), 'reason': None}
        self.attempts.append(descriptor)
        self.request_refs[id(request)] = (request, 'observation:request:' + str(len(self.attempts)))
        within_budget = self.budget.take_request()
        reason = None
        if request.method not in ('GET', 'HEAD'):
            reason = '보내지 않음(메서드)'
        elif self.network_stopped():
            reason = self.model.stop_reason or 'time_or_same_failure_limit'
        elif not self.in_scope(url):
            reason = 'external_request_not_sent'
        elif not within_budget:
            reason = 'request_or_time_budget'
        if reason:
            descriptor['reason'] = reason
            self.block(url, reason)
            await route.abort()
        else:
            await route.continue_()
            descriptor['sent'] = True
            self.budget.sent_requests += 1

    async def response(self, response):
        request, url = response.request, response.url
        if request.redirected_from is not None and not self.in_scope(url):
            # The browser follows redirects without passing the route handler; record the hop that left the origin.
            self.attempts.append({'source': 'browser', 'url': url, 'method': request.method,
                                  'resource_type': request.resource_type, 'navigation': request.is_navigation_request(),
                                  'route': ref(url), 'sent': True, 'reason': '리다이렉트로 범위 밖에 보냄',
                                  'timestamp': now()})
        row = {'source': 'browser', 'timestamp': now(), 'route': ref(url),
               '_private_request_ref': self.request_refs.get(id(request), (None, None))[1],
               'status_code': isolated(lambda: response.status),
               **{key: measured(status='못 얻음', error='ObservationNotCompleted')
                  for key in ('headers', 'cookies', 'redirect_chain', 'response_time')}}
        self.responses.append(row)
        headers = await isolated_async(response.headers_array)
        row['headers'] = isolated(lambda: response_headers(headers['value'])) if headers['status'] == '관찰됨' else headers
        row['cookies'] = isolated(lambda: cookie_metadata(headers['value'])) if headers['status'] == '관찰됨' else measured(status='못 얻음', error='headers_unavailable')
        row['browser_cookies'] = await isolated_async(lambda: self.browser_cookie_metadata(url))
        row['redirect_chain'] = isolated(lambda: self.chain(request))
        row['response_time'] = isolated(lambda: self.timing(request))
        # Chromium CDP streams bodies with a capture ceiling. response.body()
        # would materialize the entire response, including unbounded streams.
        row['body_capture'] = 'cdp_bounded_stream'

    async def capture_session(self, page):
        session = await self.browser_context.new_cdp_session(page)
        self.cdp_sessions.append(session)
        await session.send('Network.enable')
        prefix = str(len(self.cdp_sessions)) + ':'

        def retain(key, encoded):
            item = self.active_bodies.get(key)
            if item is None or not encoded:
                return
            item['seen'] += len(encoded) // 4 * 3 - (len(encoded) - len(encoded.rstrip('=')))
            active_size = sum(len(row['raw']) for row in self.active_bodies.values())
            left = max(0, min(self.body_bytes - len(item['raw']), self.retained_bytes - self.retained_size - active_size))
            chunk = base64.b64decode(encoded[:((left + 2) // 3) * 4]) if left else b''
            item['raw'].extend(chunk[:left])

        async def begin(event):
            key = prefix + event['requestId']
            if self.network_stopped() or not self.in_scope(event['response']['url']):
                return
            if key in self.active_bodies:
                finish({'requestId': event['requestId'], 'force': True})
            self.active_bodies[key] = {'route': ref(event['response']['url']), 'raw': bytearray(), 'seen': 0,
                                       'started': time.monotonic(), 'buffered': False}
            try:
                data = await asyncio.wait_for(session.send('Network.streamResourceContent',
                         {'requestId': event['requestId']}), timeout=self.request_timeout())
                retain(key, data.get('bufferedData'))
                item = self.active_bodies.get(key)
                if item is not None:
                    item['buffered'] = True
                    if 'finished' in item:
                        finish(item['finished'])
            except Exception as error:
                # Streaming could not start (for example, loading already finished). Keep the item unstreamed so
                # the finished body goes through the bounded getResponseBody path, and keep why streaming failed.
                item = self.active_bodies.get(key)
                if item is not None:
                    item['buffered'] = True
                    item['stream_error'] = (type(error).__name__ + ': ' + str(error)).splitlines()[0]
                    if 'finished' in item:
                        finish(item['finished'])

        def received(event):
            key = prefix + event['requestId']
            item = self.active_bodies.get(key)
            if item is not None:
                if time.monotonic() - item['started'] >= self.request_seconds or self.network_stopped():
                    finish({'requestId': event['requestId'], 'errorText': 'capture_time_budget'})
                else:
                    retain(key, event.get('data'))

        def finish(event):
            key = prefix + event['requestId']
            item = self.active_bodies.get(key)
            if item is None:
                return
            # Loading can finish while the initial buffered body is still on its way; store once both arrived.
            if not item.get('buffered', True) and not event.get('errorText') and not event.get('force'):
                item['finished'] = event
                return
            self.active_bodies.pop(key, None)
            # Small resources can finish before streaming delivers any byte; fetch the finished body once.
            # The whole body arrives in one message, so fetch only when the transferred size fits the body limit.
            if not item['raw'] and not item['seen'] and not event.get('errorText') and not event.get('force'):
                size = event.get('encodedDataLength')
                if type(size) in (int, float) and 0 < size <= self.body_bytes:
                    self.spawn(fetch_finished(event, item))
                    return
                if type(size) in (int, float) and size > 0:
                    event = {**event, 'errorText': 'body_not_fetched_over_limit'}
            if not item.get('buffered', True) and not event.get('errorText'):
                event = {**event, 'errorText': 'initial_body_not_received'}
            store(event, item)

        async def fetch_finished(event, item):
            try:
                data = await asyncio.wait_for(session.send('Network.getResponseBody', {'requestId': event['requestId']}),
                                              timeout=self.request_timeout())
                raw = (base64.b64decode(data['body']) if data.get('base64Encoded')
                       else str(data.get('body', '')).encode('utf-8'))
                # Keep only what the limits allow, so the truncation fields describe what was kept.
                active = sum(len(row['raw']) for row in self.active_bodies.values())
                room = max(0, min(self.body_bytes, self.retained_bytes - self.retained_size - active))
                item['raw'], item['seen'], item['buffered'] = bytearray(raw[:room]), len(raw), True
                del raw, data
                item['capture'] = 'cdp_response_body_after_finish'
            except asyncio.CancelledError:
                # Browsing ended while the body was being fetched; record the gap, then let the cancel proceed.
                store({**event, 'errorText': 'body_fetch_cancelled'}, item)
                raise
            except Exception as error:
                event = {**event, 'errorText': 'body_unavailable_after_finish:' + type(error).__name__}
            store(event, item)

        def store(event, item):
            body = self.store_body(bytes(item['raw']), item['route'])
            if item.get('capture'):
                body['body']['capture'] = item['capture']
            body['body'].update(original_size=item['seen'], capture_truncated=len(item['raw']) < item['seen'],
                                truncated=body['body']['truncated'] or len(item['raw']) < item['seen'],
                                capture_error='retention_limit' if len(item['raw']) < item['seen'] else None)
            if event.get('errorText'):
                body['body'].update(truncated=True, completion_status='못 얻음', error=event['errorText'])
            if item.get('stream_error') and not item.get('capture'):
                # Streaming never started and no finished body was fetched: nothing of the body was observed.
                body['body'].update(status='못 얻음', truncated=True, completion_status='못 얻음',
                                    error='; '.join(filter(None, [event.get('errorText'),
                                                                  'stream_unavailable: ' + item['stream_error']])))
            self.response_bodies.append(body)
        session.on('Network.responseReceived', lambda event: self.spawn(begin(event)))
        session.on('Network.dataReceived', received)
        session.on('Network.loadingFinished', finish)
        session.on('Network.loadingFailed', finish)

    async def browser_cookie_metadata(self, url):
        cookies = await self.browser_context.cookies([url])
        return [{'name': cookie['name'], 'attributes': [{'name': key, 'value': value}
                 for key, value in cookie.items() if key not in ('name', 'value')]} for cookie in cookies]

    @staticmethod
    def chain(request):
        chain = []
        while request is not None:
            chain.append(ref(request.url))
            request = request.redirected_from
        return list(reversed(chain))

    @staticmethod
    def timing(request):
        timing = request.timing
        start, end = timing.get('requestStart', -1), timing.get('responseStart', -1)
        if start < 0 or end < start:
            raise ValueError('TimingUnavailable')
        return {'elapsed_ms': round(end - start, 3), 'measurement_point': 'browser_request_to_response_start'}

    async def sample(self):
        await self.drain()
        for page in self.pages:
            if page.is_closed():
                continue
            # Scripts may still be filling the page; wait a bounded time for the network to go quiet and say so.
            try:
                await page.wait_for_load_state('networkidle', timeout=RENDER_WAIT_MS)
                render_wait = 'network_idle'
            except Exception:
                render_wait = 'timeout'
            if not self.in_scope(page.url):
                # A redirect can land outside the origin; that document is not sampled or kept.
                self.block(page.url, '보지 않음(범위 밖으로 이동함)', 'navigation')
                await page.goto('about:blank')
                continue
            last = self.decisions[-1] if self.decisions else {}
            item = {'ref': 'sample-' + str(len(self.samples) + 1), 'timestamp': now(),
                    'url': page.url, 'route': ref(page.url), 'render_wait': render_wait,
                    'after_tool': ('read_sample' if '_read_sample' in last else 'find' if '_find' in last
                                   else last.get('tool'))}
            # Bound the browser-to-Python transfer too, before storing a preview.
            for key, expression in (('screen', 'document.documentElement.innerText'),
                                    ('source', 'document.documentElement.outerHTML')):
                item[key] = await isolated_async(lambda expression=expression: asyncio.wait_for(
                    page.evaluate('(limit) => { const value = ' + expression + '; return {value: value.slice(0, limit), total: value.length}; }',
                                  min(self.body_bytes, max(0, self.retained_bytes - self.retained_size))),
                    timeout=self.request_timeout()))
                if item[key]['status'] == '관찰됨':
                    captured = item[key]['value']
                    item[key]['value'] = captured['value']
                    # JS lengths count UTF-16 units; compare in the same unit so one emoji is not a truncation.
                    item[key]['original_size'] = captured['total']
                    item[key]['capture_truncated'] = utf16_units(captured['value']) < captured['total']
            if isinstance(item['screen'].get('value'), str):
                item['screen_sha256'] = ref(item['screen']['value'])
            for key in ('screen', 'source'):
                value = item[key]['value']
                if isinstance(value, str):
                    original = item[key].get('original_size', utf16_units(value))
                    sample = self.store_body(value, item['route'], key)
                    item[key].update(sample['body'])
                    if original > utf16_units(value):
                        item[key].update(original_size=original, capture_truncated=True, truncated=True, capture_error='retention_limit')
                    item[key]['ref'] = sample['ref']
            self.samples.append(item)

    async def websocket(self, socket):
        url = socket.url
        row = {'url': url, 'route': ref(url), 'connected': False, 'received': [], 'blocked_sends': 0}
        self.realtime.append(row)
        if not self.in_scope(url) or self.network_stopped() or not self.budget.take_request():
            reason = 'external_websocket_not_sent' if not self.in_scope(url) else 'websocket_budget_or_stop'
            self.attempts.append({'url': url, 'route': ref(url), 'method': 'GET', 'resource_type': 'websocket',
                                  'navigation': False, 'sent': False, 'timestamp': now(), 'reason': reason})
            self.block(url, reason, 'websocket')
            await socket.close()
            return
        server = socket.connect_to_server()
        if inspect.isawaitable(server):
            server = await server
        row['connected'] = True
        self.sockets.append(socket)
        if server is not socket:
            self.sockets.append(server)
        self.budget.sent_requests += 1
        self.attempts.append({'url': url, 'route': ref(url), 'method': 'GET', 'resource_type': 'websocket',
                              'navigation': False, 'sent': True, 'timestamp': now(), 'reason': None})
        def received(message):
            # Explicit handlers disable automatic client-to-server forwarding.
            if self.network_stopped():
                self.spawn(socket.close())
                return
            if self.stream_count < self.stream_messages and self.retained_size < self.retained_bytes:
                row['received'].append(self.store_body(message, row['route'], 'websocket'))
                self.stream_count += 1
            else:
                row['capture_limit'] = 'stream_retention_limit'
                row['omitted_messages'] = row.get('omitted_messages', 0) + 1
            socket.send(message)
        def blocked(message):
            row['blocked_sends'] += 1
            self.block(url, '보내지 않음(WebSocket 송신)', 'websocket')
        socket.on_message(blocked)
        server.on_message(received)

    def form_attempt(self, source, data):
        self.form_attempts.append({'source': 'browser', 'action': data['action'], 'method': data['method'],
                                   'field_names': data['field_names'], 'fields': data.get('fields'),
                                   'enctype': data.get('enctype'), 'sent': False, 'timestamp': now()})
        self.block(data['action'], '보내지 않음(폼)', 'form')

    async def action(self, decision):
        if '_read_sample' in decision or '_find' in decision:
            if '_read_sample' in decision:
                self.read_sample(decision['_read_sample'])
            if '_find' in decision:
                self.feedback.append({'find': self.find(decision['_find'])})
            return
        required(decision, 'tool', 'args')
        if self.failures.exhausted(self.action_key(decision)):
            raise ModelError('same_failure_limit')
        args = json.loads(decision['args']) if isinstance(decision['args'], str) else decision['args']
        if not isinstance(args, dict):
            raise ValueError('ActionArgsNotObject')
        tool = decision['tool']
        if tool == 'stop':
            self.model_done = True
            self.human_gate = decision.get('human_confirmation') is True
            await self.stop_sockets()
            return
        if decision.get('read_only') is not True or decision.get('human_confirmation') is True:
            raise ModelError('model_rejected_candidate', decision.get('reason'))
        timeout = max(1, self.request_timeout() * 1000)
        if tool == 'read_sample':
            self.feedback.append({'sample': self.read_sample(args)})
        elif tool == 'find':
            self.feedback.append({'find': self.find(args)})
        elif tool == 'select_page':
            self.page = self.pages[args['index']]
        elif tool == 'open':
            required(args, 'url')
            target = urljoin(self.page.url if self.page else self.origin, args['url'])
            if authority(target) != authority(self.origin):
                raise ModelError('external_navigation_not_sent')
            if not self.budget.take_page():
                raise ModelError('page_or_time_budget')
            await self.page.goto(target, wait_until='domcontentloaded', timeout=timeout)
        elif tool == 'click':
            required(args, 'selector')
            if not self.budget.take_page():
                raise ModelError('page_or_time_budget')
            await self.page.locator(args['selector']).click(timeout=timeout, no_wait_after=True)
            self.feedback.append({'operation': 'click', 'selector': args['selector'],
                                  'status': 'completed', 'url': self.page.url})
        elif tool == 'inspect_form':
            required(args, 'selector')
            # Inspect native metadata without dispatching submit or exposing values.
            data = await self.page.locator(args['selector']).evaluate(FORM_READ, timeout=timeout)
            self.form_attempt(None, data)
            self.feedback.append({'operation': 'inspect_form', 'status': 'completed', 'result': data})
        else:
            raise ModelError('unavailable_tool', {'available': self.context()['available_tools']})

    async def observe_page(self, page):
        self.pages.append(page)
        try:
            await self.capture_session(page)
        except Exception as error:
            self.error('body_capture_session', error)
        page.on('download', lambda download: self.spawn(self.download(download)))
        page.on('framenavigated', lambda frame: self.navigations.append(
            {'url': frame.url, 'route': ref(frame.url), 'timestamp': now(), 'top_level': frame.parent_frame is None}))
        if page != self.page:
            if not self.budget.take_page():
                self.block(page.url, 'page_or_time_budget', 'budget')
                await page.close()

    async def navigation(self):
        decision, event = None, None
        try:
            if self.resume_decision is not None:
                decision, self.resume_decision = self.resume_decision, None
                event = self.decision_events[-1]
            else:
                decision = await self.model.call('navigation', NAVIGATE, self.model_context(), ACTION_SCHEMA,
                                                 deadline=self.budget.started + self.budget.seconds,
                                                 context_builder=lambda current, feedback: self.model_context(feedback))
                event = self.begin_decision(decision)
            await self.checkpoint_decisions()
            operation = self.action_key(decision)
            await self.action(decision)
            self.failures.clear(operation)
            event['status'] = 'completed'
        except Exception as error:
            # Rejections become feedback; another candidate can still be chosen.
            operation = self.action_key(decision)
            self.error(operation, error)
            if event is not None:
                event['status'] = 'rejected' if getattr(error, 'code', None) in (
                    'model_rejected_candidate', 'external_navigation_not_sent', 'unavailable_tool') else 'failed'
        finally:
            await self.checkpoint_decisions()
        return decision.get('tool') if isinstance(decision, dict) else None

    @staticmethod
    def action_key(decision):
        if not decision:
            return 'navigation_call'
        args = decision.get('args')
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                pass
        return json.dumps({'tool': decision.get('tool'), 'args': args}, ensure_ascii=False, sort_keys=True)

    async def run(self):
        if not self.budget.started:
            self.budget.begin()
        if self.budget.exhausted() or self.model_done or self.browse_finished() or self.model.stopped():
            if (getattr(self.model, 'pending_answer', None) is not None
                    and self.model.pending_answer['purpose'] == 'navigation'):
                decision = await self.model.call('navigation', NAVIGATE, {}, ACTION_SCHEMA)
                event = self.begin_decision(decision)
                event['status'] = 'not_sent'
                if decision.get('tool') == 'stop':
                    self.model_done = True
                    self.human_gate = decision.get('human_confirmation') is True
                    event['status'] = 'completed'
                await self.checkpoint_decisions()
            return
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self.block(self.origin, 'playwright_not_installed', 'browser_unavailable')
            await self.http_run()
            return
        try:
            async with async_playwright() as playwright:
                # Optional operator relay for an origin that is only reachable inside its own network.
                relay = os.environ.get('SITE_ANALYSIS_PROXY')
                browser = await playwright.chromium.launch(headless=True, timeout=max(1, self.budget.remaining() * 1000),
                                                           **({'proxy': {'server': relay}} if relay else {}))
                try:
                    if self.session_file is not None:
                        self.session_state = session_summary(self.session_file)
                        if self.session_state['expired']:
                            # Every cookie in the prepared session has expired: browsing would silently be anonymous.
                            raise ModelError('operator_session_expired', self.session_state)
                    # SW bypasses context.route, so blocking it preserves the method boundary.
                    context = await browser.new_context(service_workers='block', accept_downloads=True,
                                **({'storage_state': str(self.session_file)} if self.session_file is not None else {}))
                    self.browser_context = context
                    await context.expose_binding('__siteAnalysisForm', self.form_attempt)
                    await context.add_init_script(FORM_GUARD)
                    await context.route('**/*', self.route)
                    await context.route_web_socket('**/*', self.websocket)
                    context.on('response', lambda response: self.spawn(self.response(response)))
                    self.pages = []
                    self.page = await context.new_page()
                    await self.observe_page(self.page)
                    context.on('page', lambda page: self.spawn(self.observe_page(page)))
                    if self.resume_url or self.budget.take_page():
                        try:
                            await self.page.goto(self.resume_url or self.origin, wait_until='domcontentloaded', timeout=max(1, self.request_timeout() * 1000))
                        except Exception as error:
                            self.error('initial_navigation', error)
                        await self.sample()
                    while not self.budget.exhausted() and not self.model.stopped() and not self.failures.stopped and not self.model_done and not self.browse_finished():
                        tool = await self.navigation()
                        if tool != 'read_sample' and not self.model_done and not self.model.stopped():
                            await self.sample()
                    await self.drain()
                finally:
                    await self.stop_sockets()
                    # Retain partial captures when a page or stream never reaches EOF.
                    for key, item in list(self.active_bodies.items()):
                        self.active_bodies.pop(key)
                        body = self.store_body(bytes(item['raw']), item['route'])
                        body['body'].update(truncated=True, completion_status='못 얻음',
                                            error='stream_closed_before_completion', original_size=item['seen'])
                        if item.get('stream_error'):
                            body['body'].update(status='못 얻음', error='stream_closed_before_completion; '
                                                'stream_unavailable: ' + item['stream_error'])
                        self.response_bodies.append(body)
                    try:
                        await browser.close()
                    except Exception as error:
                        self.error('browser_close', error)
        except Exception as error:
            self.error('browser_transport', error)
            if not self.budget.exhausted() and not self.model.stopped() and not self.failures.stopped and not self.model_done and not self.browse_finished():
                await self.http_run()

    async def http_run(self):
        if self.session_file is not None:
            self.block(self.origin, 'session_requires_playwright', 'browser_unavailable')
            return
        from http.cookiejar import CookieJar
        from urllib.request import build_opener, HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, request, file, code, message, headers, new_url):
                return None
        self.backend, self.transport_source = 'http_client', 'http_client'
        self.page = None
        relay = os.environ.get('SITE_ANALYSIS_PROXY')
        opener = build_opener(NoRedirect(), HTTPCookieProcessor(CookieJar()),
                              ProxyHandler({'http': relay, 'https': relay} if relay else {}))
        target = self.resume_url or self.origin
        fetch, pending_event = not bool(self.resume_url and self.samples), None
        while not self.budget.exhausted() and not self.model.stopped() and not self.failures.stopped and not self.model_done and (fetch or not self.browse_finished()):
            if fetch:
                if not self.budget.take_page() or not self.budget.take_request():
                    break
                self.attempts.append({'url': target, 'route': ref(target), 'method': 'GET', 'resource_type': 'document',
                                      'navigation': True, 'sent': True, 'timestamp': now(), 'reason': None})
                self.budget.sent_requests += 1
                try:
                    await asyncio.to_thread(self.http_fetch, opener, target)
                    self.failures.clear('http_fetch:' + target)
                    if pending_event is not None:
                        pending_event['status'] = 'completed'
                except Exception as error:
                    self.error('http_fetch:' + target, error)
                    if pending_event is not None:
                        pending_event['status'] = 'failed'
                pending_event = None
                await self.checkpoint_decisions()
            fetch, decision = False, None
            if self.budget.exhausted() or self.browse_finished():
                break
            event = None
            try:
                if self.resume_decision is not None:
                    decision, self.resume_decision = self.resume_decision, None
                    event = self.decision_events[-1]
                else:
                    decision = await self.model.call('navigation', NAVIGATE, self.model_context(), ACTION_SCHEMA,
                                                     deadline=self.budget.started + self.budget.seconds,
                                                     context_builder=lambda current, feedback: self.model_context(feedback))
                    event = self.begin_decision(decision)
                await self.checkpoint_decisions()
                if '_read_sample' in decision or '_find' in decision:
                    await self.action(decision)
                    event['status'] = 'completed'
                    await self.checkpoint_decisions()
                    continue
                required(decision, 'tool', 'args')
                operation = self.action_key(decision)
                if self.failures.exhausted(operation):
                    raise ModelError('same_failure_limit')
                args = json.loads(decision['args']) if isinstance(decision['args'], str) else decision['args']
                if not isinstance(args, dict):
                    raise ValueError('ActionArgsNotObject')
                if decision['tool'] == 'stop':
                    self.model_done, self.human_gate = True, decision.get('human_confirmation') is True
                elif decision.get('read_only') is not True or decision.get('human_confirmation') is True:
                    raise ModelError('model_rejected_candidate', decision.get('reason'))
                elif decision['tool'] == 'read_sample':
                    self.feedback.append({'sample': self.read_sample(args)})
                elif decision['tool'] == 'find':
                    self.feedback.append({'find': self.find(args)})
                elif decision['tool'] == 'open':
                    required(args, 'url')
                    candidate = urljoin(target, args['url'])
                    if authority(candidate) != authority(self.origin):
                        raise ModelError('external_navigation_not_sent')
                    target, fetch = candidate, True
                    pending_event = event
                else:
                    raise ModelError('unavailable_tool', {'available': ['open', 'read_sample', 'find', 'stop']})
                self.failures.clear(operation)
                event['status'] = 'pending' if fetch else 'completed'
            except Exception as error:
                operation = self.action_key(decision)
                self.error(operation, error)
                if event is not None:
                    event['status'] = 'rejected' if getattr(error, 'code', None) in (
                        'model_rejected_candidate', 'external_navigation_not_sent', 'unavailable_tool') else 'failed'
            await self.checkpoint_decisions()
        if pending_event is not None:
            pending_event['status'] = 'not_sent'
            await self.checkpoint_decisions()

    def http_fetch(self, opener, target):
        from urllib.error import HTTPError
        from urllib.request import Request
        started = time.monotonic()
        try:
            response = opener.open(Request(target, method='GET'), timeout=self.request_timeout())
        except HTTPError as error:
            response = error
        row = {'source': 'http_client', 'timestamp': now(), 'route': ref(target),
               '_private_request_ref': 'observation:request:' + str(len(self.attempts)),
               'status_code': isolated(lambda: response.code),
               'response_time': measured({'elapsed_ms': round((time.monotonic() - started) * 1000, 3),
                                         'measurement_point': 'http_request_to_response_headers'}),
               'redirect_chain': measured([ref(target)])}
        self.responses.append(row)
        self.current_http_url = target
        self.navigations.append({'url': target, 'route': ref(target), 'timestamp': now(), 'top_level': True})
        headers = isolated(lambda: [{'name': key, 'value': value} for key, value in response.headers.items()])
        row['headers'] = isolated(lambda: response_headers(headers['value'])) if headers['status'] == '관찰됨' else headers
        row['cookies'] = isolated(lambda: cookie_metadata(headers['value'])) if headers['status'] == '관찰됨' else measured(status='못 얻음', error='headers_unavailable')
        try:
            deadline = min(started + self.request_seconds, self.budget.started + self.budget.seconds)
            raw = bytearray()
            available = max(0, min(self.body_bytes, self.retained_bytes - self.retained_size))
            ended = False
            while time.monotonic() < deadline and len(raw) < available:
                stream = getattr(response, 'fp', None)
                stream = getattr(stream, 'fp', stream)
                sock = getattr(getattr(stream, 'raw', None), '_sock', None)
                if sock is not None:
                    sock.settimeout(max(0.001, deadline - time.monotonic()))
                chunk = response.read1(min(65536, available - len(raw)))
                if not chunk:
                    ended = True
                    break
                raw.extend(chunk)
            body = self.store_body(bytes(raw), ref(target))
            if not ended:
                body['body'].update(truncated=True, capture_truncated=True, completion_status='못 얻음',
                                     error='retention_limit' if len(raw) >= available else 'request_time_budget')
        except Exception as error:
            body = self.store_body(bytes(raw), ref(target))
            body['body'].update(truncated=True, completion_status='못 얻음', error=type(error).__name__)
            self.feedback.append({'operation': 'http_body', 'status': '못 얻음', 'detail': str(error)})
        finally:
            try:
                response.close()
            except Exception as error:
                self.error('http_response_close', error)
        self.response_bodies.append(body)
        self.samples.append({'ref': 'sample-' + str(len(self.samples) + 1), 'timestamp': now(), 'url': target,
                             'route': ref(target), 'screen': measured(status='못 얻음', error='BrowserUnavailable'),
                             'source': {**measured(body['body']['value']['utf8']), 'ref': body['ref'],
                                        'original_size': body['body']['original_size'],
                                        'retained_size': body['body']['retained_size'],
                                        'capture_truncated': body['body']['capture_truncated'],
                                        'truncated': body['body']['truncated'],
                                        'completion_status': body['body'].get('completion_status', '관찰됨')}})
        for key in ('status_code', 'response_time', 'redirect_chain', 'headers', 'cookies'):
            row[key]['source'] = 'http_client'

    async def download(self, download):
        # Playwright's private temporary file is deleted with the context.
        try:
            path = await asyncio.wait_for(download.path(), timeout=self.request_timeout())
            if path is None:
                raise ModelError('DownloadUnavailable')
            from pathlib import Path
            def read():
                with Path(path).open('rb') as stream:
                    return stream.read(max(0, min(self.body_bytes, self.retained_bytes - self.retained_size)))
            raw = await asyncio.to_thread(read)
            body = self.store_body(raw, ref(download.url), 'download')
            size = Path(path).stat().st_size
            body['body'].update(original_size=size, capture_truncated=len(raw) < size,
                                truncated=body['body']['truncated'] or len(raw) < size)
            self.response_bodies.append(body)
        except Exception as error:
            self.block(download.url, getattr(error, 'code', type(error).__name__), 'download')
            self.feedback.append({'operation': 'download', 'status': '못 얻음', 'detail': str(error)})

    def publication(self):
        def hosts(sent):
            values = {urlsplit(item['url']).hostname for item in self.attempts if not sent or item['sent']}
            return sorted(host for host in values if host and host != urlsplit(self.origin).hostname)
        return public_facts({'backend': self.backend, 'source': self.transport_source,
                'capture': measured({'body_bytes': self.body_bytes, 'retained_bytes': self.retained_bytes,
                    'retained_size': self.retained_size, 'stream_messages': self.stream_messages,
                    'truncated_bodies': sum(bool(row['body'].get('capture_truncated') or row['body'].get('truncated'))
                                             for row in self.response_bodies),
                    'unavailable_bodies': sum(row['body']['status'] != '관찰됨' for row in self.response_bodies)}),
                'response_observation': measured(len(self.responses)) if self.responses else measured(status='못 얻음', error='NoResponseObtained'),
                'human_gate': {'source': 'model', 'stop_requested': self.human_gate},
                'responses': self.responses, 'unopened': self.unopened,
                'navigations': self.navigations,
                'screens': [{'ref': item['ref'], 'timestamp': item['timestamp'], 'url': item['url'], 'route': item['route'],
                             'render_wait': item.get('render_wait'), 'after_tool': item.get('after_tool'),
                             'screen_sha256': item.get('screen_sha256'),
                             'screen_status': item['screen']['status'], 'source_status': item['source']['status']}
                            for item in self.samples],
                'sent_external_hosts': measured(hosts(True)), 'attempted_external_hosts': measured(hosts(False)),
                'form_attempts': [{**item, 'route': ref(item['action'])} for item in self.form_attempts],
                'requests': self.attempts,
                'websockets': [{'url': row['url'], 'route': row['route'], 'connected': row['connected'],
                                'received_count': len(row['received']), 'blocked_sends': row['blocked_sends'],
                                'omitted_messages': row.get('omitted_messages', 0)}
                               for row in self.realtime],
                'budget': self.budget.record(), 'same_failures': self.failures.record()})
