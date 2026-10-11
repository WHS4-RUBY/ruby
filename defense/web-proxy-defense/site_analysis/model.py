"""Tool-free Codex CLI adapter with a private cost ledger and answer receipts."""
import asyncio
import base64
from decimal import Decimal
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from .record import Failures, ref

# Windows status codes raised while a process is still loading: STATUS_DLL_INIT_FAILED, STATUS_DLL_NOT_FOUND.
PROCESS_START_FAILURES = {0xC0000142, 0xC0000135}


class ModelError(RuntimeError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code, self.detail = code, detail


def protect(value, secrets):
    if isinstance(value, str):
        from urllib.parse import quote, quote_plus
        variants = set()
        for secret in secrets:
            if secret:
                raw = secret.encode('utf-8')
                variants.update((secret, quote(secret, safe=''), quote_plus(secret),
                                 base64.b64encode(raw).decode('ascii'), base64.urlsafe_b64encode(raw).decode('ascii'),
                                 json.dumps(secret, ensure_ascii=True)[1:-1]))
        for secret in sorted(variants, key=len, reverse=True):
            if secret:
                value = value.replace(secret, '<operator-credential-withheld>')
        return value
    if isinstance(value, list):
        return [protect(item, secrets) for item in value]
    if isinstance(value, dict):
        return {protect(key, secrets): protect(item, secrets) for key, item in value.items()}
    return value


def number(value):
    result = Decimal(str(value))
    if not result.is_finite() or result < 0:
        raise ValueError('비용 숫자는 유한한 비음수여야 함')
    return result


def cost_settings(path, model, ceiling):
    if path is None:
        raise ValueError('--rates에 운영자 단가 파일을 지정해야 함')
    settings = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    settings = settings.get('budget', settings)
    rates = settings.get('model_prices', settings)
    ceiling = ceiling if ceiling is not None else settings.get('max_cost_usd')
    if ceiling is None:
        raise ValueError('--max-cost-usd 또는 단가 파일의 비용 상한이 필요함')
    rate = rates.get(model)
    if not isinstance(rate, dict) or not isinstance(rate.get('base'), dict):
        raise ValueError('선택 모델의 운영자 단가가 필요함')
    for tier in ('base', 'long'):
        if tier in rate:
            for key in ('input', 'cached_input', 'output'):
                number(rate[tier][key])
    if 'long_input_threshold_tokens' in rate:
        rate['long_input_threshold_tokens'] = number(rate['long_input_threshold_tokens'])
        if 'long' not in rate:
            raise ValueError('장문 임계값에 대응하는 long 단가가 필요함')
    return rate, number(ceiling)


def price(rate, usage):
    tier = 'long' if usage['input_tokens'] > rate.get('long_input_threshold_tokens', float('inf')) else 'base'
    prices = rate[tier]
    cached = min(usage.get('cached_input_tokens', 0), usage['input_tokens'])
    return (number(usage['input_tokens'] - cached + usage.get('cache_write_input_tokens', 0)) * number(prices['input'])
            + number(cached) * number(prices['cached_input'])
            + number(usage['output_tokens'] + usage.get('reasoning_output_tokens', 0)) * number(prices['output'])) / 1000000


def decode_answer(messages):
    decoder = json.JSONDecoder()
    for message in reversed(messages):
        try:
            value = json.loads(message)
            if isinstance(value, dict):
                return value
        except ValueError:
            pass
        # Decode a JSON object inside prose/fences without judging its content.
        for index, char in enumerate(message):
            if char == '{':
                try:
                    value, _ = decoder.raw_decode(message[index:])
                    if isinstance(value, dict):
                        return value
                except ValueError:
                    pass
    raise ModelError('codex_answer_format', {'messages': messages})


def claude_receipt(raw):
    envelope = json.loads(raw)
    if not isinstance(envelope, dict):
        raise ModelError('claude_envelope_format')
    if envelope.get('total_cost_usd') is None:
        raise ModelError('cost_usage_unknown')
    return envelope, number(envelope['total_cost_usd'])


class Codex:
    def __init__(self, model, timeout, directory, secrets=(), rate=None, ceiling=None,
                 failure_limit=8, context_chars=600000, output_bytes=4000000, provider='codex', reasoning_effort='high'):
        self.model, self.timeout, self.directory = model, timeout, Path(directory)
        self.secrets, self.rate, self.ceiling = secrets, rate, ceiling
        self.spent, self.usage_unknown = Decimal(0), False
        self.calls, self.lock = [], asyncio.Lock()
        self.failures = Failures(failure_limit)
        # send_chars is the fixed envelope limit; context_chars is the packing window.
        self.context_chars = self.send_chars = context_chars
        self.browse_spent = Decimal(0)
        self.analysis_spent = Decimal(0)
        self.privacy_spent, self.merge_spent = Decimal(0), Decimal(0)
        self.output_bytes = output_bytes
        self.provider = provider
        self.reasoning_effort = reasoning_effort
        self.call_ceiling = None
        self.stop_reason = None
        self.checkpoint = None
        self.pending_answer = None
        self.receipt_delivered = False
        self.remaining_stages = lambda: []

    def persist(self):
        if self.checkpoint is not None:
            self.checkpoint(self)

    def resume_record(self):
        return {**self.cost_record(), 'calls': self.calls, 'usage_unknown': self.usage_unknown,
                'failures': self.failures.record(), 'pending_answer': self.pending_answer}

    def restore(self, saved, acknowledged=0, ceiling_override=None):
        from .resume import restore_failures
        self.spent = number(saved['spent_usd'])
        self.browse_spent = number(saved['browse_spent_usd'])
        self.analysis_spent = number(saved['analysis_spent_usd'])
        self.ceiling = number(saved['max_cost_usd']) if ceiling_override is None else ceiling_override
        # Old allocation fields are ignored; paid costs never reset.
        self.privacy_spent = number(saved.get('privacy_spent_usd', sum(
            (number(row['usd']) for row in saved['calls'] if row.get('usd') is not None
             and row['purpose'] == 'publication_privacy'), Decimal(0))))
        self.merge_spent = number(saved.get('merge_spent_usd', sum(
            (number(row['usd']) for row in saved['calls'] if row.get('usd') is not None
             and row['purpose'].startswith('merge_')), Decimal(0))))
        self.calls = saved['calls']
        self.usage_unknown = saved['usage_unknown']
        restore_failures(self.failures, saved['failures'])
        receipt = saved.get('pending_answer')
        self.pending_answer = receipt if receipt and receipt['call_index'] > acknowledged else None
        self.receipt_delivered = False
        # A hard process exit cannot run _call.finally. Retain the existing
        # timeout estimate for every durably recorded unfinished provider call.
        for row in self.calls:
            if row.get('inflight') and row['usd'] is None:
                cost = price(self.rate, row['estimate_usage'])
                self.spent += cost
                self.charge_stage(row['purpose'], cost)
                row.update(usd=str(cost), usd_estimated=True, total_usd=str(self.spent),
                           error='interrupted_provider_call', inflight=False)

    @staticmethod
    def stage(purpose):
        return ('browse' if purpose == 'navigation' else 'analysis' if purpose.startswith('group_')
                else 'privacy' if purpose == 'publication_privacy' else 'merge')

    def charge_stage(self, purpose, cost):
        attribute = self.stage(purpose) + '_spent'
        setattr(self, attribute, getattr(self, attribute) + cost)

    def cost_record(self):
        stages = ('browse', 'analysis', 'privacy', 'merge')
        recent = {stage: [number(row['usd']) for row in self.calls
                         if row.get('usd') is not None and self.stage(row['purpose']) == stage][-10:]
                  for stage in stages}
        return {'spent_usd': str(self.spent), 'max_cost_usd': str(self.ceiling),
                'privacy_spent_usd': str(self.privacy_spent), 'merge_spent_usd': str(self.merge_spent),
                'spent_by_stage_usd': {stage: str(getattr(self, stage + '_spent')) for stage in stages},
                'remaining_stages': self.remaining_stages(),
                'recent_average_call_usd_by_stage': {
                    stage: {'usd': str(sum(costs, Decimal(0)) / len(costs)) if costs else None,
                            'call_count': len(costs), 'includes_estimates': any(
                                row.get('usd_estimated', False) for row in [row for row in self.calls
                                if row.get('usd') is not None and self.stage(row['purpose']) == stage][-10:])}
                    for stage, costs in recent.items()},
                'provider_hard_cost_limit': False,
                'estimate_note': 'The executor stops at the total ceiling; missing-usage charges are estimates. A call may exceed the remaining amount.',
                'remaining_usd': str(max(Decimal(0), self.ceiling - self.spent)) if self.ceiling is not None else None,
                'browse_spent_usd': str(self.browse_spent), 'analysis_spent_usd': str(self.analysis_spent)}

    def stopped(self):
        if self.usage_unknown:
            self.stop_reason = 'cost_usage_unknown'
        elif getattr(self, 'start_failures', 0) >= 8:
            self.stop_reason = 'provider_start_failed'
        elif self.ceiling is not None and self.spent >= self.ceiling:
            self.stop_reason = 'cost_budget'
        elif self.failures.stopped:
            self.stop_reason = 'same_failure_limit'
        return self.stop_reason is not None

    async def call(self, purpose, prompt, context, schema, deadline=None, retry=True,
                   context_builder=None):
        if self.pending_answer is not None and not self.receipt_delivered:
            if self.pending_answer['purpose'] != purpose:
                raise ModelError('unconsumed_saved_answer')
            answer = self.pending_answer['answer']
            self.receipt_delivered = True
            return answer
        operation_context = {key: value for key, value in context.items() if key != 'cost_budget'}
        operation = purpose + ':' + ref(json.dumps(operation_context, ensure_ascii=False, default=str))
        if self.failures.exhausted(operation):
            raise ModelError('same_failure_limit')
        feedback = None
        while True:
            async with self.lock:
                if self.stopped():
                    raise ModelError(self.stop_reason)
                remaining = self.timeout if deadline is None else deadline - time.monotonic()
                if self.timeout is not None:
                    remaining = self.timeout if remaining is None else min(self.timeout, remaining)
                if remaining is not None and remaining <= 0:
                    raise ModelError('time_budget')
                try:
                    # Budget refresh and correction envelopes can grow a full window.
                    # Callers repack retained sources after every update.
                    data = (context_builder(context, feedback) if context_builder is not None else
                            context if feedback is None else {'input': {key: value for key, value in context.items()
                                                                       if key != 'cost_budget'}, 'correction': feedback})
                    # Every attempt, including format retries, receives the same information.
                    # Corrections are windowed too; never send an oversized envelope.
                    from .windows import serialized
                    # Freeze the envelope: live observer objects can change while the call runs in a thread.
                    data = json.loads(serialized({**data, 'cost_budget': self.cost_record()}))
                    size = len(serialized(protect(data, self.secrets)))
                    if size > self.send_chars:
                        # Withheld-credential markers and the refreshed budget can grow a packed
                        # window. Callers pack to context_chars, so shrink it and repack.
                        if context_builder is not None and self.context_chars > 1024:
                            self.context_chars = max(1024, min(self.context_chars - 256,
                                                               self.context_chars * self.send_chars // size - 256))
                            continue
                        raise ModelError('context_budget', feedback)
                    self.call_ceiling = max(Decimal(0), self.ceiling - self.spent) if self.ceiling is not None else None
                    answer = await asyncio.to_thread(self._call, purpose, prompt, data, schema, remaining)
                    self.receipt_delivered = True
                    self.failures.clear(operation)
                    return answer
                except ModelError as error:
                    if error.code in ('cost_budget', 'time_budget', 'context_budget'):
                        raise
                    if not retry or self.stopped() or self.failures.add(operation, error.code):
                        raise
                    # Raw diagnostics return to the model; never print them.
                    feedback = {'error': error.code, 'detail': error.detail,
                                'instruction': 'Return a JSON object in the requested format; preserve usable partial answers.'}
                finally:
                    self.persist()

    def payload(self, prompt, context, schema):
        observations = protect(context, self.secrets)
        if len(json.dumps(observations, ensure_ascii=False)) > self.send_chars:
            raise ModelError('context_budget')
        return json.dumps({'instructions': prompt, 'response_format': schema, 'observations': observations,
                           'remaining_usd': str(self.ceiling - self.spent) if self.ceiling is not None else None},
                          ensure_ascii=False).encode('utf-8')

    @staticmethod
    def estimate(payload):
        # UTF-8 bytes cover the full envelope and schema. Output/reasoning are
        # still estimates: the CLI does not expose a hard billing ceiling.
        return {'input_tokens': len(payload), 'output_tokens': 16000}

    def _call(self, purpose, prompt, context, schema, timeout):
        started = time.monotonic()
        row = {'purpose': purpose, 'model': self.model, 'source': self.provider + '_cli',
               'status': '못 얻음', 'usage': None, 'usd': None}
        row['cost_budget'] = context['cost_budget']
        self.calls.append(row)
        invoked = False
        try:
            executable = shutil.which(self.provider + '.cmd' if os.name == 'nt' else self.provider)
            if self.provider == 'claude' and not executable:
                executable = shutil.which('claude')
            if not executable:
                raise ModelError(self.provider + '_not_found')
            self.directory.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=self.directory, prefix='call-') as directory:
                # Schema is advisory: provider strict-output mode rejects useful extra fields.
                argv = [executable, 'exec', '-m', self.model, '--ephemeral', '--ignore-user-config',
                        '--ignore-rules', '--sandbox', 'read-only', '-c', 'web_search="disabled"',
                        '-c', 'model_reasoning_effort=' + json.dumps(self.reasoning_effort),
                        '-c', 'mcp_servers={}', '--disable', 'shell_tool', '--disable', 'unified_exec',
                        '--disable', 'browser_use', '--disable', 'computer_use',
                        '--json', '--skip-git-repo-check', '-C', directory, '-']
                if self.provider == 'claude':
                    argv = [executable, '-p', '--model', self.model, '--tools', '',
                            '--disable-slash-commands', '--no-session-persistence', '--strict-mcp-config',
                            '--mcp-config', '{"mcpServers":{}}', '--no-chrome', '--permission-mode', 'dontAsk',
                            '--setting-sources', '', '--output-format', 'json',
                            '--max-budget-usd', str(self.call_ceiling)]
                observations = protect(context, self.secrets)
                raw_context = json.dumps(observations, ensure_ascii=False)
                row['input_context_chars'] = len(raw_context)
                # Callers window retained observations. Never hide state, corrections,
                # or an indivisible privacy cell behind another prefix-only cut.
                row['context_window_exceeded'] = len(raw_context) > self.send_chars
                payload = self.payload(prompt, context, schema)
                try:
                    invoked = True
                    row['inflight'] = True
                    row['estimate_usage'] = self.estimate(payload)
                    row['reserved_usd'] = str(price(self.rate, row['estimate_usage']))
                    self.persist()
                    # Spool provider streams to disk, not capture_output in RAM.
                    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                        result = subprocess.run(argv, input=payload, stdout=stdout, stderr=stderr, timeout=timeout,
                                                cwd=directory, check=False)
                        row['output_bytes'] = stdout.tell()
                        stdout.seek(0)
                        result.stdout = stdout.read(self.output_bytes)
                        # Keep a short provider diagnostic in the private ledger when nothing came back.
                        if not row['output_bytes'] or result.returncode:
                            stderr.seek(0)
                            row['provider_stderr'] = stderr.read(600).decode('utf-8', 'replace')
                            row['returncode'] = result.returncode
                        if row['output_bytes'] > self.output_bytes:
                            raise ModelError('provider_output_limit')
                except subprocess.TimeoutExpired as error:
                    raise ModelError('codex_timeout', {'partial_output': (error.stdout or b'').decode('utf-8', 'replace')}) from None
                except OSError as error:
                    invoked = False
                    raise ModelError('codex_start_failed', str(error)) from None
            if self.provider == 'claude':
                envelope, cost = claude_receipt(result.stdout)
                row['actual_model_ids'] = list(envelope.get('modelUsage', {}))
                row['usage'] = envelope.get('usage')
                self.spent += cost
                self.charge_stage(purpose, cost)
                row.update(usd=str(cost), total_usd=str(self.spent), returncode=result.returncode,
                           partial_provider_failure=bool(result.returncode or envelope.get('is_error')))
                answer = envelope.get('structured_output')
                if not isinstance(answer, dict):
                    answer = decode_answer([envelope.get('result', '')])
                row['status'] = '관찰됨'
                self.pending_answer = {'call_index': len(self.calls), 'purpose': purpose, 'answer': answer}
                self.receipt_delivered = False
                return answer
            messages, failures, malformed = [], [], 0
            usages = []
            for line in result.stdout.splitlines():
                try:
                    event = json.loads(line)
                except (ValueError, UnicodeError):
                    malformed += 1
                    continue
                if not isinstance(event, dict):
                    malformed += 1
                    continue
                if event.get('type') == 'turn.failed':
                    failures.append(event.get('error'))
                if event.get('type') == 'turn.completed' and isinstance(event.get('usage'), dict):
                    usages.append(event['usage'])
                if event.get('type') == 'item.completed':
                    item = event.get('item', {})
                    if isinstance(item, dict) and item.get('type') == 'agent_message' and isinstance(item.get('text'), str):
                        messages.append(item['text'])
            keys = ('input_tokens', 'cached_input_tokens', 'output_tokens', 'cache_write_input_tokens', 'reasoning_output_tokens')
            if not usages or any(any(type(u.get(k)) is not int or u[k] < 0 for k in ('input_tokens', 'output_tokens'))
                                 or any(k in u and (type(u[k]) is not int or u[k] < 0) for k in keys) for u in usages):
                raise ModelError('cost_usage_unknown', {'failures': failures, 'messages': messages})
            row['usage'] = {key: sum(u.get(key, 0) for u in usages) for key in keys}
            cost = sum((price(self.rate, usage) for usage in usages), Decimal(0))
            self.spent += cost
            self.charge_stage(purpose, cost)
            row.update(usd=str(cost), total_usd=str(self.spent), malformed_events=malformed,
                       returncode=result.returncode, partial_provider_failure=bool(failures or result.returncode))
            # Preserve a usable partial answer together with a numeric failure marker.
            answer = decode_answer(messages)
            row['status'] = '관찰됨'
            self.start_failures = 0
            self.pending_answer = {'call_index': len(self.calls), 'purpose': purpose, 'answer': answer}
            self.receipt_delivered = False
            return answer
        except ModelError as error:
            row['error'] = error.code
            raise
        finally:
            if (invoked and row['usd'] is None and row.get('output_bytes') == 0
                    and row.get('returncode') in PROCESS_START_FAILURES):
                # The process failed while loading (DLL initialization or missing DLL) and printed nothing, so it
                # never reached the provider. Other status codes, such as access violations, can occur mid-run and
                # keep the estimated charge below.
                row.update(usd='0', usd_estimated=False, total_usd=str(self.spent), error='provider_start_failed')
                self.start_failures = getattr(self, 'start_failures', 0) + 1
            elif invoked and row['usd'] is None and not self.rate:
                self.usage_unknown = True
            elif invoked and row['usd'] is None:
                # Preserve timeout charging, explicitly marked as an estimate.
                estimate = row['estimate_usage']
                cost = price(self.rate, estimate)
                self.spent += cost
                self.charge_stage(purpose, cost)
                row.update(usd=str(cost), usd_estimated=True, total_usd=str(self.spent), usage_finalized=False)
            row['elapsed_seconds'] = round(time.monotonic() - started, 3)
            row['inflight'] = False
            self.persist()
