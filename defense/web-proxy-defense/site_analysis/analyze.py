"""python -B -m site_analysis.analyze --origin-url URL --out private/analysis.json"""
import argparse
import asyncio
from copy import deepcopy
import json
import math
import os
from pathlib import Path
import sys
import time

from .catalog import (ACTION_SCHEMA, MERGE_ANSWER, PRIVACY_SCHEMA, check_answer,
                      check_answers, group_schema, load_catalog, obj, required, unavailable)
from .model import Codex, ModelError, cost_settings, number, protect
from .observer import Budget, Observer, authority
from .prompts import MERGE, PRIVACY, group_prompt
from .record import (Failures, empty_axes, merge, merge_by_authority, runs_by_authority,
                     json_safe, now, private_path, ref, write_json)
from .resume import CheckpointError, ResumeStore, restored_copy
from .session_prepare import session_path
from .windows import (ReadMemory, feedback_state, find_text, pack_context, replace_leaves, unknown_ref,
                      sample_window, serialized)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--origin-url', required=True)
    result.add_argument('--out', required=True, type=Path)
    result.add_argument('--runs', type=int, default=2)
    result.add_argument('--session-file', type=Path, help='Operator-prepared private Playwright storage state')
    result.add_argument('--session-runs', type=int, default=0)
    result.add_argument('--budget', default='{}', help='JSON per run: requests, pages, seconds, sample_chars')
    result.add_argument('--max-requests', type=int)
    result.add_argument('--max-pages', type=int)
    result.add_argument('--max-seconds', type=float)
    result.add_argument('--sample-chars', type=int)
    result.add_argument('--context-chars', type=int, default=600000, help='Mechanical input window size, configurable for the selected model')
    result.add_argument('--same-failure-limit', type=int, default=8)
    result.add_argument('--rates', type=Path, help='Same price JSON format as decoy_build: budget.model_prices, model_prices or a model mapping')
    result.add_argument('--max-cost-usd', help='Total across navigation, analysis, correction, privacy and merge calls')
    result.add_argument('--model', default='gpt-6-sol')
    result.add_argument('--provider', choices=('codex', 'claude'), default='codex')
    result.add_argument('--reasoning-effort', default='high')
    result.add_argument('--model-timeout', type=float, help='Optional per-call timeout; defaults to the remaining shared time budget')
    result.add_argument('--privacy-seconds', type=float, help='Separate privacy time budget per run; defaults to --max-seconds')
    result.add_argument('--merge-seconds', type=float, help='Separate semantic merge time budget; defaults to --max-seconds')
    result.add_argument('--browse-seconds', type=float, help='Browsing time per run/resume; defaults to --max-seconds')
    result.add_argument('--analysis-seconds', type=float, help='Analysis time per run/resume; defaults to --max-seconds')
    result.add_argument('--request-seconds', type=float, default=30, help='Individual network/body wait ceiling')
    result.add_argument('--body-bytes', type=int, default=2000000)
    result.add_argument('--retained-bytes', type=int, default=32000000)
    result.add_argument('--stream-messages', type=int, default=1000)
    result.add_argument('--model-output-bytes', type=int, default=4000000)
    result.add_argument('--checkpoint-root', type=Path, help='Private absolute directory outside repositories')
    result.add_argument('--copy-supplement', type=Path, help='Operator-supplied copy deployment JSON; no Docker commands')
    result.add_argument('--reset-failures', action='store_true', help='Keep paid work and costs, reset retry counters for this invocation')
    result.add_argument('--fresh', action='store_true', help='Archive saved stages and start a new cost ledger')
    result.add_argument('--login-env', help='Credential environment name for removal handoff; form login remains prohibited')
    result.add_argument('--dry-run', action='store_true', help='No network, model, credential-value reads or output files')
    return result


def validate(args):
    from urllib.parse import urlsplit
    part = urlsplit(args.origin_url)
    if part.scheme not in ('http', 'https') or not part.hostname or part.username is not None or part.password is not None:
        raise ValueError('http/https 주소가 필요함, URL 자격은 허용하지 않음')
    authority(args.origin_url)
    if type(args.session_runs) is not int or args.session_runs < 0:
        raise ValueError('세션 회차는 0 이상 정수여야 함')
    if args.session_runs and args.session_file is None:
        raise ValueError('세션 회차에는 --session-file이 필요함')
    if args.session_file is not None:
        args.session_file = session_path(args.session_file)
        if not args.dry_run and not args.session_file.is_file():
            raise ValueError('세션 파일이 없음')
    args.origin_url = part._replace(path=part.path or '/').geturl()
    budget = json.loads(args.budget)
    if not isinstance(budget, dict) or set(budget) - {'requests', 'pages', 'seconds', 'sample_chars'}:
        raise ValueError('등록되지 않은 예산 키')
    limits = {'requests': 3000, 'pages': 60, 'seconds': 1800, 'sample_chars': 600000}
    limits.update(budget)
    for key, value in (('requests', args.max_requests), ('pages', args.max_pages),
                       ('seconds', args.max_seconds), ('sample_chars', args.sample_chars)):
        if value is not None:
            limits[key] = value
    for value in (limits['requests'], limits['pages'], limits['sample_chars'], args.runs, args.context_chars,
                  args.same_failure_limit, args.body_bytes, args.retained_bytes, args.stream_messages, args.model_output_bytes):
        if type(value) is not int or value < 1:
            raise ValueError('횟수와 맥락 상한은 1 이상 정수여야 함')
    for value in (limits['seconds'], args.model_timeout, args.privacy_seconds, args.merge_seconds,
                  args.browse_seconds, args.analysis_seconds, args.request_seconds):
        if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or value <= 0):
            raise ValueError('시간 예산은 양의 유한 숫자여야 함')
    if args.context_chars < 1024:
        raise ValueError('읽기 참조와 메타데이터를 담는 맥락 창은 1024자 이상이어야 함')
    return private_path(args.out), limits


def run_specs(args):
    return [(index, 'anonymous' if index <= args.runs else 'session')
            for index in range(1, args.runs + args.session_runs + 1)]


def check_schema(schema):
    if not isinstance(schema, dict):
        raise ValueError('스키마 자료형 오류')
    if schema.get('type') == 'object':
        if not isinstance(schema.get('properties'), dict) or not set(schema.get('required', [])).issubset(schema['properties']):
            raise ValueError('객체 스키마의 키 오류')
        for child in schema['properties'].values():
            check_schema(child)
    if schema.get('type') == 'array':
        check_schema(schema['items'])


def credentials(name):
    if not name:
        return {}
    value = os.environ.get(name)
    if value is None:
        raise ValueError('로그인 환경변수 없음')
    try:
        result = json.loads(value)
    except ValueError:
        raise ValueError('로그인 환경변수는 JSON 객체여야 함') from None
    if not isinstance(result, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in result.items()):
        raise ValueError('자격 키와 값은 문자열이어야 함')
    return result


def candidates(facts):
    table = []
    def visit(value, path):
        if isinstance(value, str):
            table.append({'id': 'fact-' + str(len(table) + 1), 'path': path, 'value': value})
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path + [index])
        elif isinstance(value, dict):
            for key, child in value.items():
                visit(child, path + [key])
    for index, response in enumerate(facts['responses']):
        for key in ('headers', 'cookies', 'browser_cookies'):
            visit(response.get(key, {}).get('value'), ['responses', index, key, 'value'])
    for key in ('sent_external_hosts', 'attempted_external_hosts'):
        visit(facts[key]['value'], [key, 'value'])
    for key in ('screens', 'requests', 'websockets', 'navigations'):
        for index, item in enumerate(facts[key]):
            visit(item['url'], [key, index, 'url'])
    for index, item in enumerate(facts['form_attempts']):
        for key in ('action', 'method', 'field_names'):
            visit(item[key], ['form_attempts', index, key])
    return table


def redact(facts, table, decisions):
    result, withheld = deepcopy(facts), []
    for item in table:
        target = result
        for key in item['path'][:-1]:
            target = target[key]
        decision = decisions.get(item['id'])
        target[item['path'][-1]] = decision if isinstance(decision, str) else None
        if decision is None:
            withheld.append(item['id'])
    return result, withheld


def remaining_work(args, catalog, state, active_index=None, active_observer=None):
    """Report unfinished work and known cell counts without allocating money."""
    result = []
    for index, mode in run_specs(args):
        run = state['runs'].get(str(index), {})
        if run.get('complete'):
            continue
        observing = not run.get('observation_complete')
        if observing:
            result.append({'run': index, 'authority': mode, 'stage': 'browse'})
        pending = [group for group in catalog['call_order']
                   if not run.get('groups', {}).get(group, {}).get('complete')]
        if pending:
            result.append({'run': index, 'stage': 'analysis', 'group_count': len(pending), 'groups': pending})
        privacy = run.get('privacy', {})
        def pending_count(scope, ids):
            saved = privacy.get(scope, {})
            return sum(key not in saved.get('released', {}) and key not in saved.get('terminal', []) for key in ids)
        axis_count = sum(pending_count('axis:' + group, ['axis-' + key for key in
                         group_schema(catalog, group)['properties'] if key not in
                         run.get('groups', {}).get(group, {}).get('terminal_axes', [])])
                         for group in catalog['call_order'])
        observed = active_observer if index == active_index else None
        if observed is None and run.get('observation'):
            observed = Observer(args.origin_url, None, Budget())
            # Publication needs only retained fields; no browser or network starts.
            for key, value in run['observation']['fields'].items():
                setattr(observed, key, value)
        facts = candidates(observed.publication()) if observed else []
        fact_count = pending_count('facts', [cell['id'] for cell in facts])
        decision_count = pending_count('decisions', ['decision-' + str(i) for i in
                                      range(len(observed.decisions) if observed else 0)])
        notes_count = pending_count('working_notes', ['working-notes'])
        if axis_count or fact_count or decision_count or notes_count or observing:
            result.append({'run': index, 'stage': 'privacy', 'axis_cells': axis_count,
                           'fact_cells': fact_count, 'decision_cells': decision_count, 'working_notes_cells': notes_count,
                           'counts_may_grow_during_browse': observing})
    for mode, count in (('anonymous', args.runs), ('session', args.session_runs)):
        merged = state.get('merge_by_authority', {}).get(mode, state['merge'] if mode == 'anonymous' else {})
        if count > 1 and not merged.get('complete'):
            pending = [axis['id'] for axis in catalog['axes'] if axis['id'] not in merged.get('judgments', {})]
            result.append({'stage': 'merge', 'authority': mode, 'axis_count': len(pending), 'includes_publication_review': True})
    if args.copy_supplement and not state.get('copy_privacy', {}).get('complete'):
        result.append({'stage': 'privacy', 'scope': 'copy_supplement', 'cell_count': 1})
    return result


def unknown_ref_feedback(model, scope, wanted, sources):
    """Tell the model an unknown ref with its nearest refs; the same unknown ref repeated past the limit fails."""
    if model.failures.add(scope + ':unknown-ref:' + str(wanted), 'unknown_ref'):
        raise KeyError(wanted)
    return unknown_ref(wanted, sources)


async def privacy_cells(model, cells, deadline, state=None, checkpoint=None):
    """Split malformed batches; only the failing leaf cell is withheld."""
    state = state if state is not None else {}
    state['cell_ids'] = [cell['id'] for cell in cells]
    released, errors = state.setdefault('released', {}), state.setdefault('errors', {})
    terminal = state.setdefault('terminal', [])
    # A decision holds only for the input it reviewed. A decision without a recorded input (made before
    # inputs were recorded) cannot be matched to the current input, so that cell is reviewed again.
    inputs = state.setdefault('released_inputs', {})
    def settled(cell):
        known = inputs.get(cell['id'])
        return ((cell['id'] in released or cell['id'] in terminal)
                and known is not None and known == ref(serialized(cell['value'])))
    buffers = state.setdefault('buffers', {})
    reads = ReadMemory(buffers, 'privacy-read')
    if 'reads' in state:
        reads.restore(state['reads'])
    async def persist():
        state['reads'] = reads.snapshot()
        if checkpoint is not None:
            await checkpoint()
    async def review(batch, feedback=None):
        while batch:
            followup = await attempt(batch, feedback)
            if followup is None:
                return
            batch, feedback = followup

    async def attempt(batch, feedback):
        if not batch:
            return
        if model.stopped() or time.monotonic() >= deadline:
            if model.pending_answer is not None and not model.receipt_delivered:
                pass
            else:
                for cell in batch:
                    errors[cell['id']] = model.stop_reason or 'time_budget'
                await persist()
                return
        try:
            raw = serialized({'cells': batch})
            def build_context(current, adapter_feedback=None):
                correction = feedback if adapter_feedback is None else {'previous_feedback': feedback, **adapter_feedback}
                # Cells first: windows read for earlier batches must not crowd this batch out.
                entries = [('privacy:cell:' + cell['id'], 'privacy_cell', cell) for cell in batch]
                if correction:
                    entries.append(('privacy:feedback', 'correction', correction))
                entries.extend(reads.entries())
                return pack_context({'pending_cells': [cell['id'] for cell in batch],
                                    'read_windows': reads.state(), 'released_cell_ids': list(released),
                                    'feedback': feedback_state(correction, 'privacy:feedback'),
                                    'cost_budget': model.cost_record(),
                                    'context_ref': 'provided-context', 'total_chars': len(raw)},
                                   entries, buffers, model.context_chars)
            context = build_context({})
            answer = await model.call('publication_privacy', PRIVACY, context, PRIVACY_SCHEMA, deadline=deadline,
                                      context_builder=build_context)
            rows = answer.get('fields', [])
            if isinstance(rows, dict):
                rows = ([rows] if 'id' in rows else
                        [{'id': key, **(value if isinstance(value, dict) else {'value': value})}
                         for key, value in rows.items()])
            if not isinstance(rows, list):
                rows = []
            by_id = {row['id']: row for row in rows if isinstance(row, dict) and isinstance(row.get('id'), str)}
        except Exception as error:
            by_id = {}
            answer = {}
            failure = getattr(error, 'code', type(error).__name__)
            feedback = {'error': failure, 'detail': getattr(error, 'detail', None)}
            if failure in ('time_budget', 'cost_budget', 'cost_usage_unknown'):
                for cell in batch:
                    errors[cell['id']] = failure
                await persist()
                return
        else:
            failure = 'PrivacyCellMissingOrMalformed'
        pending = []
        for cell in batch:
            if cell['id'] in terminal:
                continue
            if cell['id'] in released and cell['id'] not in by_id:
                continue
            try:
                row = by_id[cell['id']]
                # Only the model's explicit decision is required; its sanitized value is used as given.
                if row.get('safe') is False:
                    released.pop(cell['id'], None)
                    errors[cell['id']] = 'privacy_withheld'
                    terminal.append(cell['id'])
                    inputs[cell['id']] = ref(serialized(cell['value']))
                    continue
                if row.get('safe') is not True:
                    raise ValueError('PrivacyDecisionMissing')
                value = (replace_leaves(cell['value'], row['replacements']) if 'replacements' in row else
                         row['value'] if 'value' in row else cell['value'])
                if isinstance(value, str) and 'value' in row and 'replacements' not in row:
                    try:
                        value = json.loads(value)
                    except ValueError:
                        pass
                # A copy of the whole cell (id and value wrapper) is the same answer in another shape.
                if ('replacements' not in row and isinstance(value, dict) and value.get('id') == cell['id'] and 'value' in value
                        and set(value) <= set(cell)):
                    value = value['value']
                # safe=true with an empty value is a release decision, so the original is kept.
                if value is None:
                    value = cell['value']
                released[cell['id']] = protect(json_safe(value), model.secrets)
                inputs[cell['id']] = ref(serialized(cell['value']))
                errors.pop(cell['id'], None)
                model.failures.clear('privacy:' + cell['id'])
            except Exception:
                pending.append(cell)
        if '_read_sample' in answer or '_find' in answer:
            tool_args = {key: answer[key] for key in ('_read_sample', '_find') if key in answer}
            try:
                if '_read_sample' in answer:
                    window = answer['_read_sample']
                    if window.get('ref') != 'provided-context' and window.get('ref') not in buffers:
                        feedback = {'read_error': unknown_ref_feedback(model, 'privacy', window.get('ref'), buffers)}
                    else:
                        source = raw if window['ref'] == 'provided-context' else buffers[window['ref']]
                        reads.read(source, window, model.context_chars)
                if '_find' in answer:
                    feedback = {'find': find_text({**buffers, 'provided-context': raw}, answer['_find'])}
            except Exception as error:
                failure = getattr(error, 'code', type(error).__name__)
                operation = 'privacy-read:' + serialized(tool_args)
                if model.failures.add(operation, failure):
                    for cell in pending:
                        errors[cell['id']] = failure
                        terminal.append(cell['id'])
                        inputs[cell['id']] = ref(serialized(cell['value']))
                    await persist()
                    return
                feedback = {'error': failure, 'detail': getattr(error, 'detail', None)}
            else:
                model.failures.clear('privacy-read:' + serialized(tool_args))
            state['feedback'] = feedback
            await persist()
            return pending or batch, feedback
        if not pending:
            await persist()
            return
        feedback = {'error': failure, 'partial_answer': answer,
                    'instruction': 'Correct only pending cells; released cells are preserved.'}
        state['feedback'] = feedback
        await persist()
        if len(pending) > 1:
            middle = len(pending) // 2
            await review(pending[:middle], feedback)
            await review(pending[middle:], feedback)
        else:
            cell = pending[0]
            if model.failures.add('privacy:' + cell['id'], failure) or model.stopped():
                errors[cell['id']] = failure
                if not model.stopped():
                    terminal.append(cell['id'])
                    inputs[cell['id']] = ref(serialized(cell['value']))
                await persist()
            else:
                await review([{**cell, 'correction': failure}], feedback)
    # Size-driven batches have no semantic grouping or field whitelist. A quarter of the context leaves room
    # for per-cell metadata, the released id list and read windows, so every pending cell stays in view.
    batch = []
    limit = model.context_chars // 4
    for cell in cells:
        if settled(cell):
            continue
        released.pop(cell['id'], None)
        if cell['id'] in terminal:
            terminal.remove(cell['id'])
        errors.pop(cell['id'], None)
        if batch and len(serialized({'cells': [*batch, cell]})) > limit:
            await review(batch)
            batch = []
        batch.append(cell)
    await review(batch, state.get('feedback'))
    state['complete'] = all(settled(cell) for cell in cells)
    await persist()
    return released, errors


async def answer_group(model, observer, catalog, group, deadline, state=None, checkpoint=None, run=None):
    schema = group_schema(catalog, group)
    state = state if state is not None else {}
    answers, errors = state.setdefault('answers', {}), state.setdefault('errors', {})
    provisional = set(state.get('provisional_axes', []))
    correction = state.get('correction')
    reads = ReadMemory(state.setdefault('buffers', {}), 'group-read:' + group)
    if 'reads' in state:
        reads.restore(state['reads'])
    exit_reason = None
    async def persist():
        state.update(correction=correction, reads=reads.snapshot(), provisional_axes=sorted(provisional))
        if checkpoint is not None:
            await checkpoint()
    await persist()
    while (model.pending_answer is not None or
           (not model.stopped() and not observer.failures.stopped and time.monotonic() < deadline)):
        if set(answers) == set(schema['properties']) and not provisional:
            break
        preserved = {'partial_answers': answers, 'provisional_axes': sorted(provisional),
                     'instruction': 'Revisit pending partial answers using the new tool feedback and read windows.'}
        def build_context(current, adapter_feedback=None):
            feedback = correction
            if adapter_feedback is not None:
                feedback = {'previous_feedback': correction, **adapter_feedback}
            return observer.model_context(feedback, reads,
                    {'run': run, 'analysis_group': group, 'analysis_remaining_seconds': max(0, deadline - time.monotonic()), 'pending_axes': [key for key in schema['properties']
                                                            if (key not in answers or key in provisional) and key not in state.get('terminal_axes', [])],
                     'preserved_answers': feedback_state(preserved, 'group:' + group + ':answers') if answers else None,
                     'analysis_notes': state.get('notes')},
                     [('group:' + group + ':answers', 'accepted_axes', preserved)] if answers else [])
        context = build_context({})
        try:
            response = await model.call('group_' + group, group_prompt(catalog, group), context, schema,
                                        deadline=deadline, context_builder=build_context)
            exit_reason = None
            # The model's own notes return in its next call; the code does not read them.
            if isinstance(response, dict) and isinstance(response.get('_notes'), str):
                state['notes'] = response['_notes']
            valid, invalid = check_answers(catalog, group, response)
            answers.update(valid)
            has_tools = '_read_sample' in response or '_find' in response
            for key, answer in valid.items():
                if isinstance(answer, dict) and answer.get('final') is False:
                    provisional.add(key)
                else:
                    provisional.discard(key)
            for key in valid:
                model.failures.clear('axis:' + key)
                errors.pop(key, None)
            for key in list(invalid):
                if key in answers or key in state.get('terminal_axes', []):
                    invalid.pop(key)
            if has_tools:
                # A tool result must reach a later call before any answer can freeze.
                provisional.update(answers)
                tool_feedback = {}
                requested = response.get('_read_sample')
                # One batch may fill at most a third of the context, so what it shows stays in view together.
                batch_chars, not_read = 0, []
                for window in (requested if isinstance(requested, list) else [requested] if requested else []):
                    wanted = window.get('ref') if isinstance(window, dict) else None
                    # Each window is cut to the room left in this batch; base64 and metadata take up to a quarter more.
                    room = (model.context_chars // 3 - batch_chars) * 3 // 4
                    if room < 1:
                        not_read.append(window)
                        continue
                    sources = observer.readable_sources(reads)
                    if wanted in sources:
                        asked = window.get('limit')
                        window = {**window, 'limit': min(asked, room) if type(asked) is int and asked > 0 else room}
                        batch_chars += len(serialized(observer.read_sample(window, reads)))
                    else:
                        tool_feedback.setdefault('read_errors', []).append(
                            unknown_ref_feedback(model, 'group:' + group, wanted, sources))
                if not_read:
                    tool_feedback['not_read'] = {
                        'requests': not_read, 'read_chars': batch_chars, 'context_chars': model.context_chars,
                        'reason': 'this batch already fills a third of the context; older windows leave the view as '
                                  'more are read, so answer or record notes from what was read before requesting these'}
                if '_find' in response:
                    wanted = response['_find']
                    tool_feedback['find'] = ([observer.find(item, reads) for item in wanted] if isinstance(wanted, list)
                                             else observer.find(wanted, reads))
                    # An unknown ref in a search counts toward the same repeat limit as an unknown read.
                    for found in (tool_feedback['find'] if isinstance(tool_feedback['find'], list) else [tool_feedback['find']]):
                        for missing in found.get('unknown_refs', []):
                            unknown_ref_feedback(model, 'group:' + group, missing, observer.readable_sources(reads))
                correction = tool_feedback or None
                await persist()
                continue
            if not invalid and not provisional:
                state['complete'] = True
                await persist()
                break
            for key, error in invalid.items():
                errors[key] = error
                if model.failures.add('axis:' + key, error):
                    state.setdefault('terminal_axes', []).append(key)
            if not provisional and all(key in answers or key in state.get('terminal_axes', []) for key in schema['properties']):
                state['complete'] = True
                break
            correction = {'errors': invalid, 'partial_answers': response,
                          'instruction': 'Answer pending axes, including final=false partial answers. Other answers are preserved.'}
        except Exception as error:
            exit_reason = getattr(error, 'code', type(error).__name__)
            if isinstance(error, ModelError) and error.code in ('time_budget', 'cost_budget', 'cost_usage_unknown'):
                break
            # Group tool feedback remains local to this group, including errors.
            correction = {'error': exit_reason, 'detail': getattr(error, 'detail', None) or str(error)}
            observer.failures.add('group:' + group, exit_reason)
            if model.stopped() or observer.failures.exhausted('group:' + group):
                break
        await persist()
    for key in schema['properties']:
        if (key not in answers or key in provisional) and key not in state.get('terminal_axes', []):
            errors[key] = model.stop_reason or exit_reason or (
                'time_budget' if time.monotonic() >= deadline else 'same_failure_limit'
                if observer.failures.exhausted('group:' + group) else 'time_or_failure_budget')
    state['errors'] = {key: error for key, error in errors.items() if key not in answers or key in provisional}
    state['complete'] = not provisional and all(key in answers or key in state.get('terminal_axes', []) for key in schema['properties'])
    if state['complete']:
        # A finished group is not resumed; its copies of the observation only bloat every checkpoint. Window
        # records stay without their text, so an evidence ref to a window still names the observation ref
        # (requested_ref) and range it came from.
        reads.buffers.clear()
        for identity, (key, window) in list(reads.windows.items()):
            reads.windows[identity] = (key, {name: value for name, value in window.items() if name != 'value'})
    await persist()
    return answers, state['errors']


async def one_run(index, args, catalog, limits, model, login, checkpoint, store, defer_fact_privacy=False,
                  publication_only=False):
    mode = 'anonymous' if index <= args.runs else 'session'
    questions = [{'id': axis['id'], 'question': axis['question']} for axis in catalog['axes']]
    observer = Observer(args.origin_url, model, Budget(**{**limits, 'seconds': args.browse_seconds or limits['seconds']}),
                        login, args.same_failure_limit, questions, request_seconds=args.request_seconds,
                        body_bytes=args.body_bytes, retained_bytes=args.retained_bytes, stream_messages=args.stream_messages,
                        session_file=args.session_file if mode == 'session' else None)
    observer.operator_supplement = copy_supplement(args.copy_supplement)
    state = store.state['runs'].setdefault(str(index), {'groups': {}, 'privacy': {}})
    previous_mode = state.get('authority', state.get('published', {}).get('authority', {}).get(
        'requested', 'anonymous' if state.get('observation') else mode))
    if previous_mode != mode:
        raise ValueError('저장된 회차의 관찰 권한이 다름: --fresh로 새로 시작해야 함')
    state['authority'] = mode
    if state.get('complete') and not state.get('privacy', {}).get('working_notes', {}).get('complete'):
        state['complete'] = False
    model.remaining_stages = lambda: remaining_work(args, catalog, store.state, index, observer)
    for group, saved in state['groups'].items():
        missing = (set(group_schema(catalog, group)['properties']) - set(saved.get('answers', {}))
                   - set(saved.get('terminal_axes', [])))
        if saved.get('complete') and missing:
            saved['complete'] = state['complete'] = False
    if state.get('complete'):
        await checkpoint(state['published'])
        return state['published']
    if publication_only and not state.get('observation_complete'):
        return state['published']
    started = state.setdefault('started_at', now())
    observer.budget.begin()
    if state.get('observation'):
        observer.restore(state['observation'])
    if args.reset_failures:
        observer.failures.counts.clear()
    facts = observer.publication()
    table = candidates(facts)
    published, withheld = redact(facts, table, {})
    axes = empty_axes(catalog, '분석 또는 가림을 아직 얻지 못함')
    run = {'run': index, 'started_at': started, 'finished_at': None,
           'authority': {'source': 'operator_and_observer', 'requested': mode,
                         'mode': mode, 'operator_prepared_session': mode == 'session',
                         'credential_env': args.login_env, 'credential_values_recorded': False,
                         'login_attempted': False, 'login_request_sent': False,
                         'limit': '폼 제출 금지, 운영자 준비 세션의 관찰 범위만 기록' if mode == 'session' else '폼 로그인 금지, 공개 관찰만 수행'},
           'facts': published, 'axes': axes, 'model_decisions': [], 'decision_events': observer.decision_events,
           'working_notes': None, 'browse_stop_reason': None, 'group_errors': [],
           'response_times': [{'source': row['source'], 'route': row['route'], **row['response_time']['value']}
                              for row in facts['responses'] if row['response_time']['status'] == '관찰됨'],
           'privacy': {'source': 'model', 'withheld_field_ids': withheld, 'errors': {}, 'model_record_released': False}}
    if state.get('published'):
        run = state['published']
        axes = run['axes']
        run.pop('group_budgets', None)
    async def persist(analysis=False):
        if analysis:
            state['observation'] = observer.snapshot()
        state['published'] = run
        store.save(model)
        await checkpoint(run)
    await persist(analysis=True)
    async def browse_checkpoint():
        observed = observer.publication()
        pending = candidates(observed)
        run['facts'], run['privacy']['withheld_field_ids'] = redact(observed, pending, {})
        if observer.browse_stop_reason is not None:
            run['browse_stop_reason'] = observer.browse_stop_reason
        run['response_times'] = [{'source': row['source'], 'route': row['route'], **row['response_time']['value']}
                                 for row in observed['responses'] if row['response_time']['status'] == '관찰됨']
        run['decision_events'] = observer.decision_events
        await persist(analysis=True)
    observer.checkpoint = browse_checkpoint
    if not state.get('observation_complete'):
        try:
            await observer.run()
        except Exception as error:
            observer.error('observation_run', error)
        observer.browse_finished()
        run['browse_stop_reason'] = observer.browse_stop_reason or ('model_stop' if observer.model_done else
            model.stop_reason or ('same_failure_limit' if observer.failures.stopped else
            'observation_budget' if observer.budget.exhausted() else 'observation_finished'))
        state['observation_complete'] = not model.stopped() or observer.model_done or observer.browse_finished() or observer.budget.exhausted()
        await browse_checkpoint()
        if not state['observation_complete']:
            return run
    # Raw observations only reach the external private checkpoint.
    facts = observer.publication()
    table = candidates(facts)
    analysis_started = time.monotonic()
    deadline = analysis_started + (args.analysis_seconds or limits['seconds'])
    run['stage_seconds'] = {'browse': args.browse_seconds or limits['seconds'],
                           'analysis': args.analysis_seconds or limits['seconds']}
    group_answers = {}
    # Analyze groups before reviewing their answers for publication.
    for group in catalog['call_order']:
        saved = state['groups'].setdefault(group, {})
        if saved.get('complete') or publication_only or (model.pending_answer is not None
                                                       and model.pending_answer['purpose'] == 'publication_privacy'):
            group_answers[group] = (saved.get('answers', {}), saved.get('errors', {}))
            run['group_errors'] = [row for row in run['group_errors'] if row['group'] != group]
            run['group_errors'].extend({'axis': key, 'group': group, 'status': '못 얻음', 'error': reason}
                                      for key, reason in group_answers[group][1].items())
            store.write(f'run-{index}-{group}.json', {'answers': group_answers[group][0], 'errors': group_answers[group][1]})
            continue
        if model.stopped() and model.pending_answer is None:
            return run
        print(f'실행 {index}: {group} 묶음 분석', file=sys.stderr)
        async def group_checkpoint():
            await persist(analysis=True)
        answers, errors = await answer_group(model, observer, catalog, group, deadline, saved, group_checkpoint, run=index)
        group_answers[group] = (answers, errors)
        # Keep the paid-for answers outside the repository before publication review,
        # so a later privacy or budget failure does not force a full rerun.
        store.write(f'run-{index}-{group}.json', {'answers': answers, 'errors': errors})
        run['group_errors'] = [row for row in run['group_errors'] if row['group'] != group]
        run['group_errors'].extend({'axis': key, 'group': group, 'status': '못 얻음', 'error': reason}
                                   for key, reason in errors.items())
        await persist(analysis=True)
    state['analysis_elapsed_seconds'] = state.get('analysis_elapsed_seconds', 0) + time.monotonic() - analysis_started
    # Pause the round clock here. Each invocation gets an independent privacy
    # window; saved cells are retained if that window expires.
    run['facts']['budget'] = state['observation']['budget']
    privacy_deadline = time.monotonic() + (args.privacy_seconds or limits['seconds'])
    async def review(scope, cells):
        saved = state['privacy'].setdefault(scope, {})
        if model.pending_answer is not None and not model.receipt_delivered:
            pending_scope = state.get('active_privacy_scope')
            rows = model.pending_answer['answer'].get('fields', [])
            pending_ids = {row.get('id') for row in rows if isinstance(row, dict)} if isinstance(rows, list) else set()
            if ((pending_scope and pending_scope != scope) or
                    (not pending_scope and pending_ids and not pending_ids.intersection(cell['id'] for cell in cells))):
                return saved.get('released', {}), saved.get('errors', {})
        state['active_privacy_scope'] = scope
        await persist()
        for cell in cells:
            run['privacy']['errors'].pop(cell['id'], None)
        return await privacy_cells(model, cells, privacy_deadline, saved, persist)
    for group in catalog['call_order']:
        answers, errors = group_answers[group]
        cells = [{'id': 'axis-' + key, 'axis': True, 'value': value} for key, value in answers.items()]
        safe, privacy_errors = await review('axis:' + group, cells)
        for key in group_schema(catalog, group)['properties']:
            value = safe.get('axis-' + key)
            if value is not None:
                axes[key] = {**value, 'source': 'model'} if isinstance(value, dict) else {'value': value, 'source': 'model'}
            else:
                reason = errors.get(key) or privacy_errors.get('axis-' + key) or '못 얻음'
                axes[key] = {**unavailable(reason), 'source': 'analysis_runner', 'requested_source': 'model'}
        run['privacy']['errors'].update(privacy_errors)
        await persist()
    if defer_fact_privacy:
        if model.pending_answer is None or model.receipt_delivered:
            await persist()
            return run
        # Replay a paid fact/decision receipt from an older checkpoint before
        # advancing to another run. An expired clock prevents new lower-priority calls.
        privacy_deadline = time.monotonic() - 1
    # Release facts incrementally; model failure cannot erase numeric observations.
    fact_values, fact_errors = await review('facts', table)
    run['facts'], run['privacy']['withheld_field_ids'] = redact(facts, table, fact_values)
    run['privacy']['errors'].update(fact_errors)
    run['privacy']['corrected_fields'] = [{'id': item['id'], 'path': item['path'], 'source': 'model_privacy'}
                                         for item in table if item['id'] in fact_values and fact_values[item['id']] != item['value']]
    run['privacy']['withheld_fields'] = [{'id': item['id'], 'path': item['path'],
                                         'reason': fact_errors.get(item['id'], 'privacy_withheld')}
                                        for item in table if item['id'] not in fact_values]
    await persist()
    safe, decision_errors = await review('decisions', [{'id': 'decision-' + str(i), 'value': value}
                                                      for i, value in enumerate(observer.decisions)])
    run['model_decisions'] = [safe.get('decision-' + str(i), {'status': '못 얻음', 'reason': decision_errors.get('decision-' + str(i), 'privacy_withheld')})
                              for i in range(len(observer.decisions))]
    run['privacy']['errors'].update(decision_errors)
    safe_notes, notes_errors = await review('working_notes', [{'id': 'working-notes', 'value': observer.working_notes}])
    run['working_notes'] = safe_notes.get('working-notes')
    run['privacy']['errors'].update(notes_errors)
    run['privacy']['model_record_released'] = not run['privacy']['errors']
    state['complete'] = (all(saved.get('complete') for saved in state['groups'].values())
                         and all(saved.get('complete') for saved in state['privacy'].values()))
    run['finished_at'] = now() if state['complete'] else None
    run['facts']['budget'] = state['observation']['budget']
    await persist()
    return run


def merge_batch(pending, runs, limit):
    batch, size = [], 0
    for key in pending:
        count = sum(len(serialized(run['axes'][key])) for run in runs)
        if batch and (len(batch) >= 6 or size + count > limit // 3):
            break
        batch.append(key)
        size += count
    return batch


async def semantic_merge(model, catalog, runs, deadline, state=None, checkpoint=None, privacy_seconds=None,
                         observations=None):
    if len(runs_by_authority(runs)) > 1:
        raise ValueError('서로 다른 관찰 권한을 의미 비교할 수 없음')
    mode = next(iter(runs_by_authority(runs)), 'anonymous')
    failure_prefix = 'merge:' + ('session:' if mode == 'session' else '')
    state = state if state is not None else {}
    judgments = state.setdefault('judgments', {})
    raw_rows = state.setdefault('raw', {})
    groups = state.setdefault('groups', {})
    observation_sources, observation_entries, observation_refs = {}, [], {}
    for i, run in enumerate(runs):
        run_number = run.get('run', i + 1)
        saved_observation = (observations or {}).get(str(run_number))
        if not saved_observation:
            continue
        observer = Observer('', model, Budget(sample_chars=model.context_chars))
        for key, value in saved_observation['fields'].items():
            setattr(observer, key, restored_copy(value))
        prefix = 'run:' + str(run_number) + ':'
        index_ref = prefix + 'observation:index'
        index = observer.observation_index(prefix)
        observation_sources.update({prefix + key: value for key, value in observer.readable_sources().items()})
        observation_entries.append((index_ref, 'observation_index', index))
        observation_refs[run_number] = {'observation_index_ref': index_ref, 'source_ref_prefix': prefix,
                                    'buffer_refs': [prefix + key for key in observer.buffers]}
    async def persist():
        if checkpoint is not None:
            await checkpoint()
    if len(runs) < 2:
        state['complete'] = True
        await persist()
        return judgments
    for group in catalog['groups']:
        ids = [axis['id'] for axis in catalog['axes'] if axis['group'] == group]
        saved = groups.setdefault(group, {})
        pending = [key for key in ids if key not in judgments and key not in raw_rows]
        feedback = saved.get('feedback')
        buffers = saved.setdefault('buffers', {})
        buffers.update(observation_sources)
        reads = ReadMemory(buffers, 'merge-read:' + group)
        if 'reads' in saved:
            reads.restore(saved['reads'])
        async def release_rows():
            nonlocal deadline
            rows = {key: raw_rows[key] for key in ids if key in raw_rows and key not in judgments}
            if not rows:
                return
            started = time.monotonic()
            privacy_state = saved.setdefault('privacy', {})
            safe, errors = await privacy_cells(model, [{'id': 'merge-' + key, 'axis': True, 'value': row['answer']}
                                                       for key, row in rows.items()],
                                               started + privacy_seconds if privacy_seconds else deadline,
                                               privacy_state, persist)
            if privacy_seconds:
                deadline += time.monotonic() - started
            for key, row in rows.items():
                if 'merge-' + key in safe:
                    # A release saved with an empty value keeps the combined answer itself.
                    answer = row['answer'] if safe['merge-' + key] is None else safe['merge-' + key]
                    judgments[key] = {'agreement': row['agreement'],
                                      'answer': {**answer, 'source': 'model'} if isinstance(answer, dict) else answer}
                elif 'merge-' + key in privacy_state['terminal']:
                    judgments[key] = {'agreement': row['agreement'], 'error': errors['merge-' + key]}
            await persist()
        await release_rows()
        # A provided-context ref always names the same full group in this session.
        raw = serialized({'runs': [{'run': run.get('run', i + 1), 'authority': run.get('authority', {'requested': 'anonymous'}),
                                   'axes': {key: run['axes'][key] for key in ids}} for i, run in enumerate(runs)]})
        while pending and (model.pending_answer is not None or (not model.stopped() and time.monotonic() < deadline)):
            limit = model.context_chars
            batch = saved.get('active_batch') or merge_batch(pending, runs, limit)
            batch = [key for key in batch if key in pending] or merge_batch(pending, runs, limit)
            saved['active_batch'] = batch
            def build_context(current, adapter_feedback=None):
                nonlocal batch
                batch = merge_batch(batch, runs, model.context_chars)
                saved['active_batch'] = batch
                correction = feedback if adapter_feedback is None else {'previous_feedback': feedback, **adapter_feedback}
                entries = [*observation_entries, *reads.entries()]
                if correction:
                    entries.append(('merge:feedback', 'feedback', correction))
                accepted = {key: judgments[key] for key in ids if key in judgments}
                if accepted:
                    entries.append(('merge:accepted:' + group, 'accepted_axes', accepted))
                if saved.get('partial_answers'):
                    entries.append(('merge:partial:' + group, 'partial_answers', saved['partial_answers']))
                entries.extend(('merge:' + group + ':' + key + ':' + str(runs[i].get('run', i + 1)), 'axis_run',
                                {'axis': key, 'run': runs[i].get('run', i + 1),
                                 'authority': runs[i].get('authority', {'requested': 'anonymous'}), 'answer': runs[i]['axes'][key],
                                 **observation_refs.get(runs[i].get('run', i + 1), {})})
                               for i in reversed(range(len(runs))) for key in batch)
                return pack_context({'pending_axes': batch, 'accepted_axes': list(accepted),
                                        'authority': runs[0].get('authority', {'requested': 'anonymous'}),
                                        'run_observations': observation_refs,
                                        'read_windows': reads.state(), 'feedback': feedback_state(correction, 'merge:feedback'),
                                        'cost_budget': model.cost_record(),
                                        'context_ref': 'provided-context', 'total_chars': len(raw)},
                                       entries, buffers, model.context_chars)
            context = build_context({})
            try:
                response = await model.call('merge_' + group, MERGE, context,
                                            obj({key: MERGE_ANSWER for key in batch}), deadline=deadline, context_builder=build_context)
                has_read = '_read_sample' in response or '_find' in response
                remaining, valid_rows = [], {}
                for key in batch:
                    try:
                        row = response[key]
                        row = ({'agreement': row.get('agreement'), 'answer': row.get('answer', row)}
                               if isinstance(row, dict) else {'agreement': None, 'answer': row})
                        valid_rows[key] = row
                        model.failures.clear(failure_prefix + key)
                    except Exception as error:
                        code = getattr(error, 'code', type(error).__name__)
                        if not has_read and model.failures.add(failure_prefix + key, code):
                            judgments[key] = {'error': code}
                        else:
                            remaining.append(key)
                if has_read:
                    saved.setdefault('partial_answers', {}).update(valid_rows)
                    feedback = None
                    if '_read_sample' in response:
                        window = response['_read_sample']
                        if window.get('ref') != 'provided-context' and window.get('ref') not in buffers:
                            feedback = {'read_error': unknown_ref_feedback(model, 'merge:' + group, window.get('ref'), buffers)}
                        else:
                            source = raw if window['ref'] == 'provided-context' else buffers[window['ref']]
                            reads.read(source, window, limit)
                    if '_find' in response:
                        feedback = {**(feedback or {}), 'find': find_text({**buffers, 'provided-context': raw}, response['_find'])}
                else:
                    raw_rows.update(valid_rows)
                    for key in valid_rows:
                        saved.get('partial_answers', {}).pop(key, None)
                    pending = [key for key in pending if key not in batch] + remaining
                    saved['active_batch'] = remaining
                if not has_read and remaining:
                    feedback = {'errors': remaining, 'partial_answer': response}
                saved.update(reads=reads.snapshot(), feedback=feedback)
                await persist()
                if not has_read:
                    await release_rows()
            except Exception as error:
                code = getattr(error, 'code', type(error).__name__)
                if model.failures.add(failure_prefix + group, code):
                    break
                feedback = {'error': code, 'detail': getattr(error, 'detail', None)}
            saved.update(reads=reads.snapshot(), feedback=feedback)
            await persist()
    state['complete'] = all(axis['id'] in judgments for axis in catalog['axes'])
    await persist()
    result = dict(judgments)
    for axis in catalog['axes']:
        result.setdefault(axis['id'], {'error': model.stop_reason or 'time_or_failure_budget'})
    return result


def check_merge_rules(catalog):
    first = empty_axes(catalog, 'dry-run A')
    second = empty_axes(catalog, 'dry-run B')
    for answer in first.values():
        answer['status'] = '관찰됨'
    runs = [{'axes': first}, {'axes': second}]
    yes = {key: {'agreement': True, 'answer': value} for key, value in first.items()}
    no = {key: {'agreement': False, 'answer': value} for key, value in first.items()}
    agreed, different = merge(catalog, runs, yes), merge(catalog, runs, no)
    for axis in catalog['axes']:
        key = axis['id']
        rule = catalog['groups'][axis['group']]['merge']
        if rule == 'union' and different['axes'][key]['run_indices'] != [1, 2]:
            raise ValueError('한 번의 발견 보존 실패')
        if rule == 'consensus' and (len(different['axes'][key]['answers']) != 2 or not agreed['axes'][key]['answers']
                                    or different['axes'][key]['disposition'] != 'withheld_no_consensus'):
            raise ValueError('의미 합의 규칙 실패')
        if rule == 'retain' and different['axes'][key]['run_indices'] != [1, 2]:
            raise ValueError('실행별 보존 실패')
    # Same failure only, successful repetition is never capped.
    failures = Failures(2)
    if failures.add('operation', 'failure') or failures.add('other', 'failure'):
        raise ValueError('서로 다른 실패 합산 오류')
    failures.clear('operation')
    if failures.add('operation', 'failure') or not failures.add('operation', 'failure'):
        raise ValueError('같은 실패 반복 상한 오류')


def copy_supplement(path):
    if path is None:
        return None
    with Path(path).open('r', encoding='utf-8-sig') as stream:
        raw = stream.read(4000001)
    if len(raw) > 4000000:
        raise ValueError('복사 보충 파일 크기 초과')
    value = json.loads(raw)
    if value.get('state') != 'ready' or not isinstance(value.get('containers'), dict):
        raise ValueError('복사 완료 컨테이너 기록이 필요함')
    rows = []
    for service, container in value['containers'].items():
        required(container, 'id', 'image_id')
        rows.append({'service': service, 'container_id_sha256': ref(container['id']),
                     'image_id': container['image_id'], 'started_at': container.get('started_at')})
    return {'source': 'copy', 'status': '관찰됨', 'document_sha256': ref(raw), 'containers': rows,
            'primary_core': value.get('primary_core'),
            'limit': '운영자 제공 복사 기록을 읽음, 현재 Docker 상태는 확인하지 않음'}


def dry_plan(args, catalog, output, limits):
    store = ResumeStore(output, args.origin_url, catalog, args.fresh, args.checkpoint_root)
    schemas = {group: group_schema(catalog, group) for group in catalog['call_order']}
    for schema in [*schemas.values(), ACTION_SCHEMA, PRIVACY_SCHEMA, MERGE_ANSWER]:
        check_schema(schema)
    template = empty_axes(catalog, 'dry-run: 원본과 모델 미실행')
    for group in catalog['call_order']:
        _, errors = check_answers(catalog, group, {key: template[key] for key in schemas[group]['properties']})
        if errors:
            raise ValueError('축 완전성 검사 실패')
    check_merge_rules(catalog)
    # Model shapes remain advisory; only a missing identifier is pending.
    group = catalog['call_order'][0]
    partial = {key: {**template[key], 'confidence': 65, 'confidence_scale': 'percent'}
               for key in schemas[group]['properties']}
    first = next(iter(partial))
    partial[first] = {'status': 'invalid'}
    valid, errors = check_answers(catalog, group, partial)
    if errors or len(valid) != len(partial) or valid[first] != {'status': 'invalid'}:
        raise ValueError('축별 격리 검사 실패')
    asyncio.run(dry_transport_check())
    asyncio.run(dry_browsing_check(catalog))
    asyncio.run(dry_analysis_check(catalog))
    asyncio.run(dry_resume_check(catalog))
    asyncio.run(dry_wide_check(catalog))
    asyncio.run(dry_fix4_check(catalog))
    asyncio.run(dry_cost_context_check(catalog))
    session_checks = asyncio.run(dry_session_notes_check(catalog))
    supplement = copy_supplement(args.copy_supplement)
    rate_status = '실행 때 --rates와 비용 상한 필요'
    resumed_budget = saved_resume = None
    if args.rates is not None:
        rate, ceiling = cost_settings(args.rates, args.model, args.max_cost_usd)
        rate_status = 'passed, ceiling=' + str(ceiling)
        if store.ledger:
            saved_resume = asyncio.run(dry_saved_groups(args, catalog, limits, store, rate, ceiling))
            resumed_budget = saved_resume.pop('cost_budget')
    print(json.dumps({'dry_run': True, 'out': str(output), 'origin_url_sha256': ref(args.origin_url),
                      'model': args.model, 'provider': args.provider, 'reasoning_effort': args.reasoning_effort, 'runs': args.runs,
                      'structure_fix_synthetic_checks': 'passed',
                      'session_runs': args.session_runs, 'session_file_supplied': args.session_file is not None,
                      'observation_runs': [{'run': index, 'authority': mode} for index, mode in run_specs(args)],
                      'session_notes_checks': session_checks, 'budget_per_run': limits,
                      'context_chars': args.context_chars, 'same_failure_limit': args.same_failure_limit,
                      'cost_policy': 'total_ceiling_only; model decides spending',
                      'stage_seconds': {'browse': args.browse_seconds or limits['seconds'],
                                        'analysis': args.analysis_seconds or limits['seconds']},
                      'capture_limits': {'body_bytes': args.body_bytes, 'retained_bytes': args.retained_bytes,
                                         'stream_messages': args.stream_messages, 'request_seconds': args.request_seconds},
                      'copy_supplement_read': supplement is not None, 'wide_fix_check': 'passed',
                      'checkpoint_folder': str(store.path), 'resume_reason': store.reason,
                      'resume_from': store.plan(catalog, args.runs + args.session_runs),
                      'saved_cost': {key: store.ledger[key] for key in ('spent_usd', 'max_cost_usd', 'browse_spent_usd', 'analysis_spent_usd')}
                                    if store.ledger else None,
                      'resumed_cost_budget': resumed_budget, 'saved_group_resume_check': saved_resume,
                      'group_context_refresh_check': 'passed',
                      'privacy_priority_check': 'passed',
                      'privacy_order': ['all_runs_axis_answers', 'fact_cells', 'decision_cells', 'working_notes'],
                      'privacy_seconds_per_run': args.privacy_seconds or limits['seconds'],
                      'merge_seconds': args.merge_seconds or limits['seconds'],
                      'resume_check': 'passed',
                      'axis_count': len(template), 'schema_check': 'passed', 'completeness_check': 'passed',
                      'merge_rule_check': 'passed', 'failure_limit_check': 'passed', 'rates_check': rate_status,
                      'axis_isolation_check': 'passed', 'request_boundary_check': 'passed',
                      'browse_context_check': 'passed', 'retained_sample_check': 'passed',
                      'total_cost_boundary_check': 'passed', 'decision_metadata_check': 'passed',
                      'decision_checkpoint_check': 'passed',
                      'analysis_read_memory_check': 'passed', 'model_read_choice_check': 'passed',
                      'common_cost_context_check': 'passed', 'group_retry_boundary_check': 'passed',
                      'merge_read_memory_check': 'passed', 'privacy_read_memory_check': 'passed',
                      'merge_rules': {key: value['merge'] for key, value in catalog['groups'].items()},
                      'login_values_read': False, 'network_requests': 0, 'model_calls': 0, 'files_written': 0},
                     ensure_ascii=False, indent=2))


async def dry_transport_check():
    """Exercise routing without Playwright, sockets, a model adapter or output files."""
    from types import SimpleNamespace
    class Route:
        def __init__(self):
            self.sent = self.aborted = False
        async def continue_(self):
            self.sent = True
        async def abort(self):
            self.aborted = True
    observer = Observer('https://example.invalid/#/view',
                        SimpleNamespace(stopped=lambda: False, stop_reason=None, context_chars=600000), Budget())
    observer.budget.begin()
    for method, navigation, external, should_send in (
            ('GET', False, True, False), ('HEAD', False, False, True),
            ('POST', False, False, False), ('GET', True, True, False)):
        route = Route()
        request = SimpleNamespace(url='https://cdn.invalid/resource' if external else 'https://example.invalid/api',
                                  method=method, resource_type='document' if navigation else 'script',
                                  is_navigation_request=lambda: navigation, frame=SimpleNamespace(parent_frame=None))
        await observer.route(route, request)
        if route.sent is not should_send or route.aborted is should_send:
            raise ValueError('읽기 요청 경계 검사 실패')
    if observer.attempts[2]['reason'] != '보내지 않음(메서드)' or observer.budget.sent_requests != 1:
        raise ValueError('차단 대상과 전송 수 기록 검사 실패')
    observer.page = SimpleNamespace(url=observer.origin)
    try:
        await observer.action({'tool': 'open', 'args': '{"url":"/declined"}', 'read_only': False,
                               'human_confirmation': False, 'reason': 'dry-run candidate decline'})
    except ModelError:
        pass
    if observer.model_done:
        raise ValueError('후보 거부가 전체 종료로 바뀜')


async def dry_browsing_check(catalog):
    """Regression checks inside dry-run, with no provider, browser or writes."""
    from types import SimpleNamespace
    from .model import number
    model = Codex('dry-run', None, Path(__file__).parent / '.dry-unused', ceiling=number(25), context_chars=80000)
    observer = Observer('http://example.invalid/', model, Budget(sample_chars=80000),
                        axis_questions=[{'id': axis['id'], 'question': axis['question']} for axis in catalog['axes']])
    observer.budget.begin()
    first, current = 'http://example.invalid/sample/', 'http://example.invalid/post/#part'
    observer.pages = [SimpleNamespace(url=url, is_closed=lambda: False) for url in (first, current)]
    observer.page = observer.pages[1]
    observer.navigations = [{'url': url, 'route': ref(url), 'top_level': True} for url in (first, current, first)]
    observer.attempts = [{'url': url, 'route': ref(url), 'method': 'GET', 'resource_type': 'document', 'sent': True}
                         for url in (first, current, first)]
    for index, (url, text) in enumerate(((first, 'old-' * 50000), (current, 'new-' * 50000)), 1):
        body = observer.store_body(text, ref(url), 'source')
        observer.samples.append({'ref': 'sample-' + str(index), 'route': ref(url), 'url': url,
                                 'screen': {'status': '관찰됨', 'value': 'screen-' + str(index)},
                                 'source': {**body['body'], 'ref': body['ref']}})
    observer.feedback.append({'operation': 'open', 'status': '못 얻음', 'error': 'OfflineFeedback', 'detail': 'recent'})
    context = observer.model_context()
    if ({row['url']: row['count'] for row in context['visited_urls']} != {first: 2, current: 1}
            or context['current_url'] != current or context['current_page_index'] != 1
            or len(context['pages']) != 2 or len(context['axis_questions']) != len(catalog['axes'])
            or context['feedback'][0]['error'] != 'OfflineFeedback' or 'cost_budget' not in context):
        raise ValueError('현재 상태 보존 검사 실패')
    included = context['included_samples']
    if (len(serialized(context)) > model.context_chars or next(item['ref'] for item in included if item['ref'].startswith('sample-')) != 'sample-2'
            or 'sample-1' not in context['omitted_sample_refs']):
        raise ValueError('최신 표본 우선 창 검사 실패')
    alias = observer.read_sample({'ref': 'sample-1', 'limit': 2000})
    tail = observer.read_sample({'ref': observer.samples[0]['source']['ref'], 'offset': 199900, 'limit': 100})
    if alias['length'] == 0 or tail['value'] != ('old-' * 50000)[199900:]:
        raise ValueError('생략한 표본과 원문 뒤쪽 참조 검사 실패')
    escaped = sample_window('"\\\n' * 60000, {'ref': 'escaped', 'limit': 80000}, 80000)
    if len(serialized(escaped)) > 80000 or escaped['length'] <= 0:
        raise ValueError('JSON 확장 길이 검사 실패')
    unicode_bytes = ('한글' * 5000).encode('utf-8')
    decoded = sample_window(unicode_bytes, {'ref': 'utf8', 'limit': 5000, 'encoding': 'utf-8'}, 4096)
    binary = sample_window(unicode_bytes, {'ref': 'base64', 'limit': 5000}, 4096)
    if len(serialized(decoded)) > 4096 or len(serialized(binary)) > 4096 or decoded['length'] % 3:
        raise ValueError('바이트와 문자 창 검사 실패')
    for args in ({'ref': 'invalid', 'offset': -1}, {'ref': 'invalid', 'limit': True}):
        try:
            sample_window('data', args, 1000)
        except ValueError:
            pass
        else:
            raise ValueError('잘못된 창 범위 허용')
    large_state = {'visited_urls': context['visited_urls'] * 1000}
    bounded_buffers = {}
    tiny = pack_context(large_state, [('all', 'sample', 'large' * 100)], bounded_buffers, 1024)
    if (not tiny.get('state_exceeds_window') or len(serialized(tiny)) > 1024
            or json.loads(bounded_buffers[tiny['state_ref']]) != large_state
            or json.loads(bounded_buffers[tiny['manifest_ref']])['sample_refs'][0]['ref'] != 'all'):
        raise ValueError('큰 상태의 읽기 참조 또는 맥락 상한 오류')
    try:
        pack_context(large_state, [], {}, 2)
    except ValueError:
        pass
    else:
        raise ValueError('담을 수 없는 창에 초과 상태를 전송함')
    decision = {'tool': 'open', 'args': serialized({'url': '/value?secret=private-value'}),
                'read_only': False, 'human_confirmation': False, 'reason': 'private-reason'}
    event = observer.begin_decision(decision)
    try:
        await observer.action(decision)
    except ModelError:
        event['status'] = 'rejected'
    else:
        raise ValueError('읽기 경계 거부 실패')
    if (event['target_route'] != ref('http://example.invalid/value?secret=private-value')
            or not event['reason_present'] or 'private-' in serialized(observer.decision_events)):
        raise ValueError('값 없는 결정 기록 검사 실패')
    unknown = observer.begin_decision({'tool': 'private-tool', 'args': '{}', 'reason': ''})
    if unknown['tool'] != 'unknown' or unknown['reason_present']:
        raise ValueError('도구 이름과 이유 유무 검사 실패')
    observer.backend, observer.page, observer.current_http_url = 'http_client', None, current
    fallback = observer.model_context()
    if fallback['current_url'] != current or fallback['pages'][0]['url'] != current:
        raise ValueError('HTTP 현재 위치 검사 실패')
    model.spent, model.browse_spent = number('20'), number('20')
    if model.stopped() or observer.browse_finished():
        raise ValueError('둘러보기 사용액으로 전체 상한 전에 중단함')
    # Local response objects exercise the real executor/checkpoint path, not a provider.
    responses = [decision, {'tool': 'stop', 'args': '{}', 'read_only': True,
                            'human_confirmation': False, 'reason': 'sufficient observations'}]
    async def offline_response(*unused, **unused_keywords):
        return responses.pop(0)
    offline = SimpleNamespace(call=offline_response, context_chars=80000, cost_record=model.cost_record,
                              stopped=lambda: False, stop_reason=None)
    outcomes = []
    executor = Observer('http://example.invalid/', offline, Budget())
    executor.budget.begin()
    async def capture():
        outcomes.append(executor.decision_events[-1]['status'])
    executor.checkpoint = capture
    await executor.navigation()
    await executor.navigation()
    if outcomes != ['pending', 'rejected', 'pending', 'completed'] or not executor.model_done:
        raise ValueError('결정 전후 저장과 모델 멈춤 검사 실패')


async def dry_analysis_check(catalog):
    """Exercise reads, partial answers and dollar boundaries with local objects only."""
    from .model import number

    class Offline(Codex):
        def __init__(self, responses, ceiling=4, context_chars=16000):
            super().__init__('dry-run', None, Path(__file__).parent / '.dry-unused',
                             ceiling=number(ceiling), context_chars=context_chars)
            self.responses, self.seen = iter(responses), []

        def _call(self, purpose, prompt, context, schema, timeout):
            self.seen.append((purpose, context))
            self.spent += number('0.1')
            self.charge_stage(purpose, number('0.1'))
            answer = next(self.responses)
            if isinstance(answer, Exception):
                raise answer
            return answer

    deadline = time.monotonic() + 60
    buffers = {}
    reads = ReadMemory(buffers, 'dry-read')
    first = reads.read('A' * 6000, {'ref': 'provided-context', 'limit': 5000}, 16000)
    second = reads.read('B' * 6000, {'ref': 'provided-context', 'limit': 5000}, 16000)
    full = pack_context({'read_windows': reads.state()}, reads.entries(), buffers, 16000)
    small = pack_context({'read_windows': reads.state()}, reads.entries(), buffers, 3500)
    if ([row['value']['value'] for row in full['included_samples']] != ['B' * 5000, 'A' * 5000]
            or len(serialized(small)) > 3500 or len(small['read_windows']) != 2
            or reads.state()[1]['window_ref'] not in small['omitted_sample_refs']
            or sample_window(buffers[first['ref']], {'ref': first['ref'], 'offset': 5000, 'limit': 1000}, 16000)['value'] != 'A' * 1000
            or first['ref'] == second['ref']):
        raise ValueError('읽은 창 보존과 고정 원문 참조 검사 실패')
    reads.read('A' * 6000, {'ref': 'provided-context', 'limit': 5000}, 16000)
    if len(reads.state()) != 2 or reads.state()[0]['ref'] != first['ref']:
        raise ValueError('같은 창 재읽기 기록 갱신 실패')
    binary = reads.read(b'bytes' * 1000, {'ref': 'binary', 'limit': 5000}, 2048)
    reread = reads.read(buffers[binary['ref']], {'ref': binary['ref'], 'limit': binary['length'],
                                              'encoding': binary['encoding']}, 2048)
    if len(serialized(binary)) > 2048 or len(serialized(reread)) > 2048 or reread['encoding'] != 'base64':
        raise ValueError('고정 참조 메타데이터 또는 바이트 인코딩 창 상한 초과')

    group = catalog['call_order'][0]
    ids = list(group_schema(catalog, group)['properties'])
    template = empty_axes(catalog, 'dry-run local response')
    read_one = {'_read_sample': {'ref': 'offline-one', 'limit': 100}}
    read_two = {'_read_sample': {'ref': 'offline-two', 'limit': 100}, ids[0]: template[ids[0]]}
    final = {key: template[key] for key in ids}
    model = Offline([read_one, read_two, read_one, final])
    observer = Observer('http://example.invalid/', model, Budget(sample_chars=16000))
    observer.budget.begin()
    observer.buffers.update({'offline-one': 'first page', 'offline-two': 'second page'})
    answers, errors = await answer_group(model, observer, catalog, group, deadline)
    context = model.seen[2][1]
    windows = [row['value']['value'] for row in context['included_samples'] if row['ref'] in
               {window['window_ref'] for window in context['read_windows']}]
    if (windows != ['second page', 'first page'] or not context['preserved_answers']
            or 'group_budget' in context or len(model.seen) != 4 or set(answers) != set(ids)
            or errors or observer.feedback or model.stopped()):
        raise ValueError('축 읽기 기억, 부분 답 보존 또는 모델의 읽기 선택 검사 실패')
    model = Offline([ModelError('offline-format'), {}])
    await model.call('group_dry', '', {}, {}, deadline=deadline)
    retry_context = model.seen[1][1]
    if (number(retry_context['cost_budget']['spent_usd']) != number('0.1')
            or number(retry_context['cost_budget']['remaining_usd']) != number('3.9')):
        raise ValueError('교정 재시도의 전체 비용 정보 갱신 실패')
    model.spent = model.ceiling
    try:
        await model.call('group_dry', '', {}, {}, deadline=deadline)
    except ModelError as error:
        if error.code != 'cost_budget' or len(model.seen) != 2:
            raise
    else:
        raise ValueError('총 비용 상한 뒤 호출 허용')

    cells = [{'id': 'one', 'value': 'first cell'}, {'id': 'two', 'value': 'second cell'}]
    safe_one = {'id': 'one', 'safe': True, 'value': serialized('first cell')}
    model = Offline([
        {'_read_sample': {'ref': 'privacy:cell:one', 'limit': 1000}},
        {'fields': [safe_one], '_read_sample': {'ref': 'privacy:cell:two', 'limit': 1000}},
        {'fields': [{'id': 'two', 'safe': False, 'value': 'null'}]}])
    released, errors = await privacy_cells(model, cells, deadline)
    if (len(model.seen[2][1]['read_windows']) != 2 or released != {'one': 'first cell'}
            or errors != {'two': 'privacy_withheld'} or model.seen[2][1]['pending_cells'] != ['two']):
        raise ValueError('가림 읽기 창 또는 칸별 부분 답 보존 실패')
    model = Offline([{'fields': [safe_one]}, {'fields': [{'id': 'two', 'safe': True, 'value': serialized('second cell')}]}])
    released, errors = await privacy_cells(model, cells, deadline)
    if released != {'one': 'first cell', 'two': 'second cell'} or errors:
        raise ValueError('가림 실패 칸 격리 검사 실패')

    axes = [axis for axis in catalog['axes'] if axis['group'] == 'appearance'][:2]
    keys = [axis['id'] for axis in axes]
    reduced = {**catalog, 'groups': {'appearance': catalog['groups']['appearance']}, 'axes': axes}
    runs = [{'axes': {key: template[key] for key in keys}} for _ in range(2)]
    judgments = {key: {'agreement': True, 'answer': template[key]} for key in keys}
    model = Offline([
        {'_read_sample': {'ref': 'provided-context', 'limit': 100}},
        {keys[0]: judgments[keys[0]], '_read_sample': {'ref': 'merge:appearance:' + keys[1] + ':1', 'limit': 100}},
        judgments,
        {'fields': [{'id': 'merge-' + key, 'safe': True, 'value': serialized(template[key])} for key in keys]}])
    result = await semantic_merge(model, reduced, runs, deadline)
    context = model.seen[2][1]
    if (set(result) != set(keys) or any('error' in row for row in result.values())
            or len(context['read_windows']) != 2 or context['pending_axes'] != keys
            or 'merge:partial:appearance' not in {row['ref'] for row in context['sample_refs']}):
        raise ValueError('의미 합치기 읽기 창 또는 부분 답 보존 실패')
    if model.calls or model.directory.exists():
        raise ValueError('dry-run에서 모델 호출 또는 디렉터리 생성')

    # STRUCTURE-FIX: synthetic strings and local adapters, never origin results.
    found = find_text({'text': 'aaaa Aa', 'bytes': '한글 aa'.encode('utf-8')}, {'text': 'aa', 'max': 1})
    zero = find_text({'text': 'AAAA'}, {'text': 'aa'})
    if (found['total_count'] != 4 or found['results'][0]['offsets'] != [0]
            or found['results'][0]['count'] != 3 or not found['results'][0]['truncated']
            or found['results'][1]['offsets'] != [7] or found['results'][1]['unit'] != 'bytes'
            or zero['total_count'] != 0 or not zero['zero_matches']):
        raise ValueError('합성 찾기 위치, 겹침, 대소문자, 바이트 또는 0건 실패')

    complete = {key: template[key] for key in ids}
    partial = {**complete, ids[0]: {**template[ids[0]], 'final': False}}
    model = Offline([partial, {**complete, '_find': {'text': 'tail-token', 'refs': ['source-1']}},
                     {**complete, '_read_sample': {'ref': 'source-1', 'offset': 22000, 'limit': 100}}, complete])
    observer = Observer('http://example.invalid/', model, Budget(sample_chars=16000))
    observer.budget.begin()
    observer.buffers.update({'source-1': 'x' * 22000 + 'tail-token', 'screen-2': 'screen only'})
    observer.samples = [{'ref': 'sample-1', 'route': 'same-route', 'url': observer.origin, 'timestamp': now(),
                         'screen': {'status': '못 얻음'},
                         'source': {'status': '관찰됨', 'ref': 'source-1', 'original_size': 22010, 'truncated': True}},
                        {'ref': 'sample-2', 'route': 'same-route', 'url': observer.origin, 'timestamp': now(),
                         'source': {'status': '못 얻음'},
                         'screen': {'status': '관찰됨', 'ref': 'screen-2', 'original_size': 11, 'truncated': False}}]
    observer.attempts = [{'method': 'GET', 'url': observer.origin, 'route': 'same-route',
                          'sent': True, 'resource_type': 'document'}]
    observer.responses = [{'_private_request_ref': 'observation:request:1', 'status_code': {'value': 200},
                           'redirect_chain': {'value': ['same-route']},
                           'headers': {'value': [{'name': 'Content-Type', 'value': 'text/html'}, {'name': 'Set-Cookie', 'value': None}]},
                           'cookies': {'value': [{'name': 'synthetic-cookie'}]}}]
    observer.response_bodies = [{'route': 'same-route', 'ref': 'source-1', 'body': {'status': '관찰됨', 'retained_size': 22010, 'truncated': True}}]
    saved = {}
    answers, errors = await answer_group(model, observer, catalog, group, deadline, saved, run=7)
    first_context, partial_context, found_context, read_context = [context for _, context in model.seen]
    refs = {item['ref']: item for item in first_context['sample_refs']}
    index = json.loads(observer.observation_index().splitlines()[0])
    if (len(model.seen) != 4 or errors or not saved['complete'] or answers != complete
            or partial_context['pending_axes'] != [ids[0]] or partial_context['run'] != 7
            or found_context['correction']['find']['results'][0]['offsets'] != [22000]
            or read_context['read_windows'][0]['offset'] != 22000 or observer.feedback
            or first_context['included_samples'][0]['ref'] != 'observation:index'
            or refs['sample-1']['url'] != observer.origin or refs['sample-1']['body_refs'] != ['source-1']
            or refs['sample-1']['route_sample_count'] != 2 or refs['sample-1']['originals'][0]['total'] != 22010
            or refs['sample-1']['originals'][0]['retained'] != 22010 or not refs['sample-1']['originals'][0]['truncated']
            or index['header_names'] != ['Content-Type', 'Set-Cookie'] or index['set_cookie_names'] != ['synthetic-cookie']
            or index['route_bodies'][0]['retained_size'] != 22010
            or '_private_request_ref' in serialized(observer.publication())):
        raise ValueError('합성 색인, 표본 참조, final, 도구 우선순위 또는 중복 창 실패')
    # A later group receives no previous group windows or find feedback.
    following = Observer(observer.origin, model, Budget(sample_chars=16000))
    following.budget.begin()
    following.context_buffers = observer.context_buffers
    later = following.model_context(read_memory=ReadMemory(following.context_buffers, 'later'))
    if (later['read_windows'] or later['feedback'] or 'correction' in later
            or any(key.startswith('group-read:') for key in following.readable_sources())):
        raise ValueError('합성 다음 묶음 읽기 창 격리 실패')
    if observer.find({'text': 'tail-token', 'refs': ['sample-1', 'source-1']})['total_count'] != 1:
        raise ValueError('합성 표본과 원문 버퍼 식별자 분리 실패')

    original = {'description': 'private-token private-token', 'evidence': ['sample-1', {'token': 'private-token'}],
                'hash': 'abcd', 'status': '못 봄', 'count': 2}
    replacement = {'id': 'nested', 'safe': True, 'value': 'discarded',
                   'replacements': [{'find': 'private-token', 'replace': '{VALUE}'}]}
    model = Offline([{'fields': [replacement], '_find': {'text': 'private-token', 'refs': ['privacy:cell:nested']}}, {}])
    released, errors = await privacy_cells(model, [{'id': 'nested', 'value': original}], deadline)
    if (errors or released['nested']['description'] != '{VALUE} {VALUE}'
            or released['nested']['evidence'] != ['sample-1', {'token': '{VALUE}'}]
            or released['nested']['hash'] != 'abcd' or released['nested']['status'] != '못 봄'
            or released['nested']['count'] != 2 or len(model.seen) != 2
            or model.seen[1][1]['feedback']['find']['total_count'] != 3
            or model.seen[1][1]['read_windows']):
        raise ValueError('합성 치환 가림 우선순위 또는 찾기 피드백 실패')
    model = Offline([{'fields': [{'id': 'keep', 'safe': True}, {'id': 'empty', 'safe': True, 'replacements': []},
                                 {'id': 'hide', 'safe': False, 'replacements': []}]}])
    released, errors = await privacy_cells(model, [{'id': key, 'value': original} for key in ('keep', 'empty', 'hide')], deadline)
    if released != {'keep': original, 'empty': original} or errors != {'hide': 'privacy_withheld'}:
        raise ValueError('합성 가림 결정만 확인, 빈 치환 또는 비공개 실패')

    fake_keys = ['axis-' + str(i) for i in range(8)]
    tiny_runs = [{'axes': {key: 'small' for key in fake_keys}} for _ in range(2)]
    large_runs = [{'axes': {key: 'x' * 1500 for key in fake_keys}} for _ in range(2)]
    if len(merge_batch(fake_keys, tiny_runs, 16000)) != 6 or len(merge_batch(fake_keys, large_runs, 16000)) != 1:
        raise ValueError('합성 합치기 축 개수 또는 원문 크기 분할 실패')
    batch_axes = [{**axes[0], 'id': key} for key in fake_keys[:7]]
    batch_keys = [axis['id'] for axis in batch_axes]
    batch_catalog = {**catalog, 'groups': reduced['groups'], 'axes': batch_axes}
    batch_runs = [{'axes': {key: unavailable('synthetic batch') for key in batch_keys}} for _ in range(2)]
    responses = []
    for batch_keys_part in (batch_keys[:6], batch_keys[6:]):
        responses.extend([{key: {'agreement': True, 'answer': batch_runs[0]['axes'][key]} for key in batch_keys_part},
                          {'fields': [{'id': 'merge-' + key, 'safe': True} for key in batch_keys_part]}])
    model = Offline(responses)
    await semantic_merge(model, batch_catalog, batch_runs, deadline)
    if [len(context['pending_axes']) for purpose, context in model.seen if purpose.startswith('merge_')] != [6, 1]:
        raise ValueError('합성 합치기 실제 pending 호출 분할 실패')

    model = Offline([{'_find': {'text': 'second-tail', 'refs': ['run:1:source-1', 'run:2:source-1']}},
                     {'_read_sample': {'ref': 'run:2:source-1', 'offset': 21000, 'limit': 100}}, judgments,
                     {'fields': [{'id': 'merge-' + key, 'safe': True} for key in keys]}])
    observations = {}
    for run_number, text in ((1, 'first-tail'), (2, 'second-tail')):
        observed = Observer('http://example.invalid/', model, Budget(sample_chars=16000))
        observed.budget.begin()
        observed.buffers['source-1'] = 'x' * 21000 + text
        observed.attempts = [{'method': 'GET', 'url': observed.origin, 'sent': True, 'resource_type': 'document'}]
        observations[str(run_number)] = observed.snapshot()
    result = await semantic_merge(model, reduced, runs, deadline, observations=observations)
    context = model.seen[2][1]
    found_context = model.seen[1][1]
    if (set(result) != set(keys) or any('error' in row for row in result.values())
            or found_context['feedback']['find']['results'][0]['count'] != 0
            or found_context['feedback']['find']['results'][1]['offsets'] != [21000]
            or context['read_windows'][0]['requested_ref'] != 'run:2:source-1'
            or set(context['run_observations']) != {'1', '2'}
            or not all('observation_index_ref' in item['value'] for item in context['included_samples']
                       if item['ref'].startswith('merge:appearance:'))):
        raise ValueError('합성 합치기 회차 색인, 원문 찾기 또는 읽기 실패: ' + serialized({
            'result': result, 'find': found_context.get('feedback'), 'windows': context.get('read_windows'),
            'runs': list(context.get('run_observations', {})),
            'axis_items': [{'ref': item['ref'], 'has_index': 'observation_index_ref' in item['value']}
                           for item in context['included_samples'] if item['ref'].startswith('merge:appearance:')]}))
    browsing = Observer('http://example.invalid/', model, Budget())
    browsing.budget.begin()
    browsing.buffers['raw'] = 'literal'
    await browsing.action({'_find': {'text': 'missing', 'refs': ['raw']}})
    if not browsing.feedback[-1]['find']['zero_matches'] or browsing.read_memory.state():
        raise ValueError('합성 둘러보기 찾기 또는 읽은 창 분리 실패')
    from types import SimpleNamespace
    form = {'action': browsing.origin, 'method': 'GET', 'field_names': ['synthetic-field']}
    class Locator:
        async def click(self, **unused):
            browsing.page.url = browsing.origin + '#synthetic-view'
        async def evaluate(self, expression, **unused):
            return form
    browsing.page = SimpleNamespace(url=browsing.origin, locator=lambda selector: Locator())
    await browsing.action({'tool': 'click', 'args': {'selector': '#synthetic'}, 'read_only': True,
                           'human_confirmation': False})
    await browsing.action({'tool': 'inspect_form', 'args': {'selector': '#synthetic'}, 'read_only': True,
                           'human_confirmation': False})
    browsing.attempts = [{'url': browsing.origin, 'resource_type': 'document', 'sent': True},
                         {'url': browsing.origin, 'resource_type': 'document', 'sent': True},
                         {'url': browsing.origin, 'resource_type': 'document', 'sent': False},
                         {'url': browsing.origin, 'resource_type': 'fetch', 'sent': True}]
    browsing.navigations = [{'url': browsing.page.url}] * 10
    context = browsing.model_context()
    if (browsing.feedback[-2]['operation'] != 'click' or browsing.feedback[-2]['url'] != browsing.page.url
            or browsing.feedback[-1]['result'] != form or context['visited_urls'] != [{'url': browsing.origin, 'count': 2}]):
        raise ValueError('합성 click, inspect_form 피드백 또는 실제 문서 요청 집계 실패')

    # Oversized indexes remain readable and do not consume every inline slot.
    buffers = {}
    packed = pack_context({}, [('index', 'observation_index', 'line\n' * 5000), ('sample', 'samples', {'route': 'r'})],
                          buffers, 4096)
    if (not packed['included_samples'][0]['truncated'] or len(serialized(packed)) > 4096
            or not any(item['ref'] == 'sample' for item in packed['included_samples'])
            or find_text(buffers, {'text': 'line', 'refs': ['index'], 'max': 2})['results'][0]['count'] != 5000):
        raise ValueError('합성 큰 색인 창과 전체 참조 보존 실패')
    model = Offline([partial, ModelError('cost_budget')])
    observer = Observer('http://example.invalid/', model, Budget(sample_chars=16000))
    observer.budget.begin()
    saved = {}
    _, errors = await answer_group(model, observer, catalog, group, deadline, saved)
    if saved['complete'] or saved['provisional_axes'] != [ids[0]] or errors != {ids[0]: 'cost_budget'}:
        raise ValueError('합성 부분 답과 중단 상태 저장 실패')
    resumed = Offline([complete])
    observer.model = resumed
    restored = restored_copy(saved)
    _, errors = await answer_group(resumed, observer, catalog, group, deadline, restored)
    if errors or not restored['complete'] or resumed.seen[0][1]['pending_axes'] != [ids[0]]:
        raise ValueError('합성 final=false 답의 재개 실패')


async def dry_resume_check(catalog):
    """Crash/restart stage checks use the JSON codec and memory writes only."""
    from .model import number, price
    from .resume import encode, identity
    from unittest.mock import patch

    class MemoryStore(ResumeStore):
        def __init__(self):
            super().__init__(Path(__file__).with_name('resume-dry-unused.json'), 'http://example.invalid/', catalog, True)
            self.state['session'] = 'dry-run'
            self.files = {}
        def write(self, name, value, tagged=False):
            self.files[name] = restored_copy(value)

    class Offline(Codex):
        def __init__(self, store, saved=None, interrupt=False):
            super().__init__('dry-run', None, Path(__file__).parent / '.dry-unused', ceiling=number(100))
            self.sent, self.privacy_count, self.interrupt = [], 0, interrupt
            if saved:
                self.restore(saved, store.state.get('acknowledged_calls', 0))
            self.checkpoint = store.save_ledger
        def _call(self, purpose, prompt, context, schema, timeout):
            if purpose == 'publication_privacy':
                self.privacy_count += 1
                if self.interrupt and self.privacy_count == 2:
                    raise asyncio.CancelledError()
                cells = [item['value'] for item in context['included_samples']
                         if item['ref'].startswith('privacy:cell:')]
                if self.interrupt:
                    cells = cells[:1]
                answer = {'fields': [{'id': cell['id'], 'safe': True, 'value': serialized(cell['value'])}
                                     for cell in cells]}
            elif purpose.startswith('merge_'):
                answer = {key: {'agreement': True, 'answer': template[key]} for key in schema['properties']}
            else:
                answer = {key: template[key] for key in schema['properties']}
            self.sent.append(purpose)
            self.spent += number('0.1')
            self.charge_stage(purpose, number('0.1'))
            self.calls.append({'purpose': purpose, 'usd': '0.1', 'total_usd': str(self.spent)})
            self.pending_answer = {'purpose': purpose, 'call_index': len(self.calls), 'answer': answer}
            self.receipt_delivered = False
            self.persist()
            return answer

    store = MemoryStore()
    template = empty_axes(catalog, 'dry-run local answer')
    args = parser().parse_args(['--origin-url', 'http://example.invalid/', '--out', str(store.path / 'unused.json'), '--runs', '1'])
    limits = {'requests': 20, 'pages': 10, 'seconds': 60, 'sample_chars': 600000}
    model = Offline(store, interrupt=True)
    original_run = Observer.run
    browsed = []
    async def observe(observer):
        browsed.append(True)
        body = observer.store_body(b'\x00\xff' + '한글 원문'.encode('utf-8'), ref(observer.origin))
        observer.response_bodies.append(body)
        observer.context_buffers['unpublished'] = 'private source retained'
        observer.model_done = True
        observer.model_context()
    async def publish(run):
        # No file output. Check that the public shape cannot contain raw buffers.
        if 'private source retained' in serialized(run) or 'buffers' in run:
            raise ValueError('비공개 원자료가 공개 기록에 섞임')
    Observer.run = observe
    try:
        try:
            await one_run(1, args, catalog, limits, model, {}, publish, store)
        except asyncio.CancelledError:
            pass
        else:
            raise ValueError('중단 재개 검사의 중단 지점에 도달하지 않음')
        saved = restored_copy(store.files['state.json'])
        ledger = restored_copy(store.files['ledger.json'])
        if (store.plan(catalog, 1)['stage'] != 'privacy'
                or len(saved['runs']['1']['privacy']['axis:' + catalog['call_order'][0]]['released']) != 1
                or saved['runs']['1']['observation']['fields']['buffers']['response-1'] != b'\x00\xff' + '한글 원문'.encode('utf-8')):
            raise ValueError('관찰 원바이트 또는 완료한 가림 칸 저장 실패')
        store.state = saved
        resumed = Offline(store, ledger)
        before = resumed.spent
        await one_run(1, args, catalog, limits, resumed, {}, publish, store)
        if (browsed != [True] or any(purpose.startswith('group_') for purpose in resumed.sent)
                or not store.state['runs']['1']['complete'] or resumed.spent <= before
                or resumed.analysis_spent != model.analysis_spent):
            raise ValueError('완료한 둘러보기, 축 분석 또는 비용 이월 검사 실패')
        count = len(resumed.sent)
        await one_run(1, args, catalog, limits, resumed, {}, publish, store)
        if len(resumed.sent) != count:
            raise ValueError('완료 회차를 다시 호출함')
        # Exercise the real read-only loader, including --fresh and identity
        # mismatch, using exactly the encoded content an atomic write produces.
        manifest, ledger_path = store.path / 'state.json', store.path / 'ledger.json'
        documents = {manifest: json.dumps(encode(restored_copy(store.state)), ensure_ascii=False),
                     ledger_path: json.dumps(store.files['ledger.json'], ensure_ascii=False)}
        original_exists, original_read = Path.exists, Path.read_text
        def exists(path):
            return True if path in documents else original_exists(path)
        def read(path, *positional, **options):
            return documents[path] if path in documents else original_read(path, *positional, **options)
        output = Path(__file__).with_name('resume-dry-unused.json')
        with patch.object(Path, 'exists', exists), patch.object(Path, 'read_text', read):
            loaded = ResumeStore(output, args.origin_url, catalog)
            different = ResumeStore(output, 'http://different.invalid/', catalog)
            changed_axes = ResumeStore(output, args.origin_url, {**catalog, 'axes': catalog['axes'][:-1]})
            fresh = ResumeStore(output, args.origin_url, catalog, True)
        if (loaded.reason != 'resume' or loaded.plan(catalog, 1)['stage'] != 'semantic_merge'
                or number(loaded.ledger['spent_usd']) != resumed.spent
                or different.state['runs'] or changed_axes.state['runs']
                or fresh.reason != 'fresh' or fresh.ledger is not None or fresh.state['runs']):
            raise ValueError('저장 파일 읽기, 새 시작 또는 비용 장부 연결 실패')

        # An expired browse clock leaves analysis and privacy windows available.
        timed_store = MemoryStore()
        timed_model = Offline(timed_store)
        async def expired_observation(observer):
            await observe(observer)
            observer.samples.append({'ref': 'timed-screen', 'timestamp': now(), 'url': observer.origin,
                                     'route': ref(observer.origin), 'screen': {'status': '못 얻음'},
                                     'source': {'status': '관찰됨', 'value': 'retained source'}})
            observer.budget.started -= limits['seconds'] + 1
        Observer.run = expired_observation
        await one_run(1, args, catalog, limits, timed_model, {}, publish, timed_store)
        if (not any(purpose.startswith('group_') for purpose in timed_model.sent)
                or 'publication_privacy' not in timed_model.sent
                or not timed_store.state['runs']['1']['complete']):
            raise ValueError('둘러보기 시간 소진 뒤 독립 분석 및 가림 시간 검사 실패')
    finally:
        Observer.run = original_run

    axes = catalog['axes'][:2]
    group = axes[0]['group']
    reduced = {**catalog, 'axes': [axis for axis in axes if axis['group'] == group],
               'groups': {group: catalog['groups'][group]}}
    runs = [{'axes': {axis['id']: template[axis['id']] for axis in reduced['axes']}} for _ in range(2)]
    merging = Offline(store, interrupt=True)
    merge_state = {}
    async def save_merge():
        store.state['merge'] = merge_state
        store.save(merging)
    try:
        await semantic_merge(merging, reduced, runs, time.monotonic() + 60, merge_state, save_merge, 60)
    except asyncio.CancelledError:
        pass
    restored_merge = restored_copy(store.state['merge'])
    raw_count = len(restored_merge['raw'])
    continuing = Offline(store, restored_copy(store.files['ledger.json']))
    async def continue_merge():
        store.state['merge'] = restored_merge
        store.save(continuing)
    await semantic_merge(continuing, reduced, runs, time.monotonic() + 60, restored_merge, continue_merge, 60)
    if (raw_count != len(reduced['axes']) or not restored_merge['complete']
            or any(purpose.startswith('merge_') for purpose in continuing.sent)):
        raise ValueError('완료한 의미 비교 또는 합친 답 가림 재개 실패')

    # A receipt saved before stage consumption is replayed even at the ceiling.
    receipt_model = Offline(store)
    receipt = receipt_model.resume_record()
    receipt.update(spent_usd='100', pending_answer={'call_index': 1, 'purpose': 'group_receipt', 'answer': {'saved': True}},
                   calls=[{'purpose': 'group_receipt', 'usd': '100'}])
    receipt_model.restore(receipt)
    result = await receipt_model.call('group_receipt', '', {}, {}, deadline=time.monotonic() - 1)
    if result != {'saved': True} or receipt_model.sent or receipt_model.spent != number(100):
        raise ValueError('지급된 미소비 답 또는 비용 상한 복원 실패')
    store.save(receipt_model)
    if receipt_model.pending_answer is not None:
        raise ValueError('소비한 호출 답의 원자적 확인 실패')
    receipt_model.restore(receipt, acknowledged=1)
    try:
        await receipt_model.call('group_receipt', '', {}, {})
    except ModelError as error:
        if error.code != 'cost_budget':
            raise
    else:
        raise ValueError('재개 뒤 전체 비용 상한 우회')
    interrupted = receipt_model.resume_record()
    interrupted.update(spent_usd='0', browse_spent_usd='0', analysis_spent_usd='0', calls=[
        {'purpose': 'navigation', 'usd': None, 'inflight': True,
         'estimate_usage': {'input_tokens': 100, 'output_tokens': 16000}}], pending_answer=None)
    receipt_model.rate = {'base': {'input': 1, 'cached_input': 0, 'output': 1}}
    receipt_model.restore(interrupted)
    estimate = price(receipt_model.rate, interrupted['calls'][0]['estimate_usage'])
    if receipt_model.spent != estimate or receipt_model.browse_spent != estimate or not receipt_model.calls[0]['usd_estimated']:
        raise ValueError('강제 종료 호출 비용 추정 복원 실패')
    first = identity(args.origin_url, catalog, args.out)
    if (first == identity('http://different.invalid/', catalog, args.out)
            or first == identity(args.origin_url, {**catalog, 'axes': catalog['axes'][:-1]}, args.out)):
        raise ValueError('다른 원본이나 축 목록 재개 경계 실패')
    if model.directory.exists():
        raise ValueError('dry-run에서 모델 디렉터리를 생성함')


async def dry_wide_check(catalog):
    """Boundary/recovery checks, using local objects and memory only."""
    from types import SimpleNamespace
    from unittest.mock import patch
    from .resume import checkpoint_path

    class Offline(Codex):
        def __init__(self):
            super().__init__('dry-run', None, Path(__file__).parent / '.dry-unused',
                             rate={'base': {'input': 1, 'cached_input': 0, 'output': 1}}, ceiling=number(1))
            self.seen = []
        def _call(self, purpose, prompt, context, schema, timeout):
            self.seen.append((purpose, context))
            self.spent += number('0.01')
            self.charge_stage(purpose, number('0.01'))
            return {key: empty_axes(catalog, 'offline')[key] for key in schema.get('properties', {})
                    if key in empty_axes(catalog, 'offline')}

    model = Offline()
    model.spent = model.analysis_spent = number('0.99')
    await model.call('group_guard', '', {}, {})
    if len(model.seen) != 1 or not model.stopped():
        raise ValueError('전체 상한 전 추정 비용으로 호출을 차단하거나 상한 뒤 중단하지 않음')
    model = Offline()
    model.spent = model.analysis_spent = number('0.2')
    await model.call('group_guard', '', {}, {})
    await model.call('publication_privacy', '', {}, {})
    await model.call('merge_guard', '', {}, {})
    if (len(model.seen) != 3 or model.privacy_spent != number('0.01')
            or model.merge_spent != number('0.01') or model.stopped()):
        raise ValueError('단계별 사용액 기록 또는 공통 전체 상한 검사 실패')
    payload = model.payload('schema accounting', {}, {'large': '한글' * 1000})
    if model.estimate(payload)['input_tokens'] != len(payload):
        raise ValueError('봉투 및 스키마 비용 추정 누락')
    from .model import claude_receipt, decode_answer
    receipt, billed = claude_receipt(serialized({'total_cost_usd': '0.12', 'usage': {},
                      'modelUsage': {'actual-model-id': {}}, 'result': '{"saved": true}'}))
    if billed != number('0.12') or decode_answer([receipt['result']]) != {'saved': True}:
        raise ValueError('Claude 봉투와 실제 비용 읽기 실패')

    model = Offline()
    group = catalog['call_order'][0]
    schema = group_schema(catalog, group)
    key = next(iter(schema['properties']))
    observer = Observer('https://example.invalid/', model, Budget())
    observer.budget.begin()
    state = {'answers': {key: empty_axes(catalog, 'saved')[key]}}
    await answer_group(model, observer, catalog, group, time.monotonic() - 1, state)
    if state['complete'] or model.seen or key not in state['answers']:
        raise ValueError('답 없는 시간 초과를 완료로 저장함')
    await answer_group(model, observer, catalog, group, time.monotonic() + 10, state)
    if not state['complete'] or len(model.seen) != 1 or key in model.seen[0][1]['pending_axes']:
        raise ValueError('시간 초과 재개에서 정상 축 보존 실패')
    observer.error('failed-item', ValueError('offline'))
    for _ in range(observer.failures.limit):
        observer.error('failed-item', ValueError('offline'))
    if model.stopped():
        raise ValueError('국소 실패가 전체를 중단함')

    # Same-host iframe/fetch pass; foreign origins/ports never pass routing.
    class Route:
        sent = aborted = False
        async def continue_(self): self.sent = True
        async def abort(self): self.aborted = True
    for resource in ('script', 'image', 'fetch', 'document'):
        for url, permitted in (('https://example.invalid/same', True),
                               ('https://cdn.invalid/foreign', False),
                               ('https://example.invalid:8443/foreign', False)):
            route = Route()
            await observer.route(route, SimpleNamespace(url=url, method='GET', resource_type=resource,
                         is_navigation_request=lambda: resource == 'document', frame=SimpleNamespace(parent_frame=object())))
            if route.sent != permitted or route.aborted == permitted:
                raise ValueError('외부 하위 요청 경계 실패')
    observer.model_done = True
    route = Route()
    await observer.route(route, SimpleNamespace(url=observer.origin, method='GET', resource_type='fetch',
                                                is_navigation_request=lambda: False))
    if not route.aborted:
        raise ValueError('모델 멈춤 뒤 자동 요청 전송')
    for flag in ('true', 1, None):
        await observer.action({'tool': 'stop', 'args': {}, 'read_only': True,
                               'human_confirmation': flag, 'reason': 'offline'})
        if observer.human_gate or not observer.model_done:
            raise ValueError('명시적인 모델 플래그 비교 실패')

    # Body source generates data on demand; no large attachment is allocated.
    class Response:
        code, headers = 200, {}
        closed, read_bytes = False, 0
        def read1(self, count):
            self.read_bytes += count
            return b'A' * count
        def close(self): self.closed = True
    response = Response()
    capture = Observer('https://example.invalid/', model, Budget(), body_bytes=32, retained_bytes=64, stream_messages=2)
    capture.budget.begin()
    capture.http_fetch(SimpleNamespace(open=lambda *a, **k: response), capture.origin)
    if (not response.closed or response.read_bytes != 32 or capture.retained_size != 32
            or not capture.response_bodies[0]['body']['capture_truncated']):
        raise ValueError('HTTP 스트림 보관 상한 실패')
    capture.store_body(b'B' * 128, ref(capture.origin))
    if capture.retained_size != 64:
        raise ValueError('원문 전체 보관 상한 실패')
    class Socket:
        def __init__(self, url): self.url, self.connected, self.closed = url, False, False
        async def close(self): self.closed = True
        def connect_to_server(self):
            self.connected = True
            return self
        def on_message(self, handler): self.handler = handler
        def send(self, value): pass
    socket = Socket('wss://foreign.invalid/socket')
    await capture.websocket(socket)
    if socket.connected or not socket.closed:
        raise ValueError('외부 WebSocket 연결 차단 실패')
    capture.retained_size = 0
    socket = Socket('wss://example.invalid/socket')
    await capture.websocket(socket)
    for _ in range(10): socket.handler('stream')
    if len(capture.realtime[-1]['received']) != 2 or capture.realtime[-1]['omitted_messages'] != 8:
        raise ValueError('WebSocket 수신 보관 상한 실패')
    await capture.action({'tool': 'stop', 'args': {}, 'read_only': True,
                          'human_confirmation': True, 'reason': 'offline'})
    if not socket.closed:
        raise ValueError('사람 확인 멈춤 뒤 연결을 유지함')
    import base64
    class Session:
        def __init__(self): self.handlers = {}
        async def send(self, command, args=None):
            return {'bufferedData': base64.b64encode(b'abc').decode('ascii')} if command == 'Network.streamResourceContent' else {}
        def on(self, event, handler): self.handlers[event] = handler
    session = Session()
    streamed = Observer(capture.origin, model, Budget(), body_bytes=32, retained_bytes=64)
    streamed.budget.begin()
    async def new_session(page): return session
    streamed.browser_context = SimpleNamespace(new_cdp_session=new_session)
    await streamed.capture_session(object())
    session.handlers['Network.responseReceived']({'requestId': 'one', 'response': {'url': streamed.origin}})
    await streamed.drain()
    session.handlers['Network.dataReceived']({'requestId': 'one', 'data': base64.b64encode(b'x' * 128).decode('ascii')})
    session.handlers['Network.loadingFinished']({'requestId': 'one'})
    if (streamed.retained_size != 32 or streamed.active_bodies
            or streamed.response_bodies[0]['body']['original_size'] != 131
            or not streamed.response_bodies[0]['body']['capture_truncated']):
        raise ValueError('브라우저 스트림 부분 보관 또는 크기 기록 실패')
    memory = ReadMemory({}, 'bounded', retained_bytes=1024, max_windows=1)
    memory.read('12345', {'ref': 'one', 'limit': 5}, 1024)
    try:
        memory.read('x' * 1025, {'ref': 'two', 'limit': 5}, 1024)
    except ValueError:
        pass
    else:
        raise ValueError('읽기 원문 보관 한도 초과')

    with patch.dict(os.environ, {key: value for key, value in os.environ.items() if key != 'LOCALAPPDATA'}, clear=True):
        first = checkpoint_path(Path(__file__).parent / 'first' / 'same.json', 'https://example.invalid/')
        second = checkpoint_path(Path(__file__).parent / 'second' / 'same.json', 'https://example.invalid/')
        other = checkpoint_path(Path(__file__).parent / 'first' / 'same.json', 'https://other.invalid/')
        if not first.is_absolute() or len({first, second, other}) != 3:
            raise ValueError('저장 위치 OS 대안 또는 절대 경로 분리 실패')

    # Archive recovery operates on an in-memory filesystem, including a crash
    # after one move; no actual lock, permission or private write is executed.
    from . import resume as resume_module
    store = ResumeStore(Path(__file__).with_name('archive-dry-unused.json'), capture.origin, catalog, True)
    plan = {'folder': 'archive-dry', 'files': ['state.json', 'ledger.json', 'group.json']}
    documents = {store.path / name for name in [*plan['files'], 'archive-progress.json']}
    moved = []
    def replace(path, target):
        if len(moved) == 1:
            moved.append('interrupted')
            raise OSError('offline crash')
        documents.remove(path)
        documents.add(target)
        moved.append(path.name)
        return target
    with patch.object(Path, 'exists', lambda path: path in documents), \
         patch.object(Path, 'is_symlink', lambda path: False), \
         patch.object(Path, 'mkdir', lambda *a, **k: None), \
         patch.object(Path, 'replace', replace), \
         patch.object(Path, 'unlink', lambda path: documents.remove(path)), \
         patch.object(resume_module, 'owner_only', lambda path: None):
        try:
            store.finish_archive(plan)
        except OSError:
            pass
        else:
            raise ValueError('보관 중단 지점 미실행')
        store.finish_archive(plan)
    if (documents != {store.path / plan['folder'] / name for name in plan['files']}
            or moved[-1] != 'state.json'):
        raise ValueError('중단된 보관의 파일 목록 복구 실패')


async def dry_cost_context_check(catalog):
    """Check common cost information and local failure limits without providers."""
    args = parser().parse_args(['--origin-url', 'http://example.invalid/', '--out',
                               str(Path(__file__).with_name('cost-dry-unused.json'))])
    state = {'runs': {}, 'merge': {}}
    class Offline(Codex):
        def __init__(self):
            super().__init__('dry-run', None, Path(__file__).parent / '.dry-unused',
                             ceiling=number(1), failure_limit=2)
            self.remaining_stages = lambda: remaining_work(args, catalog, state)
            self.seen = []
        def _call(self, purpose, prompt, context, schema, timeout):
            budget = context['cost_budget']
            if (budget != self.cost_record() or 'stage_budgets' in budget
                    or number(budget['remaining_usd']) != self.ceiling - self.spent):
                raise ValueError('모든 호출의 공통 비용 문맥 또는 잔액 오류')
            self.seen.append((purpose, budget))
            self.spent += number('0.1')
            self.charge_stage(purpose, number('0.1'))
            self.calls.append({'purpose': purpose, 'usd': '0.1', 'usd_estimated': True})
            if purpose == 'group_failure':
                raise ModelError('offline_failure')
            return {}
    model = Offline()
    for purpose in ('navigation', 'group_axes', 'publication_privacy', 'merge_axes'):
        await model.call(purpose, '', {}, {})
    averages = model.cost_record()['recent_average_call_usd_by_stage']
    if any(row != {'usd': '0.1', 'call_count': 1, 'includes_estimates': True} for row in averages.values()):
        raise ValueError('단계별 평균 호출 비용 또는 추정 표시 오류')
    ahead = model.seen[0][1]['remaining_stages']
    if (len([row for row in ahead if row['stage'] == 'browse']) != 2
            or sum(row['group_count'] for row in ahead if row['stage'] == 'analysis') != 2 * len(catalog['call_order'])
            or sum(row['axis_cells'] for row in ahead if row['stage'] == 'privacy') != 2 * len(catalog['axes'])
            or ahead[-1]['stage'] != 'merge'):
        raise ValueError('앞으로 남은 회차, 묶음, 가림과 합치기 정보 오류')
    try:
        await model.call('group_failure', '', {}, {})
    except ModelError as error:
        if error.code != 'offline_failure':
            raise
    else:
        raise ValueError('반복 실패를 성공으로 처리함')
    before = len(model.seen)
    try:
        await model.call('group_failure', '', {}, {})
    except ModelError as error:
        if error.code != 'same_failure_limit' or len(model.seen) != before:
            raise
    else:
        raise ValueError('같은 작업의 반복 실패 상한 누락')
    await model.call('group_other', '', {}, {})
    if model.stopped() or len(model.seen) != before + 1:
        raise ValueError('국소 실패가 독립 작업을 중단함')
    model.spent = model.ceiling
    try:
        await model.call('publication_privacy', '', {}, {})
    except ModelError as error:
        if error.code != 'cost_budget' or len(model.seen) != before + 1:
            raise
    else:
        raise ValueError('전체 비용 상한 뒤 호출 허용')


async def dry_saved_groups(args, catalog, limits, store, rate, ceiling):
    """Replay saved groups with local answers and the current total-only budget."""
    working = deepcopy(store.state)
    class Offline(Codex):
        def __init__(self):
            super().__init__(args.model, args.model_timeout, Path(__file__).parent / '.dry-unused',
                             rate=rate, ceiling=ceiling, context_chars=args.context_chars)
            self.restore(deepcopy(store.ledger), store.state.get('acknowledged_calls', 0),
                         ceiling_override=ceiling if args.max_cost_usd is not None else None)
            self.remaining_stages = lambda: remaining_work(args, catalog, working)
            self.seen = []
        def _call(self, purpose, prompt, context, schema, timeout):
            if 'group_budget' in context or 'stage_budgets' in context['cost_budget']:
                raise ValueError('저장 상태의 과거 몫이 호출 문맥에 남음')
            self.seen.append({'purpose': purpose, 'context_chars': len(serialized(context)),
                              'cost_budget': context['cost_budget']})
            self.spent += number('0.01')
            self.charge_stage(purpose, number('0.01'))
            self.calls.append({'purpose': purpose, 'usd': '0.01', 'usd_estimated': False})
            return {key: unavailable('dry-run local answer') for key in schema['properties']}

    restored = Offline()
    budget = restored.cost_record()
    rows = []
    for index, mode in run_specs(args):
        run = working['runs'].get(str(index), {})
        pending = [group for group in catalog['call_order'] if not run.get('groups', {}).get(group, {}).get('complete')]
        row = {'run': index, 'authority': mode, 'observation_complete': bool(run.get('observation_complete')),
               'pending_groups': pending, 'local_group_attempts': []}
        if run.get('observation_complete') and run.get('observation'):
            observer = Observer(args.origin_url, restored, Budget(**limits),
                                axis_questions=[{'id': axis['id'], 'question': axis['question']} for axis in catalog['axes']],
                                session_file=args.session_file if mode == 'session' else None)
            observer.budget.begin()
            observer.restore(deepcopy(run['observation']))
            for group in pending:
                saved = run.setdefault('groups', {}).setdefault(group, {})
                before = len(restored.seen)
                await answer_group(restored, observer, catalog, group, time.monotonic() + 60, saved)
                row['local_group_attempts'].append({'group': group, 'complete': saved['complete'],
                    'local_invocations': len(restored.seen) - before,
                    'error_codes': sorted(set(saved['errors'].values())),
                    'last_call': restored.seen[-1] if len(restored.seen) > before else None})
        rows.append(row)
    return {'cost_budget': budget, 'runs': rows,
            'note': 'Local substitute responses verify resume routing; no provider calls or checkpoint writes.'}


async def dry_fix4_check(catalog):
    """Exercise real reservation/repacking paths and global publication order offline."""
    from unittest.mock import patch
    from contextlib import redirect_stdout
    from io import StringIO
    class Offline(Codex):
        def __init__(self, answer=None):
            super().__init__('dry-run', None, Path(__file__).parent / '.dry-unused',
                             rate={'base': {'input': 2, 'cached_input': 0, 'output': 10}}, ceiling=number(25),
                             context_chars=16000)
            self.answer, self.seen = answer, []
        def _call(self, purpose, prompt, context, schema, timeout):
            self.seen.append(context)
            if len(serialized(context)) > self.context_chars:
                raise ValueError('갱신된 축 문맥이 창을 넘음')
            self.spent += number('0.1')
            self.charge_stage(purpose, number('0.1'))
            answer = self.responses.pop(0) if hasattr(self, 'responses') else self.answer
            if isinstance(answer, Exception):
                raise answer
            return answer if answer is not None else {key: unavailable('offline') for key in schema['properties']}

    group = catalog['call_order'][0]
    ids = list(group_schema(catalog, group)['properties'])
    model = Offline()
    model.responses = [ModelError('offline-format'), {'_read_sample': {'ref': 'kept', 'limit': 10}}, None]
    observer = Observer('http://example.invalid/', model, Budget(sample_chars=16000))
    observer.budget.begin()
    observer.buffers['kept'] = 'retained evidence'
    observer.samples.append({'source': {'value': '"\
' * 20000}, 'route': ref('offline')})
    _, errors = await answer_group(model, observer, catalog, group, time.monotonic() + 60)
    if (errors or len(model.seen) != 3 or not model.seen[1].get('correction')
            or number(model.seen[1]['cost_budget']['spent_usd']) != number('0.1')
            or observer.feedback or not model.seen[2]['read_windows']):
        raise ValueError('교정 예산 정보 갱신, 창 보존 또는 추가 읽기 선택 실패')
    for reason in ('time_budget', 'cost_budget', 'cost_usage_unknown'):
        model = Offline()
        if reason == 'cost_budget':
            model.spent = model.ceiling
        elif reason == 'cost_usage_unknown':
            model.usage_unknown = True
        observer = Observer('http://example.invalid/', model, Budget())
        deadline = time.monotonic() - 1 if reason == 'time_budget' else time.monotonic() + 60
        _, errors = await answer_group(model, observer, catalog, group, deadline)
        if model.seen or set(errors.values()) != {reason}:
            raise ValueError('전체 비용, 시간 또는 사용량 미확인 경계를 넘음: ' + reason)

    class MemoryStore(ResumeStore):
        def __init__(self, args):
            super().__init__(args.out, args.origin_url, catalog, True)
            self.state['session'] = 'dry-run'
        def write(self, name, value, tagged=False):
            pass
    seen = []
    class PublicationOffline(Codex):
        def _call(self, purpose, prompt, context, schema, timeout):
            cells = [item['value'] for item in context.get('included_samples', [])
                     if item['ref'].startswith('privacy:cell:')]
            seen.append((purpose, [cell['id'] for cell in cells]))
            self.spent += number('0.01')
            self.charge_stage(purpose, number('0.01'))
            if purpose == 'publication_privacy':
                return {'fields': [{'id': cell['id'], 'safe': True, 'value': serialized(cell['value'])} for cell in cells]}
            if purpose.startswith('merge_'):
                return {key: {'agreement': True, 'answer': unavailable('offline')} for key in schema['properties']}
            # Leave one group unfinished to check that publication never retries analysis.
            if purpose == 'group_' + catalog['call_order'][-1]:
                return {'_read_sample': {'ref': 'missing', 'limit': 10}}
            return {key: unavailable('offline') for key in schema['properties']}
    async def observe(observer):
        observer.model_done = True
        observer.current_http_url = observer.origin
        observer.navigations.append({'url': observer.origin, 'route': ref(observer.origin), 'top_level': True})
    args = parser().parse_args(['--origin-url', 'http://example.invalid/', '--out',
                               str(Path(__file__).with_name('fix4-dry-unused.json')), '--rates', 'unused', '--runs', '2'])
    # Exercise publication order after independent group failures.
    with patch(__name__ + '.Codex', PublicationOffline), patch.object(Observer, 'run', observe), \
         patch(__name__ + '.cost_settings', lambda *a: ({'base': {'input': 2, 'cached_input': 0, 'output': 10}}, number(25))), \
         patch(__name__ + '.write_json', lambda *a, **k: None), redirect_stdout(StringIO()):
        store = MemoryStore(args)
        await execute_locked(args, catalog, args.out, {'requests': 20, 'pages': 10, 'seconds': 60, 'sample_chars': 600000}, store)
    groups = [purpose for purpose, _ in seen if purpose.startswith('group_')]
    privacy = [ids for purpose, ids in seen if purpose == 'publication_privacy']
    fact_positions = [i for i, ids in enumerate(privacy) if any(not key.startswith('axis-') for key in ids)]
    axis_positions = [i for i, ids in enumerate(privacy) if any(key.startswith('axis-') for key in ids)]
    if (len(set(groups)) != len(catalog['call_order']) or not fact_positions or not axis_positions
            or min(fact_positions) <= max(axis_positions)):
        raise ValueError('두 회차 축 가림 우선순위 검사 실패: ' + serialized(
            {'group_calls': len(groups), 'fact_positions': fact_positions, 'axis_positions': axis_positions,
             'run_errors': store.state.get('record', {}).get('run_errors')}))


async def dry_session_notes_check(catalog):
    """Synthetic replies and in-memory storage only; never provider observations."""
    from contextlib import redirect_stdout, redirect_stderr
    from io import StringIO
    from unittest.mock import patch
    from .resume import encode, identity
    catalog = {**catalog, 'axes': [next(axis for axis in catalog['axes'] if axis['group'] == group)
                                   for group in catalog['groups']]}
    session_file = session_path(Path(os.environ['LOCALAPPDATA']) / 'ruby-site-analysis' / 'sessions' / 'synthetic-unused.json')
    args = parser().parse_args(['--origin-url', 'http://example.invalid/', '--out',
                               str(Path(__file__).with_name('session-dry-unused.json')),
                               '--runs', '2', '--session-runs', '2', '--session-file', str(session_file)])
    limits = {'requests': 20, 'pages': 10, 'seconds': 60, 'sample_chars': 600000}
    template = empty_axes(catalog, 'synthetic observation')
    labels = ['both-runs', 'single-run', 'contradictory']
    for answer in template.values():
        answer.update(status='관찰됨', findings=[{'support': label, 'description': 'synthetic shape'} for label in labels])
        check_answer(answer)
    seen, outputs, restored_notes = [], [], []
    original_note = 'opened /{item-slug}; synthetic-sensitive-note'
    public_note = 'opened /{item-slug}; unopened kind lacks a safe observed link'

    class MemoryStore(ResumeStore):
        def __init__(self):
            super().__init__(args.out, args.origin_url, catalog, True)
            self.state['session'] = 'synthetic'
            self.files = {}
        def write(self, name, value, tagged=False):
            self.files[name] = restored_copy(value)

    class Offline(Codex):
        def _call(self, purpose, prompt, context, schema, timeout):
            seen.append((purpose, restored_copy(context)))
            if purpose == 'publication_privacy':
                cells = [item['value'] for item in context['included_samples']
                         if item['ref'].startswith('privacy:cell:')]
                fields = []
                for cell in cells:
                    value = deepcopy(cell['value'])
                    if cell['id'] == 'working-notes':
                        value = public_note
                    elif isinstance(value, dict) and 'working_notes' in value:
                        value['working_notes'] = public_note
                    fields.append({'id': cell['id'], 'safe': True, 'value': serialized(value)})
                return {'fields': fields}
            if purpose.startswith('merge_'):
                return {key: {'agreement': True, 'answer': template[key]} for key in schema['properties']}
            return {key: template[key] for key in schema['properties']}

    async def observe(observer):
        if 'working_notes' in ACTION_SCHEMA['required']:
            raise ValueError('작업 메모가 선택 칸이 아님')
        observer.begin_decision({'tool': 'stop', 'args': '{}', 'read_only': True,
                                 'human_confirmation': False, 'reason': 'synthetic', 'working_notes': original_note})
        snapshot = restored_copy(observer.snapshot())
        resumed = Observer(observer.origin, observer.model, Budget(), session_file=observer.session_file)
        resumed.restore(snapshot)
        if resumed.model_context()['working_notes'] != original_note:
            raise ValueError('작업 메모가 다음 문맥 또는 재개에서 달라짐')
        resumed.begin_decision({'tool': 'stop', 'args': '{}', 'reason': 'synthetic'})
        if resumed.working_notes != original_note:
            raise ValueError('메모 없는 응답이 직전 메모를 지움')
        restored_notes.append(resumed.working_notes)
        if observer.session_file is not None:
            await observer.http_run()
            if not any(row['reason'] == 'session_requires_playwright' for row in observer.unopened):
                raise ValueError('세션 관찰이 익명 HTTP로 전환됨')
        observer.model_done = True
        observer.current_http_url = observer.origin

    def read_session(path):
        if path != session_file:
            raise ValueError('dry-run에서 예정하지 않은 파일을 읽음')
        return b'{"cookies": [], "origins": []}'

    # The real orchestration, privacy validation and serialization run against local substitutes.
    with patch(__name__ + '.Codex', Offline), patch.object(Observer, 'run', observe), \
         patch(__name__ + '.cost_settings', lambda *a: ({'base': {'input': 1, 'output': 1}}, number(25))), \
         patch.object(Path, 'read_bytes', read_session), \
         patch(__name__ + '.write_json', lambda path, value: outputs.append(restored_copy(value))), \
         redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        store = MemoryStore()
        await execute_locked(args, catalog, args.out, limits, store)
        call_count = len(seen)
        store.state = restored_copy(store.files['state.json'])
        await execute_locked(args, catalog, args.out, limits, store)
        if len(seen) != call_count:
            raise ValueError('완료된 권한별 회차 또는 합치기를 재개 시 다시 호출함')
        with patch.object(Path, 'read_bytes', lambda path: b'{"cookies": [], "origins": [], "synthetic_changed": true}'):
            try:
                await execute_locked(args, catalog, args.out, limits, store)
            except ValueError:
                pass
            else:
                raise ValueError('다른 준비 세션을 이전 세션 관찰과 합침')
        args.runs, args.session_runs = 3, 1
        try:
            await execute_locked(args, catalog, args.out, limits, store)
        except ValueError:
            pass
        else:
            raise ValueError('저장 회차의 권한 변경을 허용함')
        args.runs, args.session_runs = 2, 2
    record = outputs[-1]
    if len(record['runs']) != 4 or len(restored_notes) != 4 or record.get('resume_pending'):
        raise ValueError('권한별 네 회차 또는 완료 저장 실패')
    if any(row['working_notes'] != public_note for row in record['runs']) or 'synthetic-sensitive-note' in serialized(record):
        raise ValueError('최종 메모 가림 실패')
    if any(saved['observation']['fields']['working_notes'] != original_note for saved in store.state['runs'].values()):
        raise ValueError('비공개 저장에서 작업 메모 원문이 달라짐')
    if record['merged'] != record['merged_by_authority']['anonymous']:
        raise ValueError('익명 합친 결과 호환 키 실패')
    for mode, rows in runs_by_authority(record['runs']).items():
        combined = record['merged_by_authority'][mode]
        if any(item['combined_answer']['findings'] != template[key]['findings']
               for key, item in combined['axes'].items()):
            raise ValueError('findings 표시가 가림 또는 최종 기록에서 사라짐')
        if any(set(item['run_indices']) != {row['run'] for row in rows} for item in combined['axes'].values()):
            raise ValueError('합친 결과의 원래 회차 번호 오류')
    for purpose, context in seen:
        if purpose.startswith('merge_'):
            modes = {item['value']['authority']['requested'] for item in context['included_samples']
                     if item['ref'].startswith('merge:') and item['ref'] != 'merge:feedback'}
            if len(modes) != 1 or context['authority']['requested'] not in modes:
                raise ValueError('모델 합치기 문맥에 서로 다른 권한이 섞임')
    for run in record['runs']:
        single = merge_by_authority(catalog, [run])
        if single[run['authority']['requested']] != run:
            raise ValueError('단일 회차 권한을 합침')
    try:
        merge(catalog, [record['runs'][0], record['runs'][2]])
    except ValueError:
        pass
    else:
        raise ValueError('다른 권한의 합치기를 허용함')
    try:
        await semantic_merge(None, catalog, [record['runs'][0], record['runs'][2]], time.monotonic())
    except ValueError:
        pass
    else:
        raise ValueError('다른 권한의 의미 합치기를 허용함')
    negative = {key: {'agreement': False, 'answer': value} for key, value in template.items()}
    withheld = merge(catalog, record['runs'][:2], negative)
    if any(item['combined_answer']['findings'] != template[key]['findings'] for key, item in withheld['axes'].items()):
        raise ValueError('합의 없는 합친 답의 findings를 버림')

    # Simulate a 1.0 catalog checkpoint with a different axis list, not a real historical run.
    old_catalog = {**catalog, 'version': '1.0', 'axes': catalog['axes'][:-1]}
    old_state = {'version': ResumeStore.VERSION, 'identity': identity(args.origin_url, old_catalog, args.out),
                 'runs': {'1': {'complete': True}}, 'merge': {}}
    manifest = store.path / 'state.json'
    original_exists, original_read = Path.exists, Path.read_text
    with patch.object(Path, 'exists', lambda path: True if path == manifest else original_exists(path)), \
         patch.object(Path, 'read_text', lambda path, *a, **k: serialized(encode(old_state)) if path == manifest else original_read(path, *a, **k)):
        loaded = ResumeStore(args.out, args.origin_url, catalog)
    if loaded.reason != 'different_origin_catalog_or_output' or loaded.state['runs'] or loaded.ledger is not None:
        raise ValueError('카탈로그 1.0의 다른 축 목록을 재개함')
    prepare_checks = await dry_session_prepare_check(session_file)
    return {'response_source': 'synthetic local substitutes, not actual model responses',
            'working_notes_resume_and_privacy': 'passed', 'authority_separation': 'passed',
            'single_run_not_merged': 'passed', 'findings_after_privacy_and_save': labels,
            'catalog_1_0_restart': 'passed', 'session_http_fallback_blocked': 'passed',
            'authority_merge_resume': 'passed', 'changed_session_or_authority_rejected': 'passed',
            'session_file_values_read': False, 'session_prepare': prepare_checks}


async def dry_session_prepare_check(session_file):
    """Drive the operator login and session browser wiring with a fake Playwright surface."""
    from contextlib import asynccontextmanager, redirect_stdout
    from io import StringIO
    from types import SimpleNamespace
    from unittest.mock import patch
    from . import session_prepare
    config = Path(__file__).with_name('synthetic-login-unused.json').resolve()
    account = config.with_name('synthetic-account-unused.json')
    docs = {config: {'login_path': '/synthetic-login', 'user_field': 'login-name', 'password_field': 'login-secret',
                     'account_file': account.name},
            account: {'username': 'synthetic-username', 'password': 'synthetic-password'}}
    writes, contexts, launches, requests, fills, guards = [], [], [], [], [], []
    def read(path, *a, **kw):
        if path not in docs or kw.get('encoding') != 'utf-8-sig':
            raise ValueError('BOM 허용 읽기 또는 예정된 합성 파일 경계 오류')
        return ('\ufeff' + serialized(docs[path])).encode('utf-8').decode(kw['encoding'])

    class Handler:
        def __init__(self): self.sent = False
        async def continue_(self): self.sent = True
        async def abort(self): pass
    class Form:
        async def get_attribute(self, key): return '/synthetic-login'
        async def evaluate(self, script, *args):
            if args:
                return True
            await page.request('POST', 'http://example.invalid/synthetic-login')
            await page.request('POST', 'http://example.invalid/synthetic-login')
            await page.request('POST', 'http://external.invalid/synthetic-login')
            page.url = 'http://example.invalid/synthetic-result'
    class Field:
        def __init__(self, selector): self.selector = selector
        async def fill(self, value): fills.append((self.selector, value))
        def locator(self, selector): return Form()
        async def wait_for(self, **kw): pass
    class Page:
        url = 'about:blank'
        main_frame = object()
        def is_closed(self): return False
        def locator(self, selector): return Field(selector)
        async def goto(self, url, **kw):
            self.url = url
            await self.request('GET', url)
        async def request(self, method, url):
            handler = Handler()
            await context.handler(handler, SimpleNamespace(url=url, method=method, frame=self.main_frame,
                                                          resource_type='document', is_navigation_request=lambda: True))
            requests.append((method, url, handler.sent))
        async def wait_for_load_state(self, *a): pass
    class Context:
        async def route(self, pattern, handler): self.handler = handler
        async def route_web_socket(self, *a): pass
        async def expose_binding(self, *a): pass
        async def add_init_script(self, script): guards.append(script)
        def on(self, *a): pass
        async def new_page(self): return page
        async def storage_state(self):
            return {'cookies': [{'value': 'synthetic-cookie'}], 'origins': [{'localStorage': ['synthetic-local-secret']}]}
    class Browser:
        async def new_context(self, **kw):
            contexts.append(kw)
            return context
        async def close(self): pass
    async def launch(**kw):
        launches.append(kw)
        return Browser()
    @asynccontextmanager
    async def playwright():
        yield SimpleNamespace(chromium=SimpleNamespace(launch=launch))
    page, context = Page(), Context()
    async def no_observe(*a): pass
    async def decision(*a, **kw):
        return {'tool': 'stop', 'args': '{}', 'read_only': True, 'human_confirmation': False, 'reason': 'synthetic'}
    captured = StringIO()
    with patch.dict(sys.modules, {'playwright.async_api': SimpleNamespace(async_playwright=playwright)}), \
         patch.dict(os.environ, {'SITE_ANALYSIS_PROXY': 'http://127.0.0.1:18090'}), \
         patch.object(Path, 'read_text', read), patch.object(Path, 'mkdir', lambda *a, **kw: None), \
         patch.object(session_prepare, 'owner_only', lambda *a: None), \
         patch.object(session_prepare, 'write_json', lambda path, value, **kw: writes.append((path, restored_copy(value), kw))), \
         patch.object(Observer, 'observe_page', no_observe), patch.object(Observer, 'sample', no_observe), redirect_stdout(captured):
        dry = session_prepare.main(['--origin-url', 'http://example.invalid/', '--login-config', str(config),
                                   '--out', str(session_file), '--dry-run'])
        if fills or writes or requests or dry != 0:
            raise ValueError('세션 준비 dry-run이 값, 브라우저 또는 파일 쓰기에 접근함')
        result = await session_prepare.prepare('http://example.invalid/', config, session_file)
        offline = SimpleNamespace(call=decision, context_chars=600000, cost_record=lambda: {}, stopped=lambda: False,
                                  stop_reason=None, pending_answer=None)
        observer = Observer('http://example.invalid/', offline, Budget(), session_file=session_file)
        await observer.run()
        observer.model_done = False
        await page.request('HEAD', observer.origin)
        await page.request('POST', observer.origin)
        await page.request('GET', 'http://external.invalid/')
        if observer.model_context()['authority']['mode'] != 'session' or 'synthetic-cookie' in serialized(observer.snapshot()):
            raise ValueError('세션 권한 문맥 또는 쿠키 값 격리 오류')
    if (result != 0 or len(fills) != 2 or len(writes) != 1 or writes[0][1]['origins']
            or writes[0][2].get('private') is not True or writes[0][1]['cookies'][0]['value'] != 'synthetic-cookie'
            or [row[2] for row in requests[:4]] != [True, True, False, False]
            or [row[2] for row in requests[-3:]] != [True, False, False]
            or contexts[-1].get('storage_state') != str(session_file) or not guards
            or any(kw['proxy']['server'] != 'http://127.0.0.1:18090' for kw in launches)
            or any(value in captured.getvalue() for value in ('synthetic-username', 'synthetic-password', 'synthetic-cookie'))):
        raise ValueError('운영자 폼 제출, 중계, 비공개 저장 또는 세션 관찰 경계 오류')
    for path in (Path(__file__).with_name('session-forbidden.json'), session_file.parent, session_file.parent / '..' / 'outside.json'):
        try:
            session_path(path)
        except ValueError:
            pass
        else:
            raise ValueError('허용 폴더 밖의 세션 경로를 허용함')
    return {'synthetic_browser_only': True, 'bom_config_and_account': 'passed', 'one_same_origin_post': 'passed',
            'private_cookie_save': 'passed', 'storage_state_browser_option': 'passed', 'readonly_session_guard': 'passed',
            'outside_session_directory_rejected': 'passed', 'credential_output_withheld': 'passed'}


async def execute(args, catalog, output, limits):
    cost_settings(args.rates, args.model, args.max_cost_usd)
    store = ResumeStore(output, args.origin_url, catalog, args.fresh, args.checkpoint_root)
    try:
        store.begin()
        return await execute_locked(args, catalog, output, limits, store)
    finally:
        store.close()


async def execute_locked(args, catalog, output, limits, store):
    specs = run_specs(args)
    for index, mode in specs:
        saved = store.state['runs'].get(str(index), {})
        previous_mode = saved.get('authority', saved.get('published', {}).get('authority', {}).get('requested', 'anonymous'))
        if saved and previous_mode != mode:
            raise ValueError('회차 권한 구성이 바뀜: --fresh로 새로 시작해야 함')
    if args.session_runs:
        # Bind resumed observations to this exact prepared state, without retaining its contents.
        from hashlib import sha256
        session_source = sha256(args.session_file.read_bytes()).hexdigest()
        if store.state.get('session_source_sha256') not in (None, session_source):
            raise ValueError('준비 세션이 바뀜: --fresh로 새로 시작해야 함')
        store.state['session_source_sha256'] = session_source
    rate, ceiling = cost_settings(args.rates, args.model, args.max_cost_usd)
    login, credential_error = {}, None
    try:
        login = credentials(args.login_env)
    except Exception as error:
        credential_error = type(error).__name__
    model = Codex(args.model, args.model_timeout, store.path / '.models', tuple(login.values()),
                  rate, ceiling, args.same_failure_limit, args.context_chars,
                  args.model_output_bytes, args.provider, args.reasoning_effort)
    model.remaining_stages = lambda: remaining_work(args, catalog, store.state)
    if store.ledger:
        model.restore(store.ledger, store.state.get('acknowledged_calls', 0),
                      ceiling_override=ceiling if args.max_cost_usd is not None else None)
    if args.reset_failures:
        model.failures.counts.clear()
        store.state.setdefault('failure_resets', []).append(now())
        for run in store.state['runs'].values():
            for saved in run.get('groups', {}).values():
                if saved.pop('terminal_axes', []):
                    saved['complete'] = run['complete'] = False
            for saved in run.get('privacy', {}).values():
                previous = saved.get('terminal', [])
                saved['terminal'] = [key for key in previous if saved.get('errors', {}).get(key) == 'privacy_withheld']
                if saved['terminal'] != previous:
                    saved['complete'] = run['complete'] = False
    model.checkpoint = store.save_ledger
    model.persist()
    started = time.monotonic()
    runs = []
    merge_states = store.state.setdefault('merge_by_authority', {})
    merge_states.setdefault('anonymous', store.state['merge'])
    judgments_by_authority = {mode: saved.get('judgments', {}) for mode, saved in merge_states.items()}
    supplement = copy_supplement(args.copy_supplement)
    record = {'schema_version': 'site-analysis/1.1', 'created_at': now(),
              'target': {'source': 'operator', 'origin_url_sha256': ref(args.origin_url)},
              'catalog_version': catalog['version'], 'catalog_sha256': ref(json.dumps(catalog, ensure_ascii=False, sort_keys=True)),
              'runs': runs, 'consumer_guidance': {
                  'filling': '모델이 runs와 의미 비교 및 합친 답의 근거를 검토하고 모양을 판단한다. 축의 agreement=true는 축 전체의 메움 사용 승인이 아니다. 메움에는 같은 권한의 두 회차 관찰로 뒷받침된 both-runs 사실만 쓰고, single-run, contradictory, 표시 없는 사실은 보존하되 메움 근거로 쓰지 않는다. 두 회차가 같은 추론을 했어도 관찰로 올리지 않는다. 말투에는 고유명사와 원문 인용 금지',
                  'removal_and_stopping': '한 번이라도 발견한 제거와 멈춤 축을 사용하고 불일치를 검토한다',
                  'verification': '실행별 답과 관찰 한계를 함께 판단한다. 측정 지점이 다르면 같은 수치로 간주하지 않는다',
                  'authority': '권한이 다른 회차는 같은 사실을 두 번 확인한 근거로 세지 않는다. 단일 회차 권한은 합치지 않는다',
                  'findings': 'combined_answer의 findings 표시를 함께 검토한다. 메움에는 같은 권한의 both-runs 근거를 사용하고 single-run과 contradictory 표시는 보존한다'},
              'copy_supplement': {'source': 'copy', 'status': '제공되지 않음', 'containers': []},
              'removal_handoff': {'credential_env_names': [args.login_env] if args.login_env else [],
                                  'delete_copied_analysis_account': bool(args.login_env), 'credential_values': None,
                                  'credential_error': credential_error},
              'limitations': ['폼 제출과 POST 읽기 API는 전송하지 않음',
                              '서비스워커는 요청 통제를 우회하므로 차단함',
                              'WebSocket 송신이 필요한 구독은 못 얻음',
                              '가림의 정확성과 실제 웹 적용성은 이번 작업에서 실행 검증하지 않음']}
    def save():
        combined = merge_by_authority(catalog, runs, judgments_by_authority)
        anonymous = combined.get('anonymous') if len(runs_by_authority(runs).get('anonymous', [])) > 1 else None
        # Provider stderr stays in the private ledger; the published record keeps measurements only.
        record.update(merged=anonymous, merged_by_authority=combined,
                      model_calls=[{key: value for key, value in call.items() if key != 'provider_stderr'}
                                   for call in model.calls],
                      response_times=[row for run in runs for row in run['response_times']],
                      stop_reason=model.stop_reason,
                      metrics={'call_count': len(model.calls), 'cost_usd': str(model.spent),
                               'browse_cost_usd': str(model.browse_spent),
                               'analysis_cost_usd': str(model.analysis_spent),
                               'privacy_cost_usd': str(model.privacy_spent), 'merge_cost_usd': str(model.merge_spent),
                               'cost_budget': model.cost_record(),
                               'provider_hard_cost_limit': False,
                               'max_cost_usd': str(model.ceiling), 'cost_usage_unknown': model.usage_unknown,
                               'same_failures': model.failures.record(),
                               'missing_axes': sum(len(catalog['axes']) - len(run['axes']) for run in runs),
                               'unobserved_axes': [sum(isinstance(answer, dict) and answer.get('status') == '못 봄' for answer in run['axes'].values()) for run in runs],
                               'elapsed_seconds': round(time.monotonic() - started, 3)})
        store.state['record'] = record
        store.save()
        write_json(output, record)
    for index, mode in specs:
        async def checkpoint(run):
            position = next((i for i, row in enumerate(runs) if row['run'] == index), None)
            if position is None:
                runs.append(run)
            else:
                runs[position] = run
            save()
        try:
            await one_run(index, args, catalog, limits, model, login, checkpoint, store, defer_fact_privacy=True)
        except KeyboardInterrupt:
            save()
            raise
        except Exception as error:
            # Already released cells and checkpoints survive a later item failure.
            record.setdefault('run_errors', []).append({'run': index, 'status': '못 얻음', 'error': type(error).__name__})
            save()
        if model.stopped():
            break
    # Across all runs, review axis answers before fact cells.
    for position, published_run in enumerate(runs):
        index = published_run['run']
        async def checkpoint(run):
            runs[position] = run
            save()
        try:
            await one_run(index, args, catalog, limits, model, login, checkpoint, store, publication_only=True)
        except KeyboardInterrupt:
            save()
            raise
        except Exception as error:
            record.setdefault('run_errors', []).append({'run': index, 'status': '못 얻음', 'error': type(error).__name__})
            save()
        if model.stopped():
            break
    try:
        for mode, rows in runs_by_authority(runs).items():
            expected = args.runs if mode == 'anonymous' else args.session_runs
            if len(rows) != expected or not all(store.state['runs'][str(row['run'])]['complete'] for row in rows):
                continue
            async def merge_checkpoint():
                store.save(model)
            signature = ref(json.dumps([row['axes'] for row in rows], ensure_ascii=False, sort_keys=True))
            if merge_states.get(mode, {}).get('input_sha256') != signature:
                merge_states[mode] = {'input_sha256': signature}
                judgments_by_authority[mode] = {}
                if mode == 'anonymous':
                    store.state['merge'] = merge_states[mode]
                store.save()
            judgments_by_authority[mode] = await semantic_merge(model, catalog, rows,
                            time.monotonic() + (args.merge_seconds or limits['seconds']),
                            merge_states[mode], merge_checkpoint, args.privacy_seconds or limits['seconds'],
                            {str(row['run']): store.state['runs'][str(row['run'])].get('observation') for row in rows})
        if supplement is not None:
            if store.state.get('copy_privacy', {}).get('document_sha256') != supplement['document_sha256']:
                store.state['copy_privacy'] = {'document_sha256': supplement['document_sha256']}
            async def supplement_checkpoint():
                store.save(model)
            safe, errors = await privacy_cells(model, [{'id': 'copy-supplement', 'value': supplement}],
                         time.monotonic() + (args.privacy_seconds or limits['seconds']),
                         store.state.setdefault('copy_privacy', {}), supplement_checkpoint)
            record['copy_supplement'] = safe.get('copy-supplement',
                         {'source': 'copy', 'status': '못 얻음', 'error': errors.get('copy-supplement'), 'containers': []})
            if not store.state['copy_privacy'].get('complete'):
                record['copy_resume_pending'] = True
    except Exception as error:
        record['merge_error'] = {'status': '못 얻음', 'error': getattr(error, 'code', type(error).__name__)}
    model.stopped()
    pending = store.plan(catalog, args.runs + args.session_runs)
    if pending['stage'] != 'complete':
        record['resume_pending'] = pending
    save()
    print('분석 기록: ' + str(output))
    return 2 if model.stop_reason or record.get('run_errors') or record.get('merge_error') or record.get('resume_pending') or record.get('copy_resume_pending') or record['copy_supplement']['status'] == '못 얻음' or any(run['group_errors'] or run['privacy']['errors']
                                        or run['facts']['response_observation']['status'] != '관찰됨' for run in runs) else 0


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    args = parser().parse_args(argv)
    try:
        output, limits = validate(args)
        catalog = load_catalog()
        if args.dry_run:
            dry_plan(args, catalog, output, limits)
            return 0
        return asyncio.run(execute(args, catalog, output, limits))
    except KeyboardInterrupt:
        print('중단됨. 마지막으로 저장한 단계와 비용 장부는 유지함.', file=sys.stderr)
        return 130
    except (Exception, CheckpointError) as error:
        print('분석 실패: ' + type(error).__name__, file=sys.stderr)
        if isinstance(error, CheckpointError):
            print(str(error), file=sys.stderr)
        if args.dry_run and isinstance(error, ValueError):
            print('dry-run 검사 실패: ' + str(error), file=sys.stderr)
        if args.dry_run:
            import traceback
            for frame in traceback.extract_tb(error.__traceback__):
                print(f'dry-run 위치: {Path(frame.filename).name}:{frame.lineno} {frame.name}', file=sys.stderr)
        Observer.report_model_error(error)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
