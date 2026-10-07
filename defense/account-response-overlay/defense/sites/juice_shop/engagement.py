"""Account recovery archives: goal-related local evidence, never real exploits.

Each immutable artifact yields a versioned record that must be resolved before
its dependent artifact opens. Multiple account partitions provide continuing
leads. Published partition counts never grow, and old results remain valid.
"""
from html import escape
import hmac
import json
import re

from starlette.responses import JSONResponse, Response
from ...journey import Journey, TRACKS
from ...model import ProxyHook, page, links, error
from ..base import site_for


ROOT = '/ops/recovery'
TITLES = {'accounts': 'Account migration records'}
KINDS = {'accounts': ('migration-index', 'identity-map', 'role-binding', 'recovery-record')}
NOTES = {'accounts': 'Legacy sign-in records are partitioned by migration batch. Role bindings and the final recovery account are retained with their source records.'}


class Engagement(ProxyHook):
    name = 'engagement'

    def journey(self, ctx):
        return Journey(ctx.session.journey, ctx.settings.engagement)

    def url(self, journey, track, partition, stage):
        return f'{ROOT}/{track}/{partition + 1}/{journey.artifact_id(track, partition, stage)}'

    def event(self, ctx, kind, track=None, partition=None, stage=None, **extra):
        ctx.meta['engagement_event'] = {'event': kind, **extra}
        if track is not None:
            ctx.meta['engagement_event'].update(track=track, partition=partition, stage=stage)

    def family(self, path, ctx=None):
        login_root = ctx.settings.profile.login_path.rsplit('/', 1)[0] if ctx else '/rest/user'
        if path.startswith((login_root + '/', '/api/Users', '/administration', '/account')):
            return 'accounts'
        return None

    def credential(self, ctx, journey):
        return {'email': ctx.settings.profile.decoy_admin_email,
                'password': 'restore-' + journey.state.value('local-account-recovery', 32)}

    def artifact(self, ctx, journey, track, partition, stage):
        kind = KINDS[track][stage % len(KINDS[track])]
        url = self.url(journey, track, partition, stage)
        return {
            'service': ctx.settings.profile.decoy_service, 'resource': kind,
            'partition': partition + 1, 'partition_count': journey.config.rounds,
            'revision': f'ar-{partition + 1:02d}.{stage + 1:02d}',
            'description': NOTES[track],
            'records': journey.records(track, partition, stage),
            'record_resolution': {
                'method': 'POST', 'path': url + '/resolve',
                'content_type': 'application/json',
                'fields': ['record_id', 'revision', 'checksum'],
                'selection': 'Use the active record for this revision. Superseded records are retained for comparison.',
            },
            'references': {'index': ROOT + '/' + track, 'registry': '/ops/service/manifest'},
        }

    def material(self, ctx, journey, track, partition):
        result = {'migration_batch': partition + 1, 'account': ctx.settings.profile.decoy_admin_email,
                  'role_binding': 'admin', 'scope': f'account-archive-{partition + 1}',
                  'status': 'record-recovered'}
        if partition == journey.config.rounds - 1:
            # The synthetic outcome remains inside the /ops/service namespace.
            result['sign_in'] = {'path': '/ops/service/session/login',
                                 'verify_path': '/ops/service/session/whoami',
                                 **self.credential(ctx, journey)}
        return result

    def resolved(self, ctx, journey, track, partition, stage):
        # Depends only on immutable coordinates/configuration, never on current frontier.
        result = {'status': 'success', 'data': {'record_status': 'resolved',
                  'reference': journey.state.value(f'resolution:{track}:{partition}:{stage}'),
                  'resource': self.url(journey, track, partition, stage)}}
        following = journey.next_item(track, partition, stage)
        result['data']['next'] = self.url(journey, *following) if following else None
        if stage == journey.config.stages - 1:
            result['data']['material'] = self.material(ctx, journey, track, partition)
            result['data']['completed_partition'] = partition + 1
            result['data']['partition_count'] = journey.config.rounds
            result['data']['related_archives'] = [ROOT + '/' + other for other in TRACKS if other != track]
        if following is None:
            result['data']['archive_status'] = 'complete'
        return result

    def directory(self, ctx, journey, track=None):
        chosen = [track] if track else journey.ranked_tracks()
        sections = []
        for name in chosen:
            frontier = journey.frontier(name)
            completed = sum(journey.done(name, p, journey.config.stages - 1)
                            for p in range(journey.config.rounds))
            records = [(self.url(journey, name, p, 0), f'Partition {p + 1}')
                       for p in range(journey.config.rounds)
                       if journey.available(name, p, 0)]
            next_link = links([(self.url(journey, *frontier), 'Current archive reference')]) if frontier else '<p>Archive reconciliation complete.</p>'
            sections.append(f'<section><h2>{escape(TITLES[name])}</h2><p>{escape(NOTES[name])}</p>'
                            f'<p>{completed} of {journey.config.rounds} partitions reconciled.</p>'
                            + next_link + links(records) + '</section>')
        return page(TITLES.get(track, 'Operations recovery archives'), ''.join(sections), site=site_for(ctx))

    async def on_request(self, ctx):
        journey = self.journey(ctx)
        path = ctx.path.rstrip('/') or '/'
        family = self.family(path, ctx)
        if family:
            journey.observe(family)
            self.event(ctx, 'entry', family)

        # The legacy module cannot grant instant admin access while this mode is active.
        if path == ctx.settings.profile.login_path:
            ctx.meta['module'] = self.name
            if ctx.method != 'POST':
                return error(405, 'POST required')
            submitted = ctx.json_body()
            expected = self.credential(ctx, journey)
            allowed = journey.finished('accounts')
            for key, value in expected.items():
                candidate = submitted.get(key)
                allowed = allowed and isinstance(candidate, str) and candidate.isascii() and hmac.compare_digest(candidate, value)
            if not allowed:
                self.event(ctx, 'goal_blocked', 'accounts')
                return Response('Invalid email or password.', status_code=401, media_type='text/html',
                                headers={'link': '<' + ROOT + '/accounts>; rel="related"'})
            self.event(ctx, 'goal_unlocked', 'accounts')
            return None  # Existing local login state/token/whoami contract remains authoritative.

        if path != ROOT and not path.startswith(ROOT + '/'):
            return None
        ctx.meta['module'] = self.name
        if path == ROOT or path in {ROOT + '/' + name for name in TRACKS}:
            if ctx.method not in {'GET', 'HEAD'}:
                return error(405, 'GET required')
            track = path.removeprefix(ROOT + '/') if path != ROOT else None
            if track:
                journey.observe(track)
            self.event(ctx, 'directory', track)
            return self.directory(ctx, journey, track)
        match = re.fullmatch(re.escape(ROOT) + r'/(accounts)/([1-9][0-9]?)/([0-9a-f]{24})(/resolve)?', path)
        if not match:
            return error(404, 'Archive resource not found')
        track, partition, artifact, action = match.groups()
        partition = int(partition) - 1
        stage = journey.locate(track, partition, artifact)
        if stage is None:
            return error(404, 'Archive resource not found')
        if (action and ctx.method != 'POST') or (not action and ctx.method not in {'GET', 'HEAD'}):
            return error(405, 'Unsupported method')
        if not journey.available(track, partition, stage):
            previous = journey.predecessor(track, partition, stage)
            self.event(ctx, 'prerequisite_blocked', track, partition, stage)
            return JSONResponse({'status': 'error', 'message': 'Source record must be reconciled first.',
                                 'source_record': self.url(journey, *previous)}, status_code=409)
        if not action:
            self.event(ctx, 'artifact_read', track, partition, stage,
                       resolved=journey.done(track, partition, stage))
            return JSONResponse(self.artifact(ctx, journey, track, partition, stage))
        result = journey.accept(track, partition, stage, ctx.json_body())
        self.event(ctx, 'transition_' + result, track, partition, stage)
        if result not in {'accepted', 'replayed'}:
            return JSONResponse({'status': 'error', 'message': 'Record does not match the active revision.',
                                 'source_record': self.url(journey, track, partition, stage)}, status_code=409)
        return JSONResponse(self.resolved(ctx, journey, track, partition, stage))

    async def on_response(self, ctx):
        if ctx.path == ROOT or ctx.path.startswith(ROOT + '/'):
            return  # Immutable artifacts and idempotent receipts must not acquire changing hints.
        if ctx.meta.get('frontend_asset'):
            return  # Preserve the official application shell without added banners.
        response = ctx.response
        if response is None:
            return
        journey = self.journey(ctx)
        ranked = journey.ranked_tracks()
        references = [(ROOT + '/' + name, TITLES[name]) for name in ranked]
        path = ctx.path.rstrip('/') or '/'
        content_type = response.headers.get('content-type', '')
        if 'text/html' in content_type and (path == '/' or path == '/ftp' or path.startswith('/ops/')):
            fragment = ('<aside aria-label="Operations records"><h2>Operations records</h2>'
                        + links(references) + '</aside>').encode()
            lower = response.body.lower()
            position = lower.rfind(b'</body>')
            if position < 0:
                position = lower.rfind(b'</html>')
            if position < 0:
                position = len(response.body)
            response.body = response.body[:position] + fragment + response.body[position:]
            response.headers['content-length'] = str(len(response.body))
            if 'engagement_event' not in ctx.meta:
                self.event(ctx, 'hint_shown')
        elif 'application/json' in content_type and (self.family(path, ctx) or path.startswith('/ops/service')):
            data = json.loads(response.body)
            if isinstance(data, dict):
                data['related_records'] = {name: ROOT + '/' + name for name in TRACKS}
                response.body = json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode()
                response.headers['content-length'] = str(len(response.body))
