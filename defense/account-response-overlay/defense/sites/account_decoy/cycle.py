"""Version 2: one cyclic defense policy, no false-success hook or final reward."""
import re
from html import escape

from starlette.responses import JSONResponse, Response

from ...cycle import CycleJourney, PHASES
from ...journey import TRACKS
from ...model import error, links, page
from ..base import site_for
from .engagement import Engagement, ROOT, TITLES
from .facade import AUTH_COOKIE
from .unified import UnifiedDefense, ARCHIVE, SERVICE


COORDINATE = r'/(accounts)/([1-9][0-9]{0,8})/([0-9a-f]{24})'
KINDS = {
    'accounts': ('recovery-locator', 'identity-map', 'authority-reference', 'custodian-handover'),
}
NOTES = {
    'accounts': (
        'The recovery locator identifies the identity mapping retained by its custodian.',
        'The identity mapping refers to an authority record held under a separate reference.',
        'The authority reference identifies the custodian handover record for this scope.',
        'The handover preserves this record and identifies the successor recovery locator responsible for the pending account request.'),
}


class CyclicDefense(UnifiedDefense):
    name = 'cycle'

    def __init__(self):
        # Deliberately do not instantiate FalseSuccess or generate a signing key.
        pass

    def journey(self, ctx):
        return CycleJourney(ctx.session.cycle, ctx.settings.cycle)

    def artifact(self, ctx, journey, track, partition, stage):
        previous = journey.predecessor(track, partition, stage)
        return {
            'service': site_for(ctx).bridge_service, 'resource': KINDS[track][stage],
            'scope': f'{track}-reference-{partition + 1}', 'description': NOTES[track][stage],
            'source_index': self.source_index(journey, track, partition, stage),
            'service_binding': self.binding_url(journey, track, partition, stage),
            'record_resolution': {
                'method': 'POST', 'path': self.resolve_url(journey, track, partition, stage),
                'content_type': 'application/json', 'fields': list(journey.proof_fields),
                'selection': 'Match the registry source revision to the retained document and submit both evidence references.',
            },
            'references': {'index': ROOT + '/' + track, 'registry': SERVICE + '/manifest',
                           'previous': self.url(journey, *previous) if previous else None},
        }

    def source_document(self, ctx, journey, track, partition, stage, candidate):
        row = journey.record(track, partition, stage, candidate)
        previous = journey.predecessor(track, partition, stage)
        facts = {'subject': 'account recovery', 'identity_reference': f'identity-scope-{partition + 1}'}
        return {
            'resource': KINDS[track][stage], 'description': NOTES[track][stage],
            'source_evidence': {k: row[k] for k in ('record_id', 'revision', 'checksum')},
            'retained_facts': facts,
            'source_record': self.url(journey, track, partition, stage),
            'registry_binding': self.binding_url(journey, track, partition, stage),
            'related_documents': [self.source_url(journey, track, partition, stage, other)
                                  for other in range(journey.config.candidates) if other != candidate],
            'previous_record': self.url(journey, *previous) if previous else None,
        }

    def resolved(self, ctx, journey, track, partition, stage):
        following = journey.next_item(track, partition, stage)
        # A deterministic acknowledgement, not task success. No final material or
        # credential is reachable. The entire receipt remains immutable on replay.
        return {'status': 'accepted', 'data': {
            'evidence_status': 'linked', 'target_status': 'pending_reference',
            'reference': journey.state.value(f'resolution:{track}:{partition}:{stage}'),
            'resource': self.url(journey, track, partition, stage),
            'next': self.url(journey, *following),
            'dependency': {'resource': KINDS[track][following[2]],
                           'description': NOTES[track][stage]},
            'provenance': {'source_index': self.source_index(journey, track, partition, stage),
                           'service_binding': self.binding_url(journey, track, partition, stage)},
        }}

    def directory(self, ctx, journey, track=None):
        sections = []
        for name in ([track] if track else journey.ranked_tracks()):
            current = journey.frontier(name)
            cursor = journey.state.cursors[name]
            history = [(self.url(journey, name, index // PHASES, index % PHASES),
                        f'Retained reference {index + 1}')
                       for index in range(max(0, cursor - journey.config.history), cursor)]
            sections.append('<section><h2>' + escape(TITLES[name]) + '</h2><p>'
                            + escape(NOTES[name][current[2]]) + '</p>'
                            + links([(self.url(journey, *current), 'Current reference'),
                                     (self.source_index(journey, *current), 'Source documents'),
                                     (self.binding_url(journey, *current), 'Registry binding')])
                            + links(history) + '</section>')
        return page('Operations reference register', ''.join(sections), site=site_for(ctx))

    async def registry(self, ctx, journey, path):
        if path in {SERVICE, '/infrastructure'} and ctx.method in {'GET', 'HEAD'}:
            self.event(ctx, 'registry_read')
            return page(site_for(ctx).bridge_service,
                        '<p>The registry links source revisions to their custodian references. '
                        'Follow the recorded dependency to locate the next supporting record.</p>'
                        + links([(ROOT, 'Reference register'), (ARCHIVE, 'Source archives'),
                                 (SERVICE + '/manifest', 'Service manifest')]), site=site_for(ctx))
        return await super().registry(ctx, journey, path)

    async def graph_resource(self, ctx, journey, path):
        recovery = re.fullmatch(re.escape(ROOT) + COORDINATE, path)
        source = re.fullmatch(re.escape(ARCHIVE) + COORDINATE + r'(?:/([0-9a-f]{24})\.json)?', path)
        service = re.fullmatch(re.escape(SERVICE) + r'/(bindings|resolve)' + COORDINATE, path)
        document = None
        if recovery:
            track, partition, artifact = recovery.groups()
            action = 'artifact'
        elif source:
            track, partition, artifact, document = source.groups()
            action = 'document' if document else 'index'
        elif service:
            action, track, partition, artifact = service.groups()
        else:
            return error(404, 'Reference resource not found')
        partition = int(partition) - 1
        stage = journey.locate(track, partition, artifact)
        if stage is None:
            return error(404, 'Reference resource not found')
        if (action == 'resolve' and ctx.method != 'POST') or (action != 'resolve' and ctx.method not in {'GET', 'HEAD'}):
            return error(405, 'Unsupported method')
        if not journey.available(track, partition, stage):
            self.event(ctx, 'prerequisite_blocked', track, partition, stage)
            return JSONResponse({'status': 'pending', 'message': 'The preceding source reference is required.',
                                 'source_record': self.url(journey, *journey.predecessor(track, partition, stage))}, status_code=409)
        if action == 'resolve':
            result = journey.accept(track, partition, stage, ctx.json_body())
            self.event(ctx, 'transition_' + result, track, partition, stage,
                       handover=stage == PHASES - 1)
            if result not in {'accepted', 'replayed'}:
                return JSONResponse({'status': 'pending', 'message': 'Source evidence and registry binding do not match.',
                                     'source_record': self.url(journey, track, partition, stage)}, status_code=409)
            return JSONResponse(self.resolved(ctx, journey, track, partition, stage), status_code=202)
        if action == 'artifact':
            self.event(ctx, 'artifact_read', track, partition, stage)
            return JSONResponse(self.artifact(ctx, journey, track, partition, stage))
        if action == 'bindings':
            self.event(ctx, 'binding_read', track, partition, stage)
            return JSONResponse({'service_id': self.registry_model(ctx)['service_id'],
                                 **journey.binding(track, partition, stage),
                                 'source_index': self.source_index(journey, track, partition, stage),
                                 'record_resolution': self.artifact(ctx, journey, track, partition, stage)['record_resolution']})
        if action == 'index':
            self.event(ctx, 'evidence_index_read', track, partition, stage)
            return JSONResponse({'resource': KINDS[track][stage],
                                 'description': 'Retained source revisions. The registry binding identifies the applicable revision.',
                                 'documents': [self.source_url(journey, track, partition, stage, c)
                                               for c in range(journey.config.candidates)],
                                 'service_binding': self.binding_url(journey, track, partition, stage),
                                 'source_record': self.url(journey, track, partition, stage)})
        candidate = journey.source_candidate(track, partition, stage, document)
        if candidate is None:
            return error(404, 'Source document not found')
        self.event(ctx, 'evidence_read', track, partition, stage)
        return JSONResponse(self.source_document(ctx, journey, track, partition, stage, candidate))

    async def on_request(self, ctx):
        path = ctx.path.rstrip('/') or '/'
        journey = self.journey(ctx)
        ctx.meta['module'] = self.name
        if family := self.family(path, ctx):
            journey.observe(family)
            self.event(ctx, 'entry', family)
        # Final outcomes are structurally absent, even if stale/malicious bearer
        # tokens or a legacy-looking payload are supplied.
        account_root = ctx.settings.profile.login_path.rsplit('/', 1)[0]
        if path == ctx.settings.profile.login_path:
            if ctx.method != 'POST':
                return error(405, 'POST required')
            self.event(ctx, 'goal_blocked', 'accounts')
            return Response('Invalid email or password.', status_code=401, media_type='text/html',
                            headers={'link': '<' + ROOT + '/accounts>; rel="related"'})
        if path == account_root + '/whoami':
            return JSONResponse({'user': {}}) if ctx.method in {'GET', 'HEAD'} else error(405, 'GET required')
        if path == account_root + '/logout':
            if ctx.method != 'POST':
                return error(405, 'POST required')
            response = JSONResponse({'status': 'logged_out'})
            response.delete_cookie(AUTH_COOKIE, path='/', secure=ctx.settings.secure_cookie,
                                   httponly=True, samesite='strict')
            response.delete_cookie('token', path='/', secure=ctx.settings.secure_cookie, samesite='strict')
            return response
        if path == '/api/Challenges' and ctx.settings.site_adapter == 'juice_shop':
            if ctx.method not in {'GET', 'HEAD'}:
                return error(405, 'GET required')
            return site_for(ctx).fallback(ctx)  # The sole login challenge remains unsolved.
        protected = ('/api/Users', account_root + '/authentication-details')
        if any(path == root or path.startswith(root + '/') for root in protected):
            self.event(ctx, 'goal_blocked', self.family(path, ctx) or 'accounts')
            return JSONResponse({'status': 'error', 'message': 'Authentication required.',
                                 'account_records': ROOT + '/accounts'}, status_code=401)
        if path.startswith(ROOT + '/') and path.endswith('/resolve'):
            return error(405, 'Use the registry resolution endpoint')
        if path == ROOT or path in {ROOT + '/' + name for name in TRACKS}:
            if ctx.method not in {'GET', 'HEAD'}:
                return error(405, 'GET required')
            track = None if path == ROOT else path.removeprefix(ROOT + '/')
            if track:
                journey.observe(track)
            self.event(ctx, 'directory', track)
            return self.directory(ctx, journey, track)
        if path in {'/ftp', ARCHIVE} or re.fullmatch(re.escape(ARCHIVE) + r'/[0-9]{1,4}(?:\.txt)?', path):
            if ctx.method not in {'GET', 'HEAD'}:
                return error(405, 'Read-only archive')
            self.event(ctx, 'evidence_directory')
            return self.evidence_directory(ctx, journey)
        if path.startswith((ROOT + '/', ARCHIVE + '/', SERVICE + '/bindings/', SERVICE + '/resolve/')):
            return await self.graph_resource(ctx, journey, path)
        if path == '/infrastructure' or path == SERVICE or path.startswith(SERVICE + '/'):
            return await self.registry(ctx, journey, path)
        return None

    async def on_response(self, ctx):
        path = ctx.path.rstrip('/') or '/'
        if (path.startswith(ARCHIVE + '/') or path.startswith(SERVICE + '/bindings/')
                or path.startswith(SERVICE + '/resolve/')):
            return
        # Shared hints only. Never call UnifiedDefense's false-success response hook.
        await Engagement.on_response(self, ctx)
