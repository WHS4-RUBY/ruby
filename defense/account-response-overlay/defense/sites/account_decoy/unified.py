"""One request policy joining maze evidence, bridge gates and synthetic outcomes.

The old independent maze/bridge hooks are not installed in this policy. Their
entry paths join this graph; a single JourneyState governs every surface.
"""
from html import escape
import re

from starlette.responses import JSONResponse, Response

from ...journey import TRACKS
from ...model import error, links, page
from ...unified import UnifiedJourney
from ..base import site_for
from .engagement import Engagement, ROOT, KINDS, TITLES
from .false_success import FalseSuccess


ARCHIVE = '/ops/archive'
SERVICE = '/ops/service'
COORDINATE = r'/(accounts)/([1-9][0-9]?)/([0-9a-f]{24})'


class UnifiedDefense(Engagement):
    name = 'unified'
    resources = ('access-policy.json', 'release-notes.txt')

    def __init__(self):
        self.outcomes = FalseSuccess()

    def journey(self, ctx):
        return UnifiedJourney(ctx.session.journey, ctx.settings.engagement)

    def coordinate(self, journey, track, partition, stage):
        return f'/{track}/{partition + 1}/{journey.artifact_id(track, partition, stage)}'

    def source_index(self, journey, track, partition, stage):
        return ARCHIVE + self.coordinate(journey, track, partition, stage)

    def source_url(self, journey, track, partition, stage, candidate):
        return (self.source_index(journey, track, partition, stage) + '/'
                + journey.source_id(track, partition, stage, candidate) + '.json')

    def binding_url(self, journey, track, partition, stage):
        return SERVICE + '/bindings' + self.coordinate(journey, track, partition, stage)

    def resolve_url(self, journey, track, partition, stage):
        return SERVICE + '/resolve' + self.coordinate(journey, track, partition, stage)

    def artifact(self, ctx, journey, track, partition, stage):
        # This index deliberately contains neither the source proof nor binding proof.
        data = super().artifact(ctx, journey, track, partition, stage)
        data.pop('records')
        data['source_index'] = self.source_index(journey, track, partition, stage)
        data['service_binding'] = self.binding_url(journey, track, partition, stage)
        data['record_resolution'] = {
            'method': 'POST', 'path': self.resolve_url(journey, track, partition, stage),
            'content_type': 'application/json', 'fields': list(journey.proof_fields),
            'selection': 'Match the registry source revision to an archived document, then submit its source evidence with the registry binding.',
        }
        return data

    def resolved(self, ctx, journey, track, partition, stage):
        data = super().resolved(ctx, journey, track, partition, stage)
        data['data']['provenance'] = {
            'source_index': self.source_index(journey, track, partition, stage),
            'service_binding': self.binding_url(journey, track, partition, stage),
        }
        return data

    def evidence_directory(self, ctx, journey, track=None):
        sections = []
        for name in ([track] if track else journey.ranked_tracks()):
            current = journey.frontier(name)
            references = [(ROOT + '/' + name, 'Recovery register')]
            if current:
                references += [(self.source_index(journey, *current), 'Retained source documents'),
                               (self.binding_url(journey, *current), 'Registry revision binding')]
            sections.append('<section><h2>' + escape(TITLES[name]) + '</h2>'
                            + links(references) + '</section>')
        return page('Operations source archives', ''.join(sections), site=site_for(ctx))

    def source_document(self, ctx, journey, track, partition, stage, candidate):
        row = journey.record(track, partition, stage, candidate)
        # The registry, not a convenient active=true flag in this document, selects
        # the applicable revision. All historical documents remain readable.
        evidence = {k: row[k] for k in ('record_id', 'revision', 'checksum')}
        scope = f'{track}-partition-{partition + 1}'
        facts = {'account': ctx.settings.profile.decoy_admin_email, 'migration_batch': partition + 1,
                 'role_record': f'role-{partition + 1:02d}'}
        previous = journey.predecessor(track, partition, stage)
        return {
            'resource': KINDS[track][stage % len(KINDS[track])], 'scope': scope,
            'source_evidence': evidence, 'retained_facts': facts,
            'source_record': self.url(journey, track, partition, stage),
            'registry_binding': self.binding_url(journey, track, partition, stage),
            'related_documents': [self.source_url(journey, track, partition, stage, other)
                                  for other in range(journey.config.candidates) if other != candidate],
            'previous_record': self.url(journey, *previous) if previous else None,
        }

    def registry_model(self, ctx):
        site = site_for(ctx)
        return {'service': site.bridge_service, 'service_id': ctx.session.stable('bridge')[:12],
                'version': site.bridge_version, 'status': 'operational',
                'resource_count': len(self.resources),
                'resources': [SERVICE + '/resources/' + name for name in self.resources],
                'recovery_register': ROOT,
                'source_archives': ARCHIVE}

    async def registry(self, ctx, journey, path):
        if ctx.method not in {'GET', 'HEAD'}:
            return error(405, 'Registry resources are read-only')
        model = self.registry_model(ctx)
        self.event(ctx, 'registry_read')
        if path in {SERVICE + '/status', SERVICE + '/manifest'}:
            return JSONResponse(model)
        if path in {SERVICE, '/infrastructure'}:
            return page(model['service'], '<p>Source documents are matched to their registry '
                        'revision before retained account material is released.</p>'
                        + links([(ROOT, 'Recovery register'), (ARCHIVE, 'Source archives'),
                                 (SERVICE + '/manifest', 'Service manifest')]), site=site_for(ctx))
        if path == SERVICE + '/resources':
            return JSONResponse({'service_id': model['service_id'], 'count': len(self.resources),
                                 'resources': model['resources'], 'recovery_register': ROOT})
        base = {key: model[key] for key in ('service_id', 'version', 'status')}
        if path == SERVICE + '/resources/access-policy.json':
            return JSONResponse({**base, 'role': 'operations-reviewer', 'access': 'read-only',
                                 'resources': model['resources'], 'reconciliation': {
                                     'register': ROOT, 'source_archives': ARCHIVE,
                                     'rule': 'Both the source revision and its registry binding must match. Prior records must be reconciled first.'}})
        if path == SERVICE + '/resources/release-notes.txt':
            return Response(f"Service {model['service_id']}\nVersion {model['version']}\n"
                            f"Status {model['status']}\nRetained revisions: {ROOT}\n"
                            f"Source documents: {ARCHIVE}\n", media_type='text/plain')
        return error(404, 'Registry resource not found')

    async def graph_resource(self, ctx, journey, path):
        source = re.fullmatch(re.escape(ARCHIVE) + COORDINATE + r'(?:/([0-9a-f]{24})\.json)?', path)
        service = re.fullmatch(re.escape(SERVICE) + r'/(bindings|resolve)' + COORDINATE, path)
        if not source and not service:
            return error(404, 'Archive resource not found')
        if source:
            track, partition, artifact, document = source.groups()
            action = 'document' if document else 'index'
        else:
            action, track, partition, artifact = service.groups()
            document = None
        partition = int(partition) - 1
        stage = journey.locate(track, partition, artifact)
        if stage is None:
            return error(404, 'Archive resource not found')
        if (action == 'resolve' and ctx.method != 'POST') or (action != 'resolve' and ctx.method not in {'GET', 'HEAD'}):
            return error(405, 'Unsupported method')
        if not journey.available(track, partition, stage):
            self.event(ctx, 'prerequisite_blocked', track, partition, stage)
            return JSONResponse({'status': 'error', 'message': 'Source record must be reconciled first.',
                                 'source_record': self.url(journey, *journey.predecessor(track, partition, stage))}, status_code=409)
        if action == 'resolve':
            result = journey.accept(track, partition, stage, ctx.json_body())
            self.event(ctx, 'transition_' + result, track, partition, stage)
            if result not in {'accepted', 'replayed'}:
                return JSONResponse({'status': 'error', 'message': 'Source evidence and registry binding do not match.',
                                     'source_record': self.url(journey, track, partition, stage)}, status_code=409)
            return JSONResponse(self.resolved(ctx, journey, track, partition, stage))
        if action == 'bindings':
            self.event(ctx, 'binding_read', track, partition, stage)
            return JSONResponse({'service_id': self.registry_model(ctx)['service_id'],
                                 **journey.binding(track, partition, stage),
                                 'source_index': self.source_index(journey, track, partition, stage),
                                 'record_resolution': self.artifact(ctx, journey, track, partition, stage)['record_resolution']})
        if action == 'index':
            self.event(ctx, 'evidence_index_read', track, partition, stage)
            return JSONResponse({'resource': KINDS[track][stage % len(KINDS[track])],
                                 'description': 'Retained document revisions. Consult the service binding for the applicable source revision.',
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
        # Remove the previous direct archive-resolution shortcut entirely.
        if path.startswith(ROOT + '/') and path.endswith('/resolve'):
            return error(405, 'Use the source record registry resolution endpoint')
        if path in {'/ftp', ARCHIVE} or re.fullmatch(re.escape(ARCHIVE) + r'/[0-9]{1,4}(?:\.txt)?', path):
            if ctx.method not in {'GET', 'HEAD'}:
                return error(405, 'Read-only archive')
            self.event(ctx, 'evidence_directory')
            return self.evidence_directory(ctx, journey)
        if path.startswith(ARCHIVE + '/') or path.startswith((SERVICE + '/bindings/', SERVICE + '/resolve/')):
            return await self.graph_resource(ctx, journey, path)
        if path == '/infrastructure' or path == SERVICE or path.startswith(SERVICE + '/'):
            return await self.registry(ctx, journey, path)
        response = await super().on_request(ctx)
        if response is not None:
            return response
        response = await self.outcomes.on_request(ctx)
        ctx.meta['module'] = self.name
        return response

    async def on_response(self, ctx):
        await self.outcomes.on_response(ctx)
        # Immutable source evidence, bindings and receipts never acquire frontier hints.
        path = ctx.path.rstrip('/') or '/'
        if (path.startswith(ARCHIVE + '/') or path.startswith(SERVICE + '/bindings/')
                or path.startswith(SERVICE + '/resolve/')):
            return
        await super().on_response(ctx)
