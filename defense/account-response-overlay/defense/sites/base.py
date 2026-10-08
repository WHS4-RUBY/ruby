def site_for(ctx):
    if 'site' not in ctx.meta:
        from . import get_site
        ctx.meta['site'] = get_site(ctx.settings)
    return ctx.meta['site']
