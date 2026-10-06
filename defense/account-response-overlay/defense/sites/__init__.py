"""A fixed local account decoy whose identity comes from the site profile."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ProfileSite:
    brand: str
    bridge_service: str
    name: str = 'account_decoy'
    title: str = 'Account access'
    home_label: str = 'Account'
    docs_path: str = '/ftp'
    bridge_version: str = '2.4.0'

    def fallback(self, ctx):
        from .juice_shop.facade import fallback
        return fallback(ctx)


def get_site(settings):
    return ProfileSite(settings.profile.decoy_brand, settings.profile.decoy_service)
