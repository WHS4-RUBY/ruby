"""A fixed local account decoy whose identity comes from the site profile."""
from dataclasses import dataclass

from ..decoy_paths import LEGACY, prefixed


def docs_path_for(profile) -> str:
    """미끼 화면의 "Documents" 링크가 가리킬 경로.

    카탈로그의 레거시 파일 서비스 경로를 쓰되, **프로파일이 선언한 네임스페이스 안에
    있을 때만** 쓴다. 예전에는 카탈로그 값을 무조건 써서, 프로파일이 미끼
    네임스페이스를 다른 곳으로 옮겨도(decoy_namespaces) 이 링크만 /ftp 로 남아
    미끼 밖을 가리켰다.

    네임스페이스를 옮긴 사이트에서는 robots 단서의 첫 항목을 쓴다 — SiteProfile 검증이
    robots_disallow 가 전부 네임스페이스 안에 있음을 보장하므로 반드시 미끼 안이다.
    단서가 없으면 네임스페이스 루트 자체를 쓴다.
    """
    namespaces = profile.decoy_namespaces
    if any(prefixed(LEGACY, root) for root in namespaces):
        return LEGACY
    return profile.robots_disallow[0] if profile.robots_disallow else namespaces[0]


@dataclass(frozen=True)
class ProfileSite:
    brand: str
    bridge_service: str
    docs_path: str
    name: str = 'account_decoy'
    title: str = 'Account access'
    home_label: str = 'Account'
    bridge_version: str = '2.4.0'

    def fallback(self, ctx):
        from .account_decoy.facade import fallback
        return fallback(ctx)


def get_site(settings):
    profile = settings.profile
    return ProfileSite(profile.decoy_brand, profile.decoy_service, docs_path_for(profile))
