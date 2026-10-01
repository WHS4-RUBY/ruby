import json
from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
ROOT_COMPOSE_PATH = REPOSITORY_ROOT / "docker-compose.yml"
LOCAL_COMPOSE_PATH = REPOSITORY_ROOT / "docker-compose.local.yml"
PRODUCTION_COMPOSE_PATH = (
    Path(__file__).resolve().parents[1] / "app" / "compose.production.yaml"
)


def load_overlay(name: str) -> dict:
    path = REPOSITORY_ROOT / f"docker-compose.target.{name}.yml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def environment_map(service: dict) -> dict[str, str]:
    environment = service.get("environment", {})
    if isinstance(environment, dict):
        return {str(key): str(value) for key, value in environment.items()}
    return {
        str(item).split("=", 1)[0]: str(item).split("=", 1)[1]
        for item in environment
    }


def test_juice_shop_overlay_selects_the_existing_target() -> None:
    overlay = load_overlay("juice-shop")

    assert set(overlay["services"]) == {"defense"}
    assert overlay["services"]["defense"]["environment"] == {
        "BENCHMARK_TARGET_URL": "http://benchmark-target:3000"
    }


def test_ruby_web_overlay_selects_only_the_public_web_service() -> None:
    overlay = load_overlay("ruby-web")

    assert set(overlay["services"]) == {"defense"}
    assert overlay["services"]["defense"]["environment"] == {
        "BENCHMARK_TARGET_URL": "http://ruby-web-target:8080"
    }
    assert "evaluator" not in str(overlay)
    assert "postgres" not in str(overlay)


def test_current_team_pipeline_has_no_separate_policy_hop() -> None:
    for compose_path in (ROOT_COMPOSE_PATH, LOCAL_COMPOSE_PATH):
        services = load_yaml(compose_path)["services"]
        assert "policy" not in services
        assert environment_map(services["detection"])["TARGET_URL"] == (
            "http://defense:8080"
        )
        assert environment_map(services["defense"])["BENCHMARK_TARGET_URL"] == (
            "http://benchmark-target:3000"
        )
        # The site overlay can disable this service; the default stack still
        # starts it and --wait checks its health.
        assert "benchmark-target" not in services["defense"].get("depends_on", {})
        assert services["detection"]["depends_on"]["defense"]["condition"] == (
            "service_healthy"
        )


def test_site_overlay_uses_a_profile_and_disables_the_bundled_target() -> None:
    overlay = load_overlay("site")
    assert environment_map(overlay["services"]["detection"])["TARGET_PROFILE_FILE"] == (
        "/app/config/target.json"
    )
    [mount] = overlay["services"]["detection"]["volumes"]
    assert mount["target"] == "/app/config/target.json"
    assert mount["read_only"] is True
    assert environment_map(overlay["services"]["defense"])["BENCHMARK_TARGET_URL"].startswith(
        "${RUBY_TARGET_URL:?"
    )
    assert overlay["services"]["benchmark-target"]["profiles"] == ["bundled-juice-shop"]


def test_target_profile_examples_use_distinct_bait_paths() -> None:
    paths = set()
    for name in ("juice-shop", "ruby-market", "site.example"):
        path = REPOSITORY_ROOT / "target-profiles" / f"{name}.json"
        profile = json.loads(path.read_text(encoding="utf-8"))
        assert profile["version"] == 1
        for trap in profile["bait"]["traps"]:
            assert trap["path"].startswith("/__ruby_bait/")
            assert trap["path"] not in paths
            paths.add(trap["path"])


def test_root_and_ruby_web_stacks_share_an_explicit_pipeline_network() -> None:
    root_compose = load_yaml(ROOT_COMPOSE_PATH)
    production_compose = load_yaml(PRODUCTION_COMPOSE_PATH)

    assert root_compose["networks"]["ai-defense-net"]["name"] == (
        "${RUBY_PIPELINE_NETWORK:-ruby_ai-defense-net}"
    )
    assert production_compose["networks"]["pipeline"] == {
        "external": True,
        "name": "${RUBY_BENCHMARK_PIPELINE_NETWORK:-ruby_ai-defense-net}",
    }
    assert production_compose["services"]["web"]["networks"]["pipeline"][
        "aliases"
    ] == ["ruby-web-target"]
