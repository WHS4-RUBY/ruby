from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "app" / "compose.production.yaml"


def load_compose() -> dict:
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def network_names(service: dict) -> set[str]:
    networks = service.get("networks", {})
    if isinstance(networks, list):
        return set(networks)
    return set(networks)


def test_production_compose_uses_registry_images_without_host_ports() -> None:
    compose = load_compose()
    services = compose["services"]

    assert set(services) == {
        "postgres",
        "redis",
        "object-store",
        "mock-integration",
        "api",
        "worker",
        "evaluator",
        "web",
    }
    for service in services.values():
        assert "build" not in service
        assert "ports" not in service
        assert service["image"].startswith("${RUBY_BENCHMARK_IMAGE_PREFIX:")
        assert service["image"].endswith(
            ":${RUBY_BENCHMARK_IMAGE_TAG:?Set RUBY_BENCHMARK_IMAGE_TAG}"
        )


def test_only_web_joins_the_pipeline_network() -> None:
    services = load_compose()["services"]

    assert network_names(services["web"]) == {"pipeline", "edge"}
    assert services["web"]["networks"]["pipeline"]["aliases"] == [
        "ruby-web-target"
    ]
    assert all(
        "pipeline" not in network_names(service)
        for name, service in services.items()
        if name != "web"
    )


def test_evaluator_and_data_services_remain_private() -> None:
    compose = load_compose()
    services = compose["services"]

    assert compose["networks"]["pipeline"]["external"] is True
    assert all(
        compose["networks"][name]["internal"] is True
        for name in ("edge", "data", "control")
    )
    assert network_names(services["evaluator"]) == {"control"}
    assert network_names(services["api"]) == {"edge", "data"}
    assert network_names(services["postgres"]) == {"data", "control"}
    assert network_names(services["redis"]) == {"data"}
    assert network_names(services["object-store"]) == {"data"}
    assert all("/var/run/docker.sock" not in str(service) for service in services.values())


def test_production_secrets_have_no_development_fallbacks() -> None:
    services = load_compose()["services"]
    rendered = str(services)

    required_names = {
        "POSTGRES_PASSWORD",
        "POSTGRES_APP_PASSWORD",
        "POSTGRES_UNTRUSTED_PASSWORD",
        "POSTGRES_VERIFIER_PASSWORD",
        "RUBY_WEB_OBJECT_ACCESS_KEY",
        "RUBY_WEB_OBJECT_SECRET_KEY",
        "RUBY_WEB_RESET_TOKEN",
        "RUBY_EVALUATOR_TOKEN",
        "RUBY_WEB_OPERATIONS_DIAGNOSTIC_KEY",
    }
    assert all(f"${{{name}:?" in rendered for name in required_names)
    assert "development-only" not in rendered
    assert "ops_sk_live_" not in rendered
