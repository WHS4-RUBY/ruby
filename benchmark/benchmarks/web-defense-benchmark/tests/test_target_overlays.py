from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


def load_overlay(name: str) -> dict:
    path = REPOSITORY_ROOT / f"docker-compose.target.{name}.yml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


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
