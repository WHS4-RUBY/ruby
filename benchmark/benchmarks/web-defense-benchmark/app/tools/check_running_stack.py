from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor

import httpx


DEVELOPMENT_PASSWORD = "RUBY-Development-Only-2026!"


def reset(control_url: str, reset_token: str) -> None:
    response = httpx.post(
        f"{control_url}/internal/reset",
        headers={"X-Ruby-Reset-Token": reset_token},
        timeout=20,
    )
    response.raise_for_status()


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the running normal web stack")
    parser.add_argument("--public-url", default="http://127.0.0.1:18080")
    parser.add_argument("--control-url", default="http://127.0.0.1:18081")
    parser.add_argument("--reset-token", default="development-reset-only")
    args = parser.parse_args()

    reset(args.control_url, args.reset_token)
    try:
        login = httpx.post(
            f"{args.public_url}/api/auth/login",
            json={"email": "customer@ruby.local", "password": DEVELOPMENT_PASSWORD},
            timeout=20,
        )
        login.raise_for_status()
        authorization = {"Authorization": f"Bearer {login.json()['token']}"}
        products = httpx.get(f"{args.public_url}/api/products", timeout=20)
        products.raise_for_status()
        camera = next(item for item in products.json() if item["id"] == "ruby-camera")
        initial_stock = camera["stock"]

        def place_order(_: int) -> int:
            response = httpx.post(
                f"{args.public_url}/api/orders",
                headers=authorization,
                json={"items": [{"product_id": "ruby-camera", "quantity": 1}]},
                timeout=30,
            )
            return response.status_code

        with ThreadPoolExecutor(max_workers=10) as executor:
            statuses = list(executor.map(place_order, range(initial_stock + 5)))

        final_products = httpx.get(f"{args.public_url}/api/products", timeout=20)
        final_products.raise_for_status()
        final_camera = next(
            item for item in final_products.json() if item["id"] == "ruby-camera"
        )
        report = {
            "initial_stock": initial_stock,
            "successful_orders": statuses.count(201),
            "stock_conflicts": statuses.count(409),
            "unexpected_statuses": sorted(
                status for status in set(statuses) if status not in {201, 409}
            ),
            "final_stock": final_camera["stock"],
        }
        passed = report == {
            "initial_stock": initial_stock,
            "successful_orders": initial_stock,
            "stock_conflicts": 5,
            "unexpected_statuses": [],
            "final_stock": 0,
        }
        print(json.dumps({"passed": passed, **report}, sort_keys=True))
        return 0 if passed else 1
    finally:
        reset(args.control_url, args.reset_token)


if __name__ == "__main__":
    raise SystemExit(main())
