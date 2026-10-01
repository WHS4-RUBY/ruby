from __future__ import annotations

import argparse
import json
import time

import httpx


DEVELOPMENT_PASSWORD = "RUBY-Development-Only-2026!"
ADMIN_PASSWORD = "RUBY-Operations-Only-2026!"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check all Stage 1 role flows")
    parser.add_argument("--public-url", default="http://127.0.0.1:18080")
    parser.add_argument("--control-url", default="http://127.0.0.1:18081")
    parser.add_argument("--reset-token", default="development-reset-only")
    args = parser.parse_args()
    control_headers = {"X-Ruby-Reset-Token": args.reset_token}

    def reset() -> None:
        response = httpx.post(
            f"{args.control_url}/internal/reset", headers=control_headers, timeout=20
        )
        response.raise_for_status()

    def state_hash() -> str:
        response = httpx.get(
            f"{args.control_url}/internal/state", headers=control_headers, timeout=20
        )
        response.raise_for_status()
        return response.json()["sha256"]

    def login(email: str, password: str = DEVELOPMENT_PASSWORD) -> dict[str, str]:
        response = httpx.post(
            f"{args.public_url}/api/auth/login",
            json={"email": email, "password": password},
            timeout=20,
        )
        response.raise_for_status()
        return {"Authorization": f"Bearer {response.json()['token']}"}

    reset()
    baseline_hash = state_hash()
    checks: dict[str, bool] = {}
    try:
        search = httpx.get(
            f"{args.public_url}/api/products", params={"q": "camera"}, timeout=20
        )
        search.raise_for_status()
        checks["guest_search"] = [item["id"] for item in search.json()] == ["ruby-camera"]
        inquiry = httpx.post(
            f"{args.public_url}/api/guest-inquiries",
            json={
                "email": "integration-guest@example.test",
                "subject": "Integration inquiry",
                "body": "Verify the public guest inquiry path.",
            },
            timeout=20,
        )
        inquiry.raise_for_status()

        seller = login("seller@ruby.local")
        customer = login("customer@ruby.local")
        support = login("support@ruby.local")
        admin = login("admin@ruby.local", ADMIN_PASSWORD)

        product = httpx.post(
            f"{args.public_url}/api/seller/products",
            headers=seller,
            json={
                "id": "integration-product",
                "name": "Integration Product",
                "description": "Created by the seller flow checker",
                "price_cents": 2500,
                "stock": 3,
            },
            timeout=20,
        )
        product.raise_for_status()
        checks["seller_product"] = product.json()["stock"] == 3

        order = httpx.post(
            f"{args.public_url}/api/orders",
            headers=customer,
            json={"items": [{"product_id": "integration-product", "quantity": 1}]},
            timeout=20,
        )
        order.raise_for_status()
        order_id = order.json()["id"]
        paid = httpx.post(
            f"{args.public_url}/api/orders/{order_id}/pay",
            headers=customer,
            json={"method": "wallet"},
            timeout=20,
        )
        paid.raise_for_status()
        shipped = httpx.patch(
            f"{args.public_url}/api/seller/orders/{order_id}",
            headers=seller,
            json={"status": "shipped"},
            timeout=20,
        )
        shipped.raise_for_status()
        refund_request = httpx.post(
            f"{args.public_url}/api/orders/{order_id}/refund-request",
            headers=customer,
            timeout=20,
        )
        refund_request.raise_for_status()
        refunded = httpx.patch(
            f"{args.public_url}/api/seller/orders/{order_id}",
            headers=seller,
            json={"status": "refunded"},
            timeout=20,
        )
        refunded.raise_for_status()
        checks["customer_seller_order"] = refunded.json()["status"] == "refunded"

        ticket = httpx.post(
            f"{args.public_url}/api/tickets",
            headers=customer,
            data={"subject": "Integration ticket", "body": "Verify support workflow."},
            files={
                "attachment": (
                    "integration-evidence.txt",
                    b"synthetic integration evidence",
                    "text/plain",
                )
            },
            timeout=20,
        )
        ticket.raise_for_status()
        ticket_id = ticket.json()["id"]
        attachment_available = False
        for _ in range(40):
            refreshed = httpx.get(
                f"{args.public_url}/api/tickets/{ticket_id}",
                headers=customer,
                timeout=20,
            )
            refreshed.raise_for_status()
            attachments = refreshed.json()["attachments"]
            if attachments and attachments[0]["status"] == "available":
                attachment_available = True
                break
            time.sleep(0.25)
        checks["attachment_worker"] = attachment_available
        reply = httpx.post(
            f"{args.public_url}/api/tickets/{ticket_id}/messages",
            headers=support,
            json={"body": "Support reply from integration checker."},
            timeout=20,
        )
        reply.raise_for_status()
        resolved = httpx.patch(
            f"{args.public_url}/api/tickets/{ticket_id}/status",
            headers=support,
            json={"status": "resolved"},
            timeout=20,
        )
        resolved.raise_for_status()
        checks["support_ticket"] = resolved.json()["status"] == "resolved"
        guest_resolved = httpx.patch(
            f"{args.public_url}/api/support/guest-inquiries/{inquiry.json()['id']}",
            headers=support,
            json={"status": "resolved"},
            timeout=20,
        )
        guest_resolved.raise_for_status()
        checks["support_guest_inquiry"] = guest_resolved.json()["status"] == "resolved"

        registered = httpx.post(
            f"{args.public_url}/api/auth/register",
            json={
                "email": "integration-role@example.test",
                "display_name": "Integration Role",
                "password": "Integration-role-password-2026!",
            },
            timeout=20,
        )
        registered.raise_for_status()
        promoted = httpx.patch(
            f"{args.public_url}/api/admin/users/{registered.json()['id']}/role",
            headers=admin,
            json={"role": "support_staff"},
            timeout=20,
        )
        promoted.raise_for_status()
        checks["admin_role"] = promoted.json()["role"] == "support_staff"
        checks["state_changed"] = state_hash() != baseline_hash
    finally:
        reset()

    restored_hash = state_hash()
    checks["state_restored"] = restored_hash == baseline_hash
    passed = all(checks.values())
    print(
        json.dumps(
            {
                "passed": passed,
                "baseline_sha256": baseline_hash,
                "restored_sha256": restored_hash,
                "checks": checks,
            },
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
