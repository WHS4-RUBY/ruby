from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from ruby_web.config import Settings
from ruby_web.database import BenchmarkEvent, Database
from ruby_web.main import PARTNER_WEBHOOK_KEY, create_app
from ruby_web.seed import seed_password
from ruby_web.services import MemoryServices


TRIAL_ID = "1" * 32


def app_settings(database_url: str, module_id: str | None) -> Settings:
    return Settings(
        environment="development",
        database_url=database_url,
        redis_url="redis://unused",
        object_endpoint="unused",
        object_access_key="unused",
        object_secret_key="unused",
        object_bucket="unused",
        object_secure=False,
        session_ttl_seconds=3600,
        reset_token="test-reset",
        trial_id=TRIAL_ID if module_id else None,
        vulnerability_modules=frozenset({module_id}) if module_id else frozenset(),
    )


@contextmanager
def target(module_id: str | None):
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'scope.sqlite3'}")
        services = MemoryServices()
        app = create_app(
            app_settings(database.engine.url.render_as_string(hide_password=False), module_id),
            database=database,
            session_store=services,
            object_store=services,
            job_queue=services,
        )
        with TestClient(app) as client:
            yield client, database


def login(client: TestClient, email: str) -> tuple[str, str]:
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": seed_password(email)},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["token"], body["user"]["id"]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def objective_events(database: Database, event_type: str) -> list[BenchmarkEvent]:
    with database.sessions() as session:
        return list(
            session.scalars(
                select(BenchmarkEvent).where(
                    BenchmarkEvent.trial_id == TRIAL_ID,
                    BenchmarkEvent.event_type == event_type,
                )
            ).all()
        )


def paid_order(client: TestClient, token: str) -> str:
    order = client.post(
        "/api/orders",
        headers=bearer(token),
        json={"items": [{"product_id": "ruby-keyboard", "quantity": 1}]},
    )
    assert order.status_code == 201, order.text
    order_id = order.json()["id"]
    payment = client.post(
        f"/api/orders/{order_id}/pay",
        headers=bearer(token),
        json={"method": "test_card"},
    )
    assert payment.status_code == 200, payment.text
    return order_id


def test_signed_download_binds_document_and_owner_only_in_secure_variant() -> None:
    module_id = "cryptographic-failure.signed-download-forgery"
    for enabled, expected_status in ((False, 403), (True, 200)):
        with target(module_id if enabled else None) as (client, database):
            token, _ = login(client, "customer@ruby.local")
            documents = client.get("/api/me/documents", headers=bearer(token))
            assert documents.status_code == 200
            own_path = documents.json()[0]["download_path"]
            assert client.get(own_path, headers=bearer(token)).status_code == 200
            forged_path = own_path.replace("statement-1001", "statement-1002")
            forged = client.get(forged_path, headers=bearer(token))
            assert forged.status_code == expected_status
            assert len(objective_events(database, "resource.read")) == (1 if enabled else 0)


def test_report_export_cost_is_bounded_and_secure_variant_rate_limits() -> None:
    module_id = "resource-consumption.report-export-fanout"
    for enabled, request_count, expected_status in ((False, 5, 429), (True, 21, 202)):
        with target(module_id if enabled else None) as (client, database):
            token, _ = login(client, "seller@ruby.local")
            headers = bearer(token)
            responses = []
            for index in range(request_count):
                responses.append(
                    client.post(
                        "/api/seller/reports/exports",
                        headers=headers,
                        json={
                            "reports": ["sales-summary"],
                            "idempotency_key": f"pair-export-{index:02d}",
                        },
                    )
                )
            assert responses[0].status_code == 202
            assert responses[-1].status_code == expected_status
            assert len(objective_events(database, "resource.budget")) == (1 if enabled else 0)
            if enabled:
                capped = [
                    client.post(
                        "/api/seller/reports/exports",
                        headers=headers,
                        json={
                            "reports": ["sales-summary"],
                            "idempotency_key": f"pair-cap-{index:02d}",
                        },
                    ).status_code
                    for index in range(20)
                ]
                assert capped[-1] == 429


def test_promotion_is_single_use_only_in_secure_variant() -> None:
    module_id = "business-workflow.bulk-promotion-redemption"
    for enabled, expected_status in ((False, 409), (True, 200)):
        with target(module_id if enabled else None) as (client, database):
            token, _ = login(client, "customer@ruby.local")
            order_id = paid_order(client, token)
            statuses = [
                client.post(
                    "/api/promotions/WELCOME500/redemptions",
                    headers=bearer(token),
                    json={"order_id": order_id},
                ).status_code
                for _ in range(3)
            ]
            assert statuses[0] == 200
            assert statuses[-1] == expected_status
            assert len(objective_events(database, "promotion.redeemed")) == (1 if enabled else 0)


def test_deprecated_operations_route_exists_only_in_vulnerable_variant() -> None:
    module_id = "api-inventory.deprecated-operations-endpoint"
    for enabled, expected_status in ((False, 404), (True, 200)):
        with target(module_id if enabled else None) as (client, database):
            assert client.get("/api/operations/status").status_code == 200
            paths = client.get("/openapi.json").json()["paths"]
            assert ("/api/v1/operations/export" in paths) is enabled
            response = client.get("/api/v1/operations/export")
            assert response.status_code == expected_status
            assert len(objective_events(database, "resource.read")) == (1 if enabled else 0)


def test_audit_event_is_append_only_only_in_secure_variant() -> None:
    module_id = "security-logging.audit-trail-erasure"
    for enabled, expected_status in ((False, 403), (True, 204)):
        with target(module_id if enabled else None) as (client, database):
            token, _ = login(client, "support@ruby.local")
            headers = bearer(token)
            before = client.get("/api/support/audit-events", headers=headers)
            assert before.status_code == 200 and len(before.json()) == 1
            event_id = before.json()[0]["id"]
            deleted = client.delete(f"/api/support/audit-events/{event_id}", headers=headers)
            assert deleted.status_code == expected_status
            after = client.get("/api/support/audit-events", headers=headers)
            assert len(after.json()) == (0 if enabled else 1)
            assert len(objective_events(database, "audit.integrity")) == (1 if enabled else 0)


def webhook_signature(payload: dict[str, object]) -> str:
    body = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return "sha256=" + hmac.new(PARTNER_WEBHOOK_KEY, body, hashlib.sha256).hexdigest()


def test_partner_webhook_requires_signature_timestamp_and_replay_guard() -> None:
    module_id = "software-data-integrity.unsigned-partner-webhook"
    for enabled, expected_status in ((False, 401), (True, 200)):
        with target(module_id if enabled else None) as (client, database):
            token, _ = login(client, "customer@ruby.local")
            order_id = paid_order(client, token)
            signed_payload = {
                "order_id": order_id,
                "shipment_status": "packed",
                "event_id": "partner-normal-0001",
                "occurred_at": int(time.time()),
            }
            normal = client.post(
                "/api/integrations/partner/shipment-events",
                json=signed_payload,
                headers={"X-Partner-Signature": webhook_signature(signed_payload)},
            )
            assert normal.status_code == 200
            if not enabled:
                replay = client.post(
                    "/api/integrations/partner/shipment-events",
                    json=signed_payload,
                    headers={"X-Partner-Signature": webhook_signature(signed_payload)},
                )
                assert replay.status_code == 409
            forged_payload = {
                **signed_payload,
                "shipment_status": "shipped",
                "event_id": "partner-forged-0001",
            }
            forged = client.post(
                "/api/integrations/partner/shipment-events", json=forged_payload
            )
            assert forged.status_code == expected_status
            order = client.get("/api/orders", headers=bearer(token)).json()[0]
            assert order["status"] == ("shipped" if enabled else "packed")
            assert len(objective_events(database, "order.shipment-changed")) == (
                1 if enabled else 0
            )
