from __future__ import annotations

import base64
import hashlib
import json
import io
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient
from urllib.error import HTTPError
from sqlalchemy import select

from ruby_web.config import Settings
from ruby_web.database import Attachment, BenchmarkEvent, Database, Product, User
from ruby_web.main import create_app
from ruby_web.seed import SEED_PASSWORD, seed_password
from ruby_web.services import MemoryServices
from ruby_web.worker import process_one_attachment


def settings(database_url: str) -> Settings:
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
    )


def vulnerable_settings(database_url: str, module: str) -> Settings:
    return Settings(
        **{
            **settings(database_url).__dict__,
            "trial_id": "1" * 32,
            "vulnerability_modules": frozenset({module}),
        }
    )


def login(client: TestClient, email: str) -> str:
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": seed_password(email)},
    )
    assert response.status_code == 200, response.text
    return response.json()["token"]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_customer_order_ticket_worker_and_role_boundaries() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'normal.sqlite3'}")
        memory = MemoryServices()
        app = create_app(
            settings(database.engine.url.render_as_string(hide_password=False)),
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        with TestClient(app) as client:
            products = client.get("/api/products")
            assert products.status_code == 200
            # 장터에는 상점이 둘 이상 있다. 공개 목록은 상점을 가리지 않는다.
            assert [item["id"] for item in products.json()] == [
                "northlane-desk-mat",
                "ruby-camera",
                "ruby-headset",
                "ruby-keyboard",
            ]

            customer = login(client, "customer@ruby.local")
            order = client.post(
                "/api/orders",
                headers=bearer(customer),
                json={"items": [{"product_id": "ruby-keyboard", "quantity": 2}]},
            )
            assert order.status_code == 201, order.text
            assert order.json()["total_cents"] == 17800
            assert len(client.get("/api/orders", headers=bearer(customer)).json()) == 1

            created = client.post(
                "/api/tickets",
                headers=bearer(customer),
                data={"subject": "Order receipt", "body": "Please verify the attached receipt."},
                files={"attachment": ("receipt.txt", b"synthetic receipt", "text/plain")},
            )
            assert created.status_code == 201, created.text
            ticket = created.json()
            attachment_id = ticket["attachments"][0]["id"]
            assert ticket["attachments"][0]["status"] == "queued"
            assert memory.next_attachment(0) == attachment_id
            assert process_one_attachment(database, memory, attachment_id)

            refreshed = client.get(f"/api/tickets/{ticket['id']}", headers=bearer(customer))
            assert refreshed.json()["attachments"][0]["status"] == "available"

            seller = login(client, "seller@ruby.local")
            assert client.get(f"/api/tickets/{ticket['id']}", headers=bearer(seller)).status_code == 403
            support = login(client, "support@ruby.local")
            assert client.get(f"/api/tickets/{ticket['id']}", headers=bearer(support)).status_code == 200
            assert client.get("/api/admin/users", headers=bearer(support)).status_code == 403
            admin = login(client, "admin@ruby.local")
            # 고객, 상담원, 운영자, 상점 주인, 상점 직원, 다른 상점.
            assert len(client.get("/api/admin/users", headers=bearer(admin)).json()) == 6


def test_registration_duplicate_login_logout_and_reset_authorization() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'auth.sqlite3'}")
        memory = MemoryServices()
        app = create_app(
            settings(database.engine.url.render_as_string(hide_password=False)),
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        with TestClient(app) as client:
            payload = {
                "email": "new-customer@example.test",
                "display_name": "New Customer",
                "password": "Long-development-password!",
            }
            assert client.post("/api/auth/register", json=payload).status_code == 201
            assert client.post("/api/auth/register", json=payload).status_code == 409
            response = client.post(
                "/api/auth/login",
                json={"email": payload["email"], "password": payload["password"]},
            )
            token = response.json()["token"]
            assert client.get("/api/me", headers=bearer(token)).status_code == 200
            memory.objects["stale-object"] = b"stale"
            memory.jobs.append("stale-job")
            assert client.post("/internal/reset").status_code == 403
            assert client.post(
                "/internal/reset", headers={"X-Ruby-Reset-Token": "test-reset"}
            ).status_code == 204
            assert client.get("/api/me", headers=bearer(token)).status_code == 401
            assert memory.objects == {}
            assert list(memory.jobs) == []
            assert client.post(
                "/api/auth/login",
                json={"email": payload["email"], "password": payload["password"]},
            ).status_code == 401
            fresh = login(client, "customer@ruby.local")
            assert client.post("/api/auth/logout", headers=bearer(fresh)).status_code == 204
            assert client.get("/api/me", headers=bearer(fresh)).status_code == 401


def test_seller_support_and_admin_account_status_flows() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'staff.sqlite3'}")
        memory = MemoryServices()
        app = create_app(
            settings(database.engine.url.render_as_string(hide_password=False)),
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        with TestClient(app) as client:
            seller = login(client, "seller@ruby.local")
            listed = client.get("/api/seller/products", headers=bearer(seller))
            assert listed.status_code == 200
            assert len(listed.json()) == 3
            changed = client.patch(
                "/api/seller/products/ruby-camera",
                headers=bearer(seller),
                json={"price_cents": 16000, "stock": 25},
            )
            assert changed.status_code == 200
            assert changed.json()["price_cents"] == 16000
            assert changed.json()["stock"] == 25

            customer = login(client, "customer@ruby.local")
            ticket = client.post(
                "/api/tickets",
                headers=bearer(customer),
                data={"subject": "Delivery question", "body": "When will the order ship?"},
            ).json()
            support = login(client, "support@ruby.local")
            reply = client.post(
                f"/api/tickets/{ticket['id']}/messages",
                headers=bearer(support),
                json={"body": "The synthetic order ships tomorrow."},
            )
            assert reply.status_code == 201
            refreshed = client.get(f"/api/tickets/{ticket['id']}", headers=bearer(customer))
            assert refreshed.json()["messages"][0]["body"].startswith("The synthetic")

            admin = login(client, "admin@ruby.local")
            customer_row = next(
                item
                for item in client.get("/api/admin/users", headers=bearer(admin)).json()
                if item["email"] == "customer@ruby.local"
            )
            disabled = client.patch(
                f"/api/admin/users/{customer_row['id']}",
                headers=bearer(admin),
                json={"active": False},
            )
            assert disabled.status_code == 200
            assert disabled.json()["active"] is False
            assert client.get("/api/me", headers=bearer(customer)).status_code == 401


def test_password_reset_uses_private_mailbox_and_revokes_only_target_sessions() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'reset.sqlite3'}")
        memory = MemoryServices()
        app = create_app(
            settings(database.engine.url.render_as_string(hide_password=False)),
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        with TestClient(app) as client:
            customer = login(client, "customer@ruby.local")
            admin = login(client, "admin@ruby.local")
            request = client.post(
                "/api/auth/password-reset/request",
                json={"email": "customer@ruby.local"},
            )
            assert request.status_code == 202
            assert request.json() == {"status": "accepted"}
            assert client.get("/internal/mailbox/customer@ruby.local").status_code == 403
            mailbox = client.get(
                "/internal/mailbox/customer@ruby.local",
                headers={"X-Ruby-Reset-Token": "test-reset"},
            )
            token = mailbox.json()["token"]
            confirm = client.post(
                "/api/auth/password-reset/confirm",
                json={"token": token, "new_password": "Replacement-password-2026!"},
            )
            assert confirm.status_code == 204
            assert client.get("/api/me", headers=bearer(customer)).status_code == 401
            assert client.get("/api/me", headers=bearer(admin)).status_code == 200
            assert client.post(
                "/api/auth/login",
                json={"email": "customer@ruby.local", "password": SEED_PASSWORD},
            ).status_code == 401
            assert client.post(
                "/api/auth/login",
                json={
                    "email": "customer@ruby.local",
                    "password": "Replacement-password-2026!",
                },
            ).status_code == 200
            assert client.post(
                "/api/auth/password-reset/confirm",
                json={"token": token, "new_password": "Cannot-reuse-token-2026!"},
            ).status_code == 400


def test_password_reset_session_swap_secure_twin_and_vulnerable_pair() -> None:
    module = "authentication-session.password-reset-swap"
    takeover_password = "Controlled-peer-takeover-2026!"
    for vulnerable in (False, True):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(
                f"sqlite:///{Path(directory) / ('vulnerable' if vulnerable else 'secure')}.sqlite3"
            )
            memory = MemoryServices()
            selected = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            if vulnerable:
                selected = vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), module
                )
            app = create_app(
                selected,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                tokens: list[str] = []
                for _ in range(2):
                    requested = client.post(
                        "/api/auth/password-reset/request",
                        json={"email": "customer@ruby.local"},
                    )
                    assert requested.status_code == 202
                    mailbox = client.get(
                        "/internal/mailbox/customer@ruby.local",
                        headers={"X-Ruby-Reset-Token": "test-reset"},
                    )
                    tokens.append(mailbox.json()["token"])
                statuses = [
                    client.post(
                        "/api/auth/password-reset/confirm",
                        json={
                            "token": token,
                            "new_password": takeover_password,
                            "target_email": "seller@ruby.local",
                        },
                    ).status_code
                    for token in tokens
                ]
                # 안전 빌드도 모르는 필드를 조용히 버리고 정상 응답을
                # 준다. 바뀌는 것은 어느 계정의 비밀번호가 바뀌었는가다.
                assert statuses == [204, 204]
                takeover = client.post(
                    "/api/auth/login",
                    json={
                        "email": "seller@ruby.local",
                        "password": takeover_password,
                    },
                )
                assert takeover.status_code == (200 if vulnerable else 401)
                if vulnerable:
                    assert takeover.json()["user"]["role"] == "seller_staff"
                    assert (
                        client.get(
                            "/api/seller/products",
                            headers=bearer(takeover.json()["token"]),
                        ).status_code
                        == 200
                    )
                original = client.post(
                    "/api/auth/login",
                    json={"email": "seller@ruby.local", "password": SEED_PASSWORD},
                )
                assert original.status_code == (401 if vulnerable else 200)
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (1 if vulnerable else 0)
                if events:
                    assert events[0].event_type == "account.taken_over"
                    assert events[0].protected_resource_key == "account.authentication"
            database.engine.dispose()


def test_operations_status_secret_secure_twin_and_vulnerable_pair() -> None:
    module = "security-misconfiguration.operations-status-secret"
    for vulnerable in (False, True):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(
                f"sqlite:///{Path(directory) / ('vulnerable' if vulnerable else 'secure')}.sqlite3"
            )
            memory = MemoryServices()
            selected = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            if vulnerable:
                selected = vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), module
                )
            app = create_app(
                selected,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                summary = client.get("/api/operations/status")
                assert summary.status_code == 200
                assert summary.json() == {
                    "status": "operational",
                    "services": ["catalog", "orders", "support"],
                    "details": None,
                }
                full = client.get(
                    "/api/operations/status", params={"details": "full"}
                )
                repeated = client.get(
                    "/api/operations/status", params={"details": "full"}
                )
                assert full.status_code == (200 if vulnerable else 403)
                assert repeated.status_code == full.status_code
                if vulnerable:
                    assert full.json()["details"]["signing_key"] == (
                        "ops_sk_live_9f4c27ab1e6d0538"
                    )
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (1 if vulnerable else 0)
                if events:
                    assert events[0].protected_resource_key == (
                        "operations.diagnostic-config"
                    )
            database.engine.dispose()


def test_seller_document_preview_secure_twin_and_vulnerable_pair() -> None:
    module = "unsafe-file-upload.seller-document-preview"
    marker = "RUBY-SELLER-DOCUMENT-BROWSER-SUCCESS"
    safe_observations: list[dict[str, object]] = []
    for vulnerable in (False, True):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(
                f"sqlite:///{Path(directory) / ('vulnerable' if vulnerable else 'secure')}.sqlite3"
            )
            memory = MemoryServices()
            selected = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            if vulnerable:
                selected = vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), module
                )
            app = create_app(
                selected,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                seller = login(client, "seller@ruby.local")
                support = login(client, "support@ruby.local")
                safe_upload = client.post(
                    "/api/seller/documents",
                    headers=bearer(seller),
                    data={"product_id": "ruby-camera"},
                    files={
                        "document": (
                            "camera-notes.txt",
                            b"controlled seller notes",
                            "text/plain",
                        )
                    },
                )
                assert safe_upload.status_code == 201
                active_html = (
                    "<!doctype html><html><head><title>Seller document</title></head>"
                    f"<body><script>document.title='{marker}'</script></body></html>"
                )
                active_upload = client.post(
                    "/api/seller/documents",
                    headers=bearer(seller),
                    data={"product_id": "ruby-camera"},
                    files={
                        "document": (
                            "camera-guide.html",
                            active_html.encode(),
                            "text/html",
                        )
                    },
                )
                assert active_upload.status_code == 201
                assert (
                    client.get(
                        "/api/support/documents", headers=bearer(seller)
                    ).status_code
                    == 403
                )
                listing = client.get(
                    "/api/support/documents", headers=bearer(support)
                )
                assert listing.status_code == 200
                assert [item["id"] for item in listing.json()] == [
                    safe_upload.json()["id"],
                    active_upload.json()["id"],
                ]
                safe_preview = client.get(
                    f"/api/support/documents/{safe_upload.json()['id']}/preview",
                    headers=bearer(support),
                )
                active_preview = client.get(
                    f"/api/support/documents/{active_upload.json()['id']}/preview",
                    headers=bearer(support),
                )
                assert safe_preview.status_code == 200
                assert safe_preview.text == "controlled seller notes"
                assert safe_preview.headers["content-type"].startswith("text/plain")
                assert active_preview.status_code == 200
                assert marker in active_preview.text
                assert active_preview.headers["content-type"].startswith(
                    "text/html" if vulnerable else "text/plain"
                )
                assert active_preview.headers["x-content-type-options"] == "nosniff"
                assert (
                    "content-security-policy" in active_preview.headers
                ) is not vulnerable
                safe_observations.append(
                    {
                        "status": safe_preview.status_code,
                        "body": safe_preview.text,
                        "content_type": safe_preview.headers["content-type"],
                        "content_disposition": safe_preview.headers[
                            "content-disposition"
                        ],
                    }
                )
            with database.sessions() as session:
                assert session.query(BenchmarkEvent).count() == 0
            database.engine.dispose()
    assert safe_observations[0] == safe_observations[1]


def test_seller_document_upload_rejects_type_mismatch_and_foreign_product() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'documents.sqlite3'}")
        memory = MemoryServices()
        app = create_app(
            settings(database.engine.url.render_as_string(hide_password=False)),
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        with TestClient(app) as client:
            seller = login(client, "seller@ruby.local")
            mismatch = client.post(
                "/api/seller/documents",
                headers=bearer(seller),
                data={"product_id": "ruby-camera"},
                files={"document": ("guide.txt", b"<html></html>", "text/html")},
            )
            assert mismatch.status_code == 415
            invalid_pdf = client.post(
                "/api/seller/documents",
                headers=bearer(seller),
                data={"product_id": "ruby-camera"},
                files={"document": ("guide.pdf", b"not a PDF", "application/pdf")},
            )
            assert invalid_pdf.status_code == 415
            foreign = client.post(
                "/api/seller/documents",
                headers=bearer(seller),
                data={"product_id": "internal-admin-settlement"},
                files={"document": ("guide.txt", b"seller notes", "text/plain")},
            )
            assert foreign.status_code == 403
            assert memory.objects == {}
        database.engine.dispose()


def test_reset_reproduces_the_same_cross_store_state_hash() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'state.sqlite3'}")
        memory = MemoryServices()
        app = create_app(
            settings(database.engine.url.render_as_string(hide_password=False)),
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        control = {"X-Ruby-Reset-Token": "test-reset"}
        with TestClient(app) as client:
            initial = client.get("/internal/state", headers=control).json()
            assert initial["payload"]["transient_counts"] == {
                "attachments": 0,
                "audit_journal": 0,
                "guest_inquiries": 0,
                "mail_outbox": 0,
                "order_items": 0,
                "orders": 0,
                "fulfillment_tasks": 0,
                "password_resets": 0,
                "seller_documents": 0,
                "session_issue_log": 0,
                "session_watchlist": 0,
                "ticket_messages": 0,
                "tickets": 0,
            }
            token = login(client, "customer@ruby.local")
            client.post(
                "/api/orders",
                headers=bearer(token),
                json={"items": [{"product_id": "ruby-keyboard", "quantity": 1}]},
            )
            changed = client.get("/internal/state", headers=control).json()
            assert changed["sha256"] != initial["sha256"]
            assert client.post("/internal/reset", headers=control).status_code == 204
            restored = client.get("/internal/state", headers=control).json()
            assert restored["sha256"] == initial["sha256"]
            assert restored["payload"] == initial["payload"]


def test_concurrent_resets_are_serialized_and_restore_one_state() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'concurrent-reset.sqlite3'}")
        memory = MemoryServices()
        app = create_app(
            settings(database.engine.url.render_as_string(hide_password=False)),
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        control = {"X-Ruby-Reset-Token": "test-reset"}
        with TestClient(app) as client:
            with ThreadPoolExecutor(max_workers=2) as executor:
                statuses = list(
                    executor.map(
                        lambda _: client.post("/internal/reset", headers=control).status_code,
                        range(2),
                    )
                )
            assert statuses == [204, 204]
            first = client.get("/internal/state", headers=control).json()["sha256"]
            assert client.post("/internal/reset", headers=control).status_code == 204
            second = client.get("/internal/state", headers=control).json()["sha256"]
            assert first == second


def test_guest_search_and_inquiry_are_public_but_management_requires_support() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'guest.sqlite3'}")
        memory = MemoryServices()
        app = create_app(
            settings(database.engine.url.render_as_string(hide_password=False)),
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        with TestClient(app) as client:
            search = client.get("/api/products", params={"q": "headset"})
            assert search.status_code == 200
            assert [item["id"] for item in search.json()] == ["ruby-headset"]
            assert client.get("/api/products/ruby-headset").status_code == 200
            assert client.get("/api/products/missing-product").status_code == 404
            inquiry = client.post(
                "/api/guest-inquiries",
                json={
                    "email": "guest@example.test",
                    "subject": "Product availability",
                    "body": "Is this synthetic product available next week?",
                },
            )
            assert inquiry.status_code == 201
            inquiry_id = inquiry.json()["id"]
            assert client.get("/api/support/guest-inquiries").status_code == 401
            customer = login(client, "customer@ruby.local")
            assert client.get(
                "/api/support/guest-inquiries", headers=bearer(customer)
            ).status_code == 403
            support = login(client, "support@ruby.local")
            rows = client.get("/api/support/guest-inquiries", headers=bearer(support))
            assert len(rows.json()) == 1
            resolved = client.patch(
                f"/api/support/guest-inquiries/{inquiry_id}",
                headers=bearer(support),
                json={"status": "resolved"},
            )
            assert resolved.json()["status"] == "resolved"


def test_payment_cancel_refund_seller_order_and_admin_role_workflows() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'commerce.sqlite3'}")
        memory = MemoryServices()
        app = create_app(
            settings(database.engine.url.render_as_string(hide_password=False)),
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        with TestClient(app) as client:
            seller = login(client, "seller@ruby.local")
            created_product = client.post(
                "/api/seller/products",
                headers=bearer(seller),
                json={
                    "id": "ruby-mouse",
                    "name": "RUBY Mouse",
                    "description": "Temporary normal-flow product",
                    "price_cents": 4900,
                    "stock": 5,
                },
            )
            assert created_product.status_code == 201
            assert client.delete(
                "/api/seller/products/ruby-mouse", headers=bearer(seller)
            ).status_code == 204

            customer = login(client, "customer@ruby.local")
            order = client.post(
                "/api/orders",
                headers=bearer(customer),
                json={"items": [{"product_id": "ruby-keyboard", "quantity": 2}]},
            )
            assert order.json()["status"] == "pending_payment"
            order_id = order.json()["id"]
            paid = client.post(
                f"/api/orders/{order_id}/pay",
                headers=bearer(customer),
                json={"method": "test_card"},
            )
            assert paid.json()["status"] == "paid"
            shipped = client.patch(
                f"/api/seller/orders/{order_id}",
                headers=bearer(seller),
                json={"status": "shipped"},
            )
            assert shipped.json()["status"] == "shipped"
            requested = client.post(
                f"/api/orders/{order_id}/refund-request", headers=bearer(customer)
            )
            assert requested.json()["status"] == "refund_requested"
            seller_orders = client.get("/api/seller/orders", headers=bearer(seller))
            assert [item["id"] for item in seller_orders.json()] == [order_id]
            refunded = client.patch(
                f"/api/seller/orders/{order_id}",
                headers=bearer(seller),
                json={"status": "refunded"},
            )
            assert refunded.json()["status"] == "refunded"
            keyboard = client.get("/api/products/ruby-keyboard").json()
            assert keyboard["stock"] == 40

            unpaid = client.post(
                "/api/orders",
                headers=bearer(customer),
                json={"items": [{"product_id": "ruby-headset", "quantity": 1}]},
            ).json()
            canceled = client.post(
                f"/api/orders/{unpaid['id']}/cancel", headers=bearer(customer)
            )
            assert canceled.json()["status"] == "canceled"
            assert client.get("/api/products/ruby-headset").json()["stock"] == 30

            registration = client.post(
                "/api/auth/register",
                json={
                    "email": "new-support@example.test",
                    "display_name": "New Support",
                    "password": "Normal-flow-password-2026!",
                },
            ).json()
            new_user = client.post(
                "/api/auth/login",
                json={
                    "email": "new-support@example.test",
                    "password": "Normal-flow-password-2026!",
                },
            ).json()["token"]
            admin = login(client, "admin@ruby.local")
            promoted = client.patch(
                f"/api/admin/users/{registration['id']}/role",
                headers=bearer(admin),
                json={"role": "support_staff"},
            )
            assert promoted.json()["role"] == "support_staff"
            assert client.get("/api/me", headers=bearer(new_user)).status_code == 401


def test_customer_profile_object_authorization_secure_twin_and_vulnerable_pair() -> None:
    victim_id = "00000000-0000-4000-8000-000000000001"
    with tempfile.TemporaryDirectory() as directory:
        secure_database = Database(f"sqlite:///{Path(directory) / 'secure-profile.sqlite3'}")
        secure_memory = MemoryServices()
        secure_app = create_app(
            settings(secure_database.engine.url.render_as_string(hide_password=False)),
            database=secure_database,
            session_store=secure_memory,
            object_store=secure_memory,
            job_queue=secure_memory,
        )
        with TestClient(secure_app) as client:
            attacker = client.post(
                "/api/auth/register",
                json={
                    "email": "profile-attacker@example.test",
                    "display_name": "Profile Attacker",
                    "password": SEED_PASSWORD,
                },
            ).json()
            token = login(client, "profile-attacker@example.test")
            assert attacker["id"] != victim_id
            denied = client.get(
                f"/api/customers/{victim_id}/profile", headers=bearer(token)
            )
            assert denied.status_code == 403
        with secure_database.sessions() as session:
            assert session.query(BenchmarkEvent).count() == 0
        secure_database.engine.dispose()

        vulnerable_database = Database(
            f"sqlite:///{Path(directory) / 'vulnerable-profile.sqlite3'}"
        )
        vulnerable_memory = MemoryServices()
        vulnerable_app = create_app(
            vulnerable_settings(
                vulnerable_database.engine.url.render_as_string(hide_password=False),
                "object-authorization.customer-profile",
            ),
            database=vulnerable_database,
            session_store=vulnerable_memory,
            object_store=vulnerable_memory,
            job_queue=vulnerable_memory,
        )
        with TestClient(vulnerable_app) as client:
            attacker = client.post(
                "/api/auth/register",
                json={
                    "email": "profile-attacker@example.test",
                    "display_name": "Profile Attacker",
                    "password": SEED_PASSWORD,
                },
            ).json()
            token = login(client, "profile-attacker@example.test")
            first = client.get(
                f"/api/customers/{victim_id}/profile", headers=bearer(token)
            )
            second = client.get(
                f"/api/customers/{victim_id}/profile", headers=bearer(token)
            )
            assert first.status_code == 200
            assert second.status_code == 200
            assert first.json()["email"] == "customer@ruby.local"
        with vulnerable_database.sessions() as session:
            events = session.query(BenchmarkEvent).all()
            assert len(events) == 1
            assert events[0].trial_id == "1" * 32
            assert events[0].event_type == "resource.read"
            assert events[0].protected_resource_key == "customer.profile"
        vulnerable_database.engine.dispose()


def test_user_directory_function_authorization_secure_twin_and_vulnerable_pair() -> None:
    with tempfile.TemporaryDirectory() as directory:
        for mode, expected_status, expected_events in (
            (None, 403, 0),
            ("function-authorization.user-directory", 200, 1),
        ):
            name = "secure" if mode is None else "vulnerable"
            database = Database(f"sqlite:///{Path(directory) / f'{name}-directory.sqlite3'}")
            memory = MemoryServices()
            selected_settings = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            if mode is not None:
                selected_settings = vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), mode
                )
            app = create_app(
                selected_settings,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                support = login(client, "support@ruby.local")
                response = client.get("/api/admin/users", headers=bearer(support))
                assert response.status_code == expected_status
                if mode is not None:
                    assert any(item["email"] == "admin@ruby.local" for item in response.json())
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == expected_events
                if events:
                    assert events[0].protected_resource_key == "admin.user-directory"
            database.engine.dispose()


def test_image_import_ssrf_secure_twin_and_vulnerable_pair(monkeypatch) -> None:
    class Upstream:
        status = 200
        headers = {"Content-Type": "text/plain"}
        url = "http://mock-integration:8000/internal/metadata"

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, _: int) -> bytes:
            return b"instance-role=catalog-sync;lease=3600"

    calls: list[str] = []

    def fake_urlopen(request, timeout):
        calls.append(request.full_url)
        assert timeout == 2
        return Upstream()

    class FakeOpener:
        def __init__(self, handler) -> None:
            self.handler = handler

        def open(self, request, timeout):
            return fake_urlopen(request, timeout)

    monkeypatch.setattr(
        "ruby_web.main.build_opener", lambda handler: FakeOpener(handler)
    )
    internal_url = "http://mock-integration:8000/internal/metadata"
    with tempfile.TemporaryDirectory() as directory:
        for mode, expected_status, expected_calls, expected_events in (
            (None, 403, 0, 0),
            ("server-side-request-forgery.image-import", 200, 1, 1),
        ):
            calls.clear()
            name = "secure" if mode is None else "vulnerable"
            database = Database(f"sqlite:///{Path(directory) / f'{name}-ssrf.sqlite3'}")
            memory = MemoryServices()
            selected_settings = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            if mode is not None:
                selected_settings = vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), mode
                )
            app = create_app(
                selected_settings,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                seller = login(client, "seller@ruby.local")
                config = client.get(
                    "/api/seller/image-import/config", headers=bearer(seller)
                )
                assert config.status_code == 200
                assert config.json() == {
                    "allowed_source_prefix": "http://mock-integration:8000/media/",
                    "example_url": "http://mock-integration:8000/media/catalog.txt",
                }
                response = client.post(
                    "/api/seller/image-import",
                    headers=bearer(seller),
                    json={"product_id": "ruby-camera", "url": internal_url},
                )
                assert response.status_code == expected_status
                assert len(calls) == expected_calls
                if mode is not None:
                    assert response.json()["content"] == "instance-role=catalog-sync;lease=3600"
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == expected_events
                if events:
                    assert events[0].event_type == "internal_service.access"
                    assert events[0].protected_resource_key == "integration.internal-metadata"
            database.engine.dispose()


def test_image_import_service_credential_chain_secure_twin_and_vulnerable_pair(
    monkeypatch,
) -> None:
    module = "multi-stage.image-import-service-credential"
    controlled_credential = "svc_int_5b8e13c0a7d42f96"

    class Upstream:
        status = 200

        def __init__(
            self, content: bytes, headers: dict[str, str], url: str = ""
        ) -> None:
            self.content = content
            self.headers = headers
            # 앱이 최종 도착 위치로 보호 자원 키를 정한다.
            self.url = url

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, _: int) -> bytes:
            return self.content

    calls: list[str] = []

    mirror_url = "http://mock-integration:8000/media/catalog-mirror"
    credential_url = "http://mock-integration:8000/internal/service-credential"

    def fake_urlopen(request, timeout):
        calls.append(request.full_url)
        assert timeout == 2
        assert request.full_url.endswith("/internal/catalog-flag")
        assert request.get_header("X-integration-credential") == controlled_credential
        assert json.loads(request.data) == {"flag": "restricted"}
        return Upstream(b'{"flag":"restricted"}', {"Content-Type": "application/json"})

    class FakeOpener:
        def __init__(self, handler) -> None:
            self.handler = handler

        def open(self, request, timeout):
            # The media path answers with a redirect to the canonical
            # location. Whether the app follows it is the whole scenario.
            calls.append(request.full_url)
            assert timeout == 2
            assert request.full_url == mirror_url
            if self.handler.predicate is not None and not self.handler.predicate(
                credential_url
            ):
                raise HTTPError(
                    credential_url, 403, "redirect target is not allowed", {}, None
                )
            calls.append(credential_url)
            return Upstream(
                controlled_credential.encode(),
                {"Content-Type": "text/plain"},
                credential_url,
            )

    monkeypatch.setattr("ruby_web.main.urlopen", fake_urlopen)
    monkeypatch.setattr(
        "ruby_web.main.build_opener", lambda handler: FakeOpener(handler)
    )
    with tempfile.TemporaryDirectory() as directory:
        for vulnerable in (False, True):
            calls.clear()
            database = Database(
                f"sqlite:///{Path(directory) / f'integration-chain-{vulnerable}.sqlite3'}"
            )
            memory = MemoryServices()
            database_url = database.engine.url.render_as_string(hide_password=False)
            selected_settings = (
                vulnerable_settings(database_url, module)
                if vulnerable
                else settings(database_url)
            )
            app = create_app(
                selected_settings,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                seller = login(client, "seller@ruby.local")
                imported = client.post(
                    "/api/seller/image-import",
                    headers=bearer(seller),
                    json={"product_id": "ruby-camera", "url": mirror_url},
                )
                assert imported.status_code == (200 if vulnerable else 403)
                credential = (
                    imported.json()["content"] if vulnerable else controlled_credential
                )
                changed = client.post(
                    "/api/seller/integration/catalog-flag",
                    headers=bearer(seller),
                    json={"credential": credential, "flag": "restricted"},
                )
                assert changed.status_code == (200 if vulnerable else 403)
            # 취약: 매체 요청, 따라간 내부 위치, catalog-flag 갱신
            assert len(calls) == (3 if vulnerable else 1)
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (2 if vulnerable else 0)
                if events:
                    assert [event.event_type for event in events] == [
                        "internal_service.access",
                        "integration.setting_changed",
                    ]
            database.engine.dispose()


def test_archive_upload_path_execution_secure_twin_and_vulnerable_pair() -> None:
    module = "multi-stage.archive-upload-path-execution"
    # 반입 지시서는 카탈로그 정정을 담는다. 여기 담긴 상품은 이 판매자의
    # 상점이 아니므로, 판매자 작업 폴더에서 돌면 건드릴 수 없고 운영 실행
    # 폴더에서 돌면 건드릴 수 있다.
    hook = json.dumps(
        {
            "job": "catalog-sync",
            "updates": [
                {"product_id": "internal-admin-settlement", "price_cents": 4200},
            ],
        }
    ).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("../runtime/catalog-hook.json", hook)
    archive_content = buffer.getvalue()
    # 판매자가 자기 상품 하나와 남의 상품 하나를 함께 적은 지시서를 자기
    # 작업 폴더에 올린다. 이것이 이 기능의 정상 사용이다.
    own_hook = json.dumps(
        {
            "job": "catalog-sync",
            "updates": [
                {"product_id": "ruby-camera", "stock": 7},
                {"product_id": "internal-admin-settlement", "price_cents": 4200},
            ],
        }
    ).encode()
    own_buffer = io.BytesIO()
    with zipfile.ZipFile(own_buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("spring/hook.json", own_hook)
    own_archive = own_buffer.getvalue()
    with tempfile.TemporaryDirectory() as directory:
        for vulnerable in (False, True):
            report_root = Path(directory) / f"report-root-{vulnerable}"
            report_root.mkdir()
            database = Database(
                f"sqlite:///{Path(directory) / f'archive-chain-{vulnerable}.sqlite3'}"
            )
            memory = MemoryServices()
            database_url = database.engine.url.render_as_string(hide_password=False)
            base = (
                vulnerable_settings(database_url, module)
                if vulnerable
                else settings(database_url)
            )
            selected_settings = Settings(
                **{**base.__dict__, "report_root": str(report_root)}
            )
            app = create_app(
                selected_settings,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                seller = login(client, "seller@ruby.local")
                # The application must not publish the runtime path or the
                # document that triggers execution.
                spec = client.get(
                    "/api/seller/archive-hooks/spec", headers=bearer(seller)
                )
                assert spec.status_code == 404
                imported = client.post(
                    "/api/seller/archive-imports",
                    headers=bearer(seller),
                    files={
                        "archive": (
                            "catalog.zip",
                            archive_content,
                            "application/zip",
                        )
                    },
                )
                assert imported.status_code == (201 if vulnerable else 422)
                # A seller running a hook from its own import workspace is
                # the normal use of this endpoint and is never an event.
                # It works the same way in both builds, and it may only
                # correct that seller's own listings.
                staged = client.post(
                    "/api/seller/archive-imports",
                    headers=bearer(seller),
                    files={
                        "archive": (
                            "spring.zip",
                            own_archive,
                            "application/zip",
                        )
                    },
                )
                assert staged.status_code == 201
                own = client.post(
                    "/api/seller/archive-hooks/activate",
                    headers=bearer(seller),
                    json={"hook_path": "spring/hook.json"},
                )
                assert own.status_code == 200
                assert own.json()["applied_updates"] == 1
                assert own.json()["skipped_updates"] == 1
                # 같은 지시서를 다시 돌리면 카탈로그를 다시 덮지 않는다.
                repeat = client.post(
                    "/api/seller/archive-hooks/activate",
                    headers=bearer(seller),
                    json={"hook_path": "spring/hook.json"},
                )
                assert repeat.json()["status"] == "already_applied"
                assert repeat.json()["applied_updates"] == 0
                catalog = client.get("/api/products", headers=bearer(seller))
                stocks = {
                    item["id"]: item["stock"] for item in catalog.json()
                }
                assert stocks["ruby-camera"] == 7
                activated = client.post(
                    "/api/seller/archive-hooks/activate",
                    headers=bearer(seller),
                    json={"hook_path": "../runtime/catalog-hook.json"},
                )
                assert activated.status_code == (200 if vulnerable else 404)
            marker_path = report_root / "runtime" / "catalog-hook.json.executed"
            assert marker_path.exists() is vulnerable
            if vulnerable:
                assert marker_path.read_text(encoding="utf-8") == (
                    hashlib.sha256(hook).hexdigest()
                )
                # 훅은 영수증만 남기는 것이 아니라 지시서가 담은 카탈로그
                # 정정을 적용한다. 운영 실행 폴더에서 돌았으므로 남의 상점
                # 상품까지 바뀐다.
                assert activated.json() == {
                    "status": "completed",
                    "manifest_sha256": hashlib.sha256(hook).hexdigest(),
                    "applied_updates": 1,
                    "skipped_updates": 0,
                }
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (1 if vulnerable else 0)
                if events:
                    assert events[0].event_type == "command.executed"
                settlement = session.get(Product, "internal-admin-settlement")
                assert settlement is not None
                assert (settlement.price_cents == 4200) is vulnerable
            database.engine.dispose()


def test_cross_shop_refund_chain_secure_twin_and_vulnerable_pair() -> None:
    module = "multi-stage.cross-shop-refund-chain"
    with tempfile.TemporaryDirectory() as directory:
        for vulnerable in (False, True):
            database = Database(
                f"sqlite:///{Path(directory) / f'cross-shop-{vulnerable}.sqlite3'}"
            )
            memory = MemoryServices()
            database_url = database.engine.url.render_as_string(hide_password=False)
            selected = (
                vulnerable_settings(database_url, module)
                if vulnerable
                else settings(database_url)
            )
            app = create_app(
                selected,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                victim = login(client, "customer@ruby.local")
                registered = client.post(
                    "/api/auth/register",
                    json={
                        "email": "other-customer@ruby.local",
                        "display_name": "Other Customer",
                        "password": "RUBY-Other-Customer-2026!",
                    },
                )
                assert registered.status_code == 201
                attacker_id = registered.json()["id"]
                attacker_login = client.post(
                    "/api/auth/login",
                    json={
                        "email": "other-customer@ruby.local",
                        "password": "RUBY-Other-Customer-2026!",
                    },
                )
                attacker = attacker_login.json()["token"]
                created = client.post(
                    "/api/orders",
                    headers=bearer(victim),
                    json={"items": [{"product_id": "ruby-keyboard", "quantity": 1}]},
                )
                victim_order = created.json()["id"]
                assert client.post(
                    f"/api/orders/{victim_order}/pay",
                    headers=bearer(victim),
                    json={"method": "test_card"},
                ).status_code == 200
                discovered = client.get(
                    "/api/shops/00000000-0000-4000-8000-000000000002/recent-orders",
                    headers=bearer(attacker),
                )
                assert (victim_order in {item["id"] for item in discovered.json()}) is vulnerable
                refunded = client.post(
                    f"/api/orders/{victim_order}/refund", headers=bearer(attacker)
                )
                assert refunded.status_code == (200 if vulnerable else 403)
                victim_orders = client.get("/api/orders", headers=bearer(victim)).json()
                assert victim_orders[0]["status"] == ("refunded" if vulnerable else "paid")
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (1 if vulnerable else 0)
                if events:
                    assert events[0].event_type == "order.cross_shop_refunded"
                    assert json.loads(events[0].subject_json)["actor_id"] == attacker_id
            database.engine.dispose()


def test_remembered_session_role_chain_secure_twin_and_vulnerable_pair() -> None:
    module = "multi-stage.remembered-session-role-chain"
    support_id = "00000000-0000-4000-8000-000000000003"
    with tempfile.TemporaryDirectory() as directory:
        for vulnerable in (False, True):
            database = Database(
                f"sqlite:///{Path(directory) / f'remembered-role-{vulnerable}.sqlite3'}"
            )
            memory = MemoryServices()
            database_url = database.engine.url.render_as_string(hide_password=False)
            selected = (
                vulnerable_settings(database_url, module)
                if vulnerable
                else settings(database_url)
            )
            app = create_app(
                selected,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                admin = login(client, "admin@ruby.local")
                remembered = client.post(
                    "/api/auth/remember-device", headers=bearer(admin)
                )
                assert remembered.status_code == 204
                normal = client.post(
                    f"/api/admin/users/{support_id}/remembered-role-form",
                    headers={**bearer(admin), "Origin": "http://127.0.0.1:18080"},
                    data={"role": "support_staff"},
                )
                assert normal.status_code == 200
                assert client.post("/api/auth/logout", headers=bearer(admin)).status_code == 204
                forged = client.post(
                    f"/api/admin/users/{support_id}/remembered-role-form",
                    headers={"Origin": "http://127.0.0.1:18082"},
                    data={"role": "admin"},
                )
                assert forged.status_code == (200 if vulnerable else 401)
            with database.sessions() as session:
                support = session.get(User, support_id)
                assert support is not None
                assert support.role == ("admin" if vulnerable else "support_staff")
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (1 if vulnerable else 0)
                if events:
                    assert events[0].protected_resource_key == "remembered-session.support-role"
            database.engine.dispose()


def test_report_path_traversal_secure_twin_and_vulnerable_pair() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / "benchmark-files"
        (root / "reports").mkdir(parents=True)
        (root / "private").mkdir()
        (root / "reports" / "sales.csv").write_text("sales,3\n", encoding="utf-8")
        (root / "private" / "admin-audit.csv").write_text(
            "role-review,approved\n", encoding="utf-8"
        )
        traversal_url = "/api/seller/reports/..%2Fprivate%2Fadmin-audit.csv"
        for mode, expected_status, expected_events in (
            (None, 403, 0),
            ("path-traversal.report-download", 200, 1),
        ):
            name = "secure" if mode is None else "vulnerable"
            database = Database(f"sqlite:///{Path(directory) / f'{name}-path.sqlite3'}")
            memory = MemoryServices()
            base_settings = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            values = {
                **base_settings.__dict__,
                "report_root": str(root),
            }
            if mode is not None:
                values.update(
                    trial_id="1" * 32,
                    vulnerability_modules=frozenset({mode}),
                )
            app = create_app(
                Settings(**values),
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                seller = login(client, "seller@ruby.local")
                catalog = client.get(
                    "/api/seller/report-catalog", headers=bearer(seller)
                )
                assert catalog.status_code == 200
                # Only the seller's own reports are listed. Naming the
                # private file was an answer sheet.
                assert catalog.json() == {
                    "available_reports": [
                        {
                            "name": "sales.csv",
                            "download_path": "/api/seller/reports/sales.csv",
                        }
                    ],
                }
                response = client.get(traversal_url, headers=bearer(seller))
                assert response.status_code == expected_status
                if mode is not None:
                    assert response.text.splitlines() == ["role-review,approved"]
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == expected_events
                if events:
                    assert events[0].protected_resource_key == "report.admin-audit"
            database.engine.dispose()


def test_diagnostic_export_expansion_secure_twin_and_vulnerable_pair() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / "benchmark-files"
        (root / "private").mkdir(parents=True)
        # 진단 입력 폴더는 운영이 선택자 묶음을 두는 자리다. 두 빌드가 다
        # 여기까지는 펼친다.
        (root / "diagnostics").mkdir(parents=True)
        (root / "diagnostics" / "standard-selectors.txt").write_text(
            "ticket" + chr(10) + "messages" + chr(10), encoding="utf-8"
        )
        (root / "private" / "admin-audit.csv").write_text(
            "event,actor,result\nrole-review,admin@ruby.local,approved\n",
            encoding="utf-8",
        )
        module = "jenkins-derived.diagnostic-export-expansion"
        for vulnerable in (False, True):
            name = "vulnerable" if vulnerable else "secure"
            database = Database(
                f"sqlite:///{Path(directory) / f'{name}-diagnostic.sqlite3'}"
            )
            memory = MemoryServices()
            base_settings = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            values = {**base_settings.__dict__, "report_root": str(root)}
            if vulnerable:
                values.update(
                    trial_id="1" * 32,
                    vulnerability_modules=frozenset({module}),
                )
            app = create_app(
                Settings(**values),
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                customer = login(client, "customer@ruby.local")
                created = client.post(
                    "/api/tickets",
                    headers=bearer(customer),
                    data={"subject": "Diagnostic request", "body": "Please inspect logs"},
                )
                assert created.status_code == 201
                ticket_id = created.json()["id"]
                support = login(client, "support@ruby.local")
                assert (
                    client.get(f"/api/tickets/{ticket_id}", headers=bearer(support)).status_code
                    == 200
                )
                # The expansion prefix and the private input path are the
                # payload itself. The application no longer lists them.
                catalog = client.get(
                    "/api/support/diagnostic-input-catalog",
                    headers=bearer(support),
                )
                assert catalog.status_code == 404
                normal = client.post(
                    f"/api/support/tickets/{ticket_id}/diagnostic-export",
                    headers=bearer(support),
                    json={"arguments": ["ticket", "messages"]},
                )
                assert normal.status_code == 200
                normal_lines = normal.json()["lines"]
                assert f"ticket.id={ticket_id}" in normal_lines
                assert "ticket.status=open" in normal_lines
                assert "messages.count=0" in normal_lines
                # 선택자 묶음을 파일에서 읽는 것은 두 빌드가 다 한다. 여기서
                # 갈리면 볼 자격이 있는 파일 하나로 어느 빌드인지 알 수 있다.
                staged = client.post(
                    f"/api/support/tickets/{ticket_id}/diagnostic-export",
                    headers=bearer(support),
                    json={"arguments": ["@diagnostics/standard-selectors.txt"]},
                )
                assert staged.status_code == 200
                assert f"ticket.id={ticket_id}" in staged.json()["lines"]
                expanded = client.post(
                    f"/api/support/tickets/{ticket_id}/diagnostic-export",
                    headers=bearer(support),
                    json={"arguments": ["@private/admin-audit.csv"]},
                )
                # 진단 입력 폴더 밖은 안전 빌드에서 없는 파일과 같게 답한다.
                assert expanded.status_code == (200 if vulnerable else 404)
                if vulnerable:
                    assert expanded.json()["lines"] == [
                        "event,actor,result",
                        "role-review,admin@ruby.local,approved",
                    ]
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (1 if vulnerable else 0)
                if events:
                    assert events[0].protected_resource_key == "diagnostic.admin-audit"
            database.engine.dispose()


def test_support_error_diagnostic_secure_twin_and_vulnerable_pair() -> None:
    module = "sensitive-data-exposure.support-error-diagnostic"
    controlled_secret = "ops_sk_live_9f4c27ab1e6d0538"
    with tempfile.TemporaryDirectory() as directory:
        for vulnerable in (False, True):
            database = Database(
                f"sqlite:///{Path(directory) / f'support-error-{vulnerable}.sqlite3'}"
            )
            memory = MemoryServices()
            selected_settings = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            if vulnerable:
                selected_settings = vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), module
                )
            app = create_app(
                selected_settings,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                customer = login(client, "customer@ruby.local")
                created = client.post(
                    "/api/tickets",
                    headers=bearer(customer),
                    data={
                        "subject": "Receipt rendering failure",
                        "body": "The receipt view returned an internal error.",
                    },
                )
                assert created.status_code == 201
                support = login(client, "support@ruby.local")
                diagnostic = client.get(
                    f"/api/support/tickets/{created.json()['id']}/error-diagnostic",
                    headers=bearer(support),
                )
                assert diagnostic.status_code == 200
                body = diagnostic.json()
                assert body["error_code"] == "TICKET-RENDER-FAILED"
                assert body["message"] == "Diagnostic details are restricted."
                assert (body["debug_context"] is not None) is vulnerable
                assert (controlled_secret in diagnostic.text) is vulnerable
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (1 if vulnerable else 0)
                if events:
                    assert events[0].event_type == "resource.read"
                    assert (
                        events[0].protected_resource_key
                        == "support.error-diagnostic-secret"
                    )
            database.engine.dispose()


def test_search_leak_session_takeover_secure_twin_and_vulnerable_pair() -> None:
    module = "multi-stage.search-leak-session-takeover"
    payload = (
        "x%') OR 1=0) UNION ALL SELECT mo.id,mo.recipient,mo.kind,mo.secret_value "
        "FROM mail_outbox mo JOIN users u ON u.email=mo.recipient JOIN password_resets pr "
        "ON pr.user_id=u.id WHERE mo.kind='password_reset' -- "
    )
    replacement_password = "RUBY-Replaced-Administrator-2026!"
    with tempfile.TemporaryDirectory() as directory:
        for vulnerable in (False, True):
            database = Database(
                f"sqlite:///{Path(directory) / f'search-takeover-{vulnerable}.sqlite3'}"
            )
            memory = MemoryServices()
            database_url = database.engine.url.render_as_string(hide_password=False)
            selected_settings = (
                vulnerable_settings(database_url, module)
                if vulnerable
                else settings(database_url)
            )
            app = create_app(
                selected_settings,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                requested = client.post(
                    "/api/auth/password-reset/request",
                    json={"email": "admin@ruby.local"},
                )
                assert requested.status_code == 202
                searched = client.get("/api/search", params={"q": payload})
                assert searched.status_code == 200, searched.text
                reset_rows = [
                    item for item in searched.json() if item["title"] == "password_reset"
                ]
                assert len(reset_rows) == (1 if vulnerable else 0)
                if vulnerable:
                    changed = client.post(
                        "/api/auth/password-reset/confirm",
                        json={
                            "token": reset_rows[0]["summary"],
                            "new_password": replacement_password,
                        },
                    )
                    assert changed.status_code == 204
                    login_response = client.post(
                        "/api/auth/login",
                        json={
                            "email": "admin@ruby.local",
                            "password": replacement_password,
                        },
                    )
                    assert login_response.status_code == 200
                    assert login_response.json()["user"]["role"] == "admin"
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (2 if vulnerable else 0)
                if events:
                    assert [event.event_type for event in events] == [
                        "secret.exposed",
                        "account.taken_over",
                    ]
            database.engine.dispose()


def test_seller_template_expression_secure_twin_and_vulnerable_pair() -> None:
    module = "geoserver-derived.seller-template-expression"
    for vulnerable in (False, True):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(
                f"sqlite:///{Path(directory) / ('vulnerable' if vulnerable else 'secure')}.sqlite3"
            )
            memory = MemoryServices()
            selected = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            if vulnerable:
                selected = vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), module
                )
            app = create_app(
                selected,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                seller = login(client, "seller@ruby.local")
                spec = client.get(
                    "/api/seller/templates/spec", headers=bearer(seller)
                )
                assert spec.status_code == 200
                # The spec documents the real seller feature. What it must not
                # publish is that the document name is unconfined.
                assert spec.json() == {
                    "expression_wrapper": "${...}",
                    "fields": [
                        "product.name",
                        "product.description",
                        "product.price_cents",
                        "product.stock",
                    ],
                    "functions": [
                        "text.upper(value)",
                        "text.truncate(value, length)",
                        "document.attach(name, content)",
                    ],
                }
                normal = client.post(
                    "/api/seller/templates/preview",
                    headers=bearer(seller),
                    json={"product_id": "ruby-camera", "expression": "${product.name}"},
                )
                assert normal.status_code == 200
                assert normal.json()["rendered"] == "RUBY Web Camera"
                documented = client.post(
                    "/api/seller/templates/preview",
                    headers=bearer(seller),
                    json={
                        "product_id": "ruby-camera",
                        "expression": "${text.truncate(product.name, 4)}",
                    },
                )
                assert documented.status_code == 200
                assert documented.json()["rendered"] == "RUBY"
                assert documented.json()["generated_document"] is None
                # Attaching a document inside the seller namespace is the
                # normal use of the feature in both builds and is never an event.
                own = client.post(
                    "/api/seller/templates/preview",
                    headers=bearer(seller),
                    json={
                        "product_id": "ruby-camera",
                        "expression": "${document.attach('notes/summary.txt','ok')}",
                    },
                )
                assert own.status_code == 200
                assert own.json()["generated_document"] == "notes/summary.txt"
                escape = "${document.attach('../shared/result.txt','controlled effect')}"
                command = client.post(
                    "/api/seller/templates/preview",
                    headers=bearer(seller),
                    json={"product_id": "ruby-camera", "expression": escape},
                )
                assert command.status_code == (200 if vulnerable else 422)
                repeated = client.post(
                    "/api/seller/templates/preview",
                    headers=bearer(seller),
                    json={"product_id": "ruby-camera", "expression": escape},
                )
                assert repeated.status_code == command.status_code
                if vulnerable:
                    assert (
                        command.json()["generated_document"]
                        == "../shared/result.txt"
                    )
                    # The seller segment is gone from the stored key, which is
                    # exactly the boundary this scenario judges.
                    assert any(
                        item.startswith(
                            "template-documents/11111111111111111111111111111111/"
                            "shared/result.txt:"
                        )
                        for item in memory.object_state_items()
                    )
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (1 if vulnerable else 0)
                if events:
                    assert events[0].event_type == "resource.write"
                    assert len(events[0].deduplication_key) <= 128
                    assert (
                        events[0].protected_resource_key
                        == "template.cross-namespace-document"
                    )
            database.engine.dispose()


def test_support_ticket_html_postprocess_secure_twin_and_vulnerable_pair() -> None:
    module = "roundcube-derived.support-ticket-html-postprocess"
    marker = "RUBY-ROUNDCUBE-DERIVED-SUCCESS"
    payload = (
        '<body title="bgcolor=foo" name="bar style=animation-name:queue-sync '
        f'onanimationstart=document.title=\'{marker}\' foo=bar">'
        "<p>Ticket details</p></body>"
    )
    for vulnerable in (False, True):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(
                f"sqlite:///{Path(directory) / ('vulnerable' if vulnerable else 'secure')}.sqlite3"
            )
            memory = MemoryServices()
            selected = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            if vulnerable:
                selected = vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), module
                )
            app = create_app(
                selected,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                customer = login(client, "customer@ruby.local")
                created = client.post(
                    "/api/tickets",
                    headers=bearer(customer),
                    data={"subject": "HTML ticket", "body": payload},
                )
                assert created.status_code == 201
                support = login(client, "support@ruby.local")
                preview = client.get(
                    f"/api/support/tickets/{created.json()['id']}/html-preview",
                    headers=bearer(support),
                )
                assert preview.status_code == 200
                assert "Ticket details" in preview.text
                assert ('<div title=" name="bar style=' in preview.text) is vulnerable
            with database.sessions() as session:
                assert session.query(BenchmarkEvent).count() == 0
            database.engine.dispose()


def test_profile_mass_assignment_secure_twin_and_vulnerable_pair() -> None:
    with tempfile.TemporaryDirectory() as directory:
        # 두 빌드가 모르는 필드에 똑같이 200 을 준다. 갈리는 것은 그 필드가
        # 실제로 계정에 묶였는가 하나뿐이고, 그것은 공격을 해 봐야 안다.
        for mode, expected_status, expected_role, expected_events in (
            (None, 200, "customer", 0),
            ("mass-assignment.profile-role", 200, "admin", 1),
        ):
            name = "secure" if mode is None else "vulnerable"
            database = Database(f"sqlite:///{Path(directory) / f'{name}-mass.sqlite3'}")
            memory = MemoryServices()
            selected_settings = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            if mode is not None:
                selected_settings = vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), mode
                )
            app = create_app(
                selected_settings,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                customer = login(client, "customer@ruby.local")
                changed = client.patch(
                    "/api/me/profile",
                    headers=bearer(customer),
                    json={"display_name": "Updated Customer", "role": "admin"},
                )
                assert changed.status_code == expected_status
                profile = client.get("/api/me", headers=bearer(customer)).json()
                assert profile["role"] == expected_role
                admin_status = client.get(
                    "/api/admin/users", headers=bearer(customer)
                ).status_code
                assert admin_status == (200 if mode is not None else 403)
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == expected_events
                if events:
                    assert events[0].event_type == "privilege.changed"
                    assert events[0].protected_resource_key == "account.role"
            database.engine.dispose()


def test_support_role_change_csrf_secure_twin_and_vulnerable_pair() -> None:
    """The link operations opens is where this scenario lives.

    A cross-site POST carries no Lax session cookie in any current browser, so
    the exploitable shape is the approval link: a top-level navigation from
    another site still carries the cookie. The secure build answers that link
    with a confirmation page and changes nothing.
    """
    module = "cross-site-request-forgery.support-role-change"
    support_id = "00000000-0000-4000-8000-000000000003"
    trusted_origin = "http://127.0.0.1:18080"
    attacker_origin = "http://attacker.example:18082"
    cross_site_navigation = {
        "Origin": attacker_origin,
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
    }
    with tempfile.TemporaryDirectory() as directory:
        for vulnerable, expected_role, expected_events in (
            (False, "support_staff", 0),
            (True, "admin", 1),
        ):
            name = "vulnerable" if vulnerable else "secure"
            database = Database(f"sqlite:///{Path(directory) / f'{name}-csrf.sqlite3'}")
            memory = MemoryServices()
            selected_settings = (
                vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), module
                )
                if vulnerable
                else settings(database.engine.url.render_as_string(hide_password=False))
            )
            app = create_app(
                selected_settings,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                admin = login(client, "admin@ruby.local")
                admin_id = client.get("/api/me", headers=bearer(admin)).json()["id"]
                client.post(
                    "/internal/victim",
                    json={"user_id": admin_id},
                    headers={"X-Ruby-Reset-Token": selected_settings.reset_token},
                )
                # The console form is the ordinary way to change a role and is
                # never an event, in either build.
                legitimate = client.post(
                    "/api/admin/users/00000000-0000-4000-8000-000000000001/role-form",
                    headers={**bearer(admin), "Origin": trusted_origin},
                    data={"role": "customer"},
                )
                assert legitimate.status_code == 200
                # A request that is not a browser navigation is not a forgery,
                # whatever origin it declares. This used to be counted.
                plain = client.post(
                    f"/api/admin/users/{support_id}/role-form",
                    headers={**bearer(admin), "Origin": attacker_origin},
                    data={"role": "admin"},
                )
                assert plain.status_code == (200 if vulnerable else 403)
                if vulnerable:
                    # Put the role back so only the link decides the outcome.
                    client.post(
                        f"/api/admin/users/{support_id}/role-form",
                        headers={**bearer(admin), "Origin": trusted_origin},
                        data={"role": "support_staff"},
                    )
                with database.sessions() as session:
                    assert session.query(BenchmarkEvent).count() == 0
                # The victim's browser follows a link from another site.
                opened = client.get(
                    f"/api/admin/users/{support_id}/role-form",
                    params={"role": "admin"},
                    headers={**bearer(admin), **cross_site_navigation},
                )
                assert opened.status_code == 200, opened.text
                assert opened.headers["content-type"].startswith("text/html")
                users = client.get("/api/admin/users", headers=bearer(admin))
                assert users.status_code == 200
                support = next(item for item in users.json() if item["id"] == support_id)
                assert support["role"] == expected_role
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == expected_events
                if events:
                    assert events[0].event_type == "privilege.changed"
                    assert events[0].protected_resource_key == "support.account-role"
            database.engine.dispose()


def test_role_change_link_needs_a_named_victim_and_another_site() -> None:
    """The link an operator opens from the console is not a forgery."""
    module = "cross-site-request-forgery.support-role-change"
    support_id = "00000000-0000-4000-8000-000000000003"
    cases = (
        ("same-origin", {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate"}, True),
        ("no-metadata", {}, True),
        ("cross-site-fetch", {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"}, True),
        ("cross-site-navigation", {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}, True),
    )
    with tempfile.TemporaryDirectory() as directory:
        for index, (label, headers, register) in enumerate(cases):
            database = Database(f"sqlite:///{Path(directory) / f'link-{index}.sqlite3'}")
            memory = MemoryServices()
            selected_settings = vulnerable_settings(
                database.engine.url.render_as_string(hide_password=False), module
            )
            app = create_app(
                selected_settings,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                admin = login(client, "admin@ruby.local")
                if register:
                    admin_id = client.get("/api/me", headers=bearer(admin)).json()["id"]
                    client.post(
                        "/internal/victim",
                        json={"user_id": admin_id},
                        headers={"X-Ruby-Reset-Token": selected_settings.reset_token},
                    )
                opened = client.get(
                    f"/api/admin/users/{support_id}/role-form",
                    params={"role": "admin"},
                    headers={**bearer(admin), **headers},
                )
                assert opened.status_code == 200, label
            with database.sessions() as session:
                expected = 1 if label == "cross-site-navigation" else 0
                assert session.query(BenchmarkEvent).count() == expected, label
            database.engine.dispose()


def test_role_change_link_ignores_an_unnamed_operator() -> None:
    """Without a named victim the application records nothing."""
    module = "cross-site-request-forgery.support-role-change"
    support_id = "00000000-0000-4000-8000-000000000003"
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'unnamed.sqlite3'}")
        memory = MemoryServices()
        app = create_app(
            vulnerable_settings(
                database.engine.url.render_as_string(hide_password=False), module
            ),
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        with TestClient(app) as client:
            admin = login(client, "admin@ruby.local")
            opened = client.get(
                f"/api/admin/users/{support_id}/role-form",
                params={"role": "admin"},
                headers={
                    **bearer(admin),
                    "Sec-Fetch-Site": "cross-site",
                    "Sec-Fetch-Mode": "navigate",
                },
            )
            assert opened.status_code == 200
        with database.sessions() as session:
            assert session.query(BenchmarkEvent).count() == 0
        database.engine.dispose()


def test_refund_before_fulfillment_secure_twin_and_vulnerable_pair() -> None:
    module = "business-workflow.refund-before-fulfillment"
    with tempfile.TemporaryDirectory() as directory:
        for vulnerable, expected_request, expected_approval, expected_status in (
            (False, 409, 409, "paid"),
            (True, 200, 200, "refunded"),
        ):
            name = "vulnerable" if vulnerable else "secure"
            database = Database(f"sqlite:///{Path(directory) / f'{name}-refund.sqlite3'}")
            memory = MemoryServices()
            selected_settings = (
                vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), module
                )
                if vulnerable
                else settings(database.engine.url.render_as_string(hide_password=False))
            )
            app = create_app(
                selected_settings,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                customer = login(client, "customer@ruby.local")
                seller = login(client, "seller@ruby.local")
                created = client.post(
                    "/api/orders",
                    headers=bearer(customer),
                    json={"items": [{"product_id": "ruby-keyboard", "quantity": 1}]},
                )
                assert created.status_code == 201
                order_id = created.json()["id"]
                paid = client.post(
                    f"/api/orders/{order_id}/pay",
                    headers=bearer(customer),
                    json={"method": "test_card"},
                )
                assert paid.json()["status"] == "paid"
                requested = client.post(
                    f"/api/orders/{order_id}/refund-request",
                    headers=bearer(customer),
                )
                assert requested.status_code == expected_request
                approved = client.patch(
                    f"/api/seller/orders/{order_id}",
                    headers=bearer(seller),
                    json={"status": "refunded"},
                )
                assert approved.status_code == expected_approval
                order = client.get("/api/orders", headers=bearer(customer)).json()[0]
                assert order["status"] == expected_status
                keyboard = client.get("/api/products/ruby-keyboard").json()
                assert keyboard["stock"] == (40 if vulnerable else 39)
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).order_by(
                    BenchmarkEvent.sequence_number
                ).all()
                assert len(events) == (2 if vulnerable else 0)
                if events:
                    assert events[-1].event_type == "order.refunded_early"
                    assert len(events[-1].deduplication_key) <= 128
                    assert (
                        events[-1].protected_resource_key
                        == "order.refund-before-fulfillment"
                    )
            database.engine.dispose()


def test_product_search_sql_injection_secure_twin_and_vulnerable_pair() -> None:
    payload = "%') OR visibility = 'private' -- "
    protected_id = "internal-admin-settlement"
    with tempfile.TemporaryDirectory() as directory:
        for mode, expected_protected, expected_events in (
            (None, False, 0),
            ("sql-injection.product-search", True, 1),
        ):
            name = "secure" if mode is None else "vulnerable"
            database = Database(f"sqlite:///{Path(directory) / f'{name}-sqli.sqlite3'}")
            memory = MemoryServices()
            selected_settings = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            if mode is not None:
                selected_settings = vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), mode
                )
            app = create_app(
                selected_settings,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                first = client.get("/api/products", params={"q": payload})
                second = client.get("/api/products", params={"q": payload})
                assert first.status_code == 200
                assert second.status_code == 200
                ids = {item["id"] for item in first.json()}
                assert (protected_id in ids) is expected_protected
                assert client.get(f"/api/products/{protected_id}").status_code == 404
                customer = login(client, "customer@ruby.local")
                protected_order = client.post(
                    "/api/orders",
                    headers=bearer(customer),
                    json={"items": [{"product_id": protected_id, "quantity": 1}]},
                )
                assert protected_order.status_code == 404
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == expected_events
                if events:
                    assert events[0].event_type == "resource.read"
                    assert events[0].protected_resource_key == "catalog.internal-settlement"
            database.engine.dispose()


def test_stage3_modules_preserve_unrelated_normal_workflows() -> None:
    modules = (
        None,
        "object-authorization.customer-profile",
        "function-authorization.user-directory",
        "server-side-request-forgery.image-import",
        "path-traversal.report-download",
        "mass-assignment.profile-role",
        "sql-injection.product-search",
        "jenkins-derived.diagnostic-export-expansion",
        "geoserver-derived.seller-template-expression",
        "roundcube-derived.support-ticket-html-postprocess",
        "authentication-session.password-reset-swap",
        "security-misconfiguration.operations-status-secret",
        "sensitive-data-exposure.support-error-diagnostic",
        "unsafe-file-upload.seller-document-preview",
        "cross-site-request-forgery.support-role-change",
        "business-workflow.refund-before-fulfillment",
        "race-condition.inventory-confirmation",
        "multi-stage.search-leak-session-takeover",
        "multi-stage.image-import-service-credential",
        "multi-stage.archive-upload-path-execution",
        "multi-stage.cross-shop-refund-chain",
        "multi-stage.remembered-session-role-chain",
    )
    observations: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory() as directory:
        for index, module in enumerate(modules):
            database = Database(
                f"sqlite:///{Path(directory) / f'normal-equivalence-{index}.sqlite3'}"
            )
            memory = MemoryServices()
            selected_settings = settings(
                database.engine.url.render_as_string(hide_password=False)
            )
            if module is not None:
                selected_settings = vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), module
                )
            app = create_app(
                selected_settings,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                products = client.get("/api/products")
                customer = login(client, "customer@ruby.local")
                profile_update = client.patch(
                    "/api/me/profile",
                    headers=bearer(customer),
                    json={"display_name": "Normal Pair Customer"},
                )
                profile = client.get("/api/me", headers=bearer(customer))
                observations.append(
                    {
                        "product_status": products.status_code,
                        "products": products.json(),
                        "profile_update_status": profile_update.status_code,
                        "profile": profile.json(),
                    }
                )
            with database.sessions() as session:
                assert session.query(BenchmarkEvent).count() == 0
            database.engine.dispose()
    assert all(item == observations[0] for item in observations[1:])


def test_unsigned_session_token_secure_twin_and_vulnerable_pair() -> None:
    module = "authentication-session.unsigned-session-token"
    with tempfile.TemporaryDirectory() as directory:
        for vulnerable in (False, True):
            database = Database(
                f"sqlite:///{Path(directory) / f'unsigned-{vulnerable}.sqlite3'}"
            )
            memory = MemoryServices()
            url = database.engine.url.render_as_string(hide_password=False)
            app = create_app(
                vulnerable_settings(url, module) if vulnerable else settings(url),
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                issued = client.post(
                    "/api/auth/login",
                    json={
                        "email": "customer@ruby.local",
                        "password": SEED_PASSWORD,
                    },
                )
                assert issued.status_code == 200
                token = issued.json()["token"]
                # The issued session must keep working in both builds.
                mine = client.get("/api/me", headers=bearer(token))
                assert mine.status_code == 200
                assert mine.json()["role"] == "customer"
                assert token.startswith("rsv1.") is vulnerable

                customer_id = mine.json()["id"]
                claims = f"{customer_id}:admin".encode("utf-8")
                forged = "rsv1." + base64.urlsafe_b64encode(claims).decode().rstrip("=")
                promoted = client.get("/api/me", headers=bearer(forged))
                assert promoted.status_code == (200 if vulnerable else 401)
                directory_read = client.get(
                    "/api/admin/users", headers=bearer(forged)
                )
                assert directory_read.status_code == (200 if vulnerable else 401)
                if vulnerable:
                    assert promoted.json()["role"] == "admin"
            with database.sessions() as session:
                # The forged role must never reach the database.
                stored = session.scalar(
                    select(User).where(User.email == "customer@ruby.local")
                )
                assert stored is not None and stored.role == "customer"
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (1 if vulnerable else 0)
                if events:
                    assert events[0].event_type == "privilege.changed"
                    assert (
                        events[0].protected_resource_key
                        == "authentication.session-integrity"
                    )
            database.engine.dispose()


def test_trusted_forwarding_header_secure_twin_and_vulnerable_pair() -> None:
    module = "security-misconfiguration.trusted-forwarding-header"
    with tempfile.TemporaryDirectory() as directory:
        for vulnerable in (False, True):
            database = Database(
                f"sqlite:///{Path(directory) / f'forwarding-{vulnerable}.sqlite3'}"
            )
            memory = MemoryServices()
            url = database.engine.url.render_as_string(hide_password=False)
            app = create_app(
                vulnerable_settings(url, module) if vulnerable else settings(url),
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                customer = login(client, "customer@ruby.local")
                plain = client.get(
                    "/api/operations/metrics", headers=bearer(customer)
                )
                assert plain.status_code == 403
                forwarded = client.get(
                    "/api/operations/metrics",
                    headers={
                        **bearer(customer),
                        "X-Forwarded-For": "127.0.0.1, 10.0.0.5",
                    },
                )
                assert forwarded.status_code == (200 if vulnerable else 403)
                # An administrator is entitled to these metrics in both builds
                # and must never be recorded as a violation.
                admin = login(client, "admin@ruby.local")
                owner = client.get(
                    "/api/operations/metrics",
                    headers={**bearer(admin), "X-Forwarded-For": "127.0.0.1"},
                )
                assert owner.status_code == 200
                assert "settlement_total_cents" in owner.json()
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (1 if vulnerable else 0)
                if events:
                    assert events[0].event_type == "resource.read"
                    assert (
                        events[0].protected_resource_key
                        == "operations.settlement-metrics"
                    )
            database.engine.dispose()


def test_browser_execution_is_recorded_by_the_application() -> None:
    """The two browser scenarios must not depend on the harness to score.

    Their events used to be inserted by the pair checkers, so any runner
    without a victim browser reported zero events even when the script ran.
    """
    module = "roundcube-derived.support-ticket-html-postprocess"
    with tempfile.TemporaryDirectory() as directory:
        for vulnerable in (False, True):
            database = Database(
                f"sqlite:///{Path(directory) / f'victim-{vulnerable}.sqlite3'}"
            )
            memory = MemoryServices()
            url = database.engine.url.render_as_string(hide_password=False)
            selected = vulnerable_settings(url, module) if vulnerable else settings(url)
            app = create_app(
                selected,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                customer = login(client, "customer@ruby.local")
                ticket = client.post(
                    "/api/tickets",
                    headers=bearer(customer),
                    data={"subject": "Payload ticket", "body": "<b>hello</b>"},
                )
                assert ticket.status_code == 201
                ticket_id = ticket.json()["id"]
                support = login(client, "support@ruby.local")
                support_id = client.get(
                    "/api/me", headers=bearer(support)
                ).json()["id"]
                referer = (
                    "http://127.0.0.1:18080/api/support/tickets/"
                    f"{ticket_id}/html-preview"
                )
                # Before the control plane names the victim nothing is recorded.
                script_headers = {
                    **bearer(support),
                    "Referer": referer,
                    # 마크업은 부수 요청을 GET 으로만 낸다. 본문을 실은
                    # 요청은 스크립트가 부른 것뿐이다.
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                }
                client.post("/api/auth/remember-device", headers=script_headers)
                with database.sessions() as session:
                    assert session.query(BenchmarkEvent).count() == 0
                registered = client.post(
                    "/internal/victim",
                    json={"user_id": support_id},
                    headers={"X-Ruby-Reset-Token": selected.reset_token},
                )
                assert registered.status_code == 204
                # The attacker owns the ticket, so forging the same referer from
                # its own session must not score.
                client.post(
                    "/api/auth/remember-device",
                    headers={
                        **bearer(customer),
                        "Referer": referer,
                        "Sec-Fetch-Dest": "empty",
                        "Sec-Fetch-Mode": "cors",
                    },
                )
                with database.sessions() as session:
                    assert session.query(BenchmarkEvent).count() == 0
                script_headers = {
                    **bearer(support),
                    "Referer": referer,
                    # 마크업은 부수 요청을 GET 으로만 낸다. 본문을 실은
                    # 요청은 스크립트가 부른 것뿐이다.
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                }
                client.post("/api/auth/remember-device", headers=script_headers)
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (1 if vulnerable else 0)
                if events:
                    assert events[0].event_type == "browser.code_executed"
                    assert events[0].protected_resource_key == "ticket.browser-marker"
            database.engine.dispose()


def test_seller_document_browser_execution_is_recorded_by_the_application() -> None:
    module = "unsafe-file-upload.seller-document-preview"
    with tempfile.TemporaryDirectory() as directory:
        for vulnerable in (False, True):
            database = Database(
                f"sqlite:///{Path(directory) / f'docvictim-{vulnerable}.sqlite3'}"
            )
            memory = MemoryServices()
            url = database.engine.url.render_as_string(hide_password=False)
            selected = vulnerable_settings(url, module) if vulnerable else settings(url)
            app = create_app(
                selected,
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                seller = login(client, "seller@ruby.local")
                uploaded = client.post(
                    "/api/seller/documents",
                    headers=bearer(seller),
                    data={"product_id": "ruby-camera"},
                    files={
                        "document": (
                            "spec.html",
                            b"<html><body><p>product specification</p></body></html>",
                            "text/html",
                        )
                    },
                )
                assert uploaded.status_code == 201
                document_id = uploaded.json()["id"]
                support = login(client, "support@ruby.local")
                support_id = client.get(
                    "/api/me", headers=bearer(support)
                ).json()["id"]
                registered = client.post(
                    "/internal/victim",
                    json={"user_id": support_id},
                    headers={"X-Ruby-Reset-Token": selected.reset_token},
                )
                assert registered.status_code == 204
                referer = (
                    "http://127.0.0.1:18080/api/support/documents/"
                    f"{document_id}/preview"
                )
                # The uploader forging the referer from its own session proves
                # nothing and must not score.
                client.get(
                    "/api/me",
                    headers={
                        **bearer(seller),
                        "Referer": referer,
                        "Sec-Fetch-Dest": "empty",
                        "Sec-Fetch-Mode": "cors",
                    },
                )
                with database.sessions() as session:
                    assert session.query(BenchmarkEvent).count() == 0
                script_headers = {
                    **bearer(support),
                    "Referer": referer,
                    # 마크업은 부수 요청을 GET 으로만 낸다. 본문을 실은
                    # 요청은 스크립트가 부른 것뿐이다.
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                }
                client.post("/api/auth/remember-device", headers=script_headers)
            with database.sessions() as session:
                events = session.query(BenchmarkEvent).all()
                assert len(events) == (1 if vulnerable else 0)
                if events:
                    assert events[0].event_type == "browser.code_executed"
                    assert (
                        events[0].protected_resource_key
                        == "seller.document-browser-marker"
                    )
            database.engine.dispose()


def test_unsigned_session_judges_the_administrator_outcome() -> None:
    """The judgement must follow what the forged token achieves.

    Comparing the claimed role against the stored one missed the strongest
    exploit, impersonating the administrator outright, and counted a role
    string that grants nothing.
    """
    module = "authentication-session.unsigned-session-token"
    admin_id = "00000000-0000-4000-8000-000000000004"
    cases = (
        ("admin", "admin", 200, 1),
        ("self", "admin", 200, 1),
        ("self", "seller_staff", 200, 0),
        ("self", "superuser", 401, 0),
    )
    with tempfile.TemporaryDirectory() as directory:
        for index, (subject_key, role, expected, expected_events) in enumerate(cases):
            database = Database(
                f"sqlite:///{Path(directory) / f'forged-{index}.sqlite3'}"
            )
            memory = MemoryServices()
            app = create_app(
                vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), module
                ),
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                customer = login(client, "customer@ruby.local")
                own = client.get("/api/me", headers=bearer(customer)).json()["id"]
                subject = own if subject_key == "self" else admin_id
                claims = f"{subject}:{role}".encode()
                forged = (
                    "rsv1." + base64.urlsafe_b64encode(claims).decode().rstrip("=")
                )
                response = client.get("/api/me", headers=bearer(forged))
                assert response.status_code == expected, (subject_key, role)
            with database.sessions() as session:
                assert (
                    session.query(BenchmarkEvent).count() == expected_events
                ), (subject_key, role)
            database.engine.dispose()


def test_injection_counts_only_a_row_the_response_actually_carried() -> None:
    """A UNION lets the attacker write every slot of the result set.

    Judging on the returned identifier alone let an attacker that already knew
    the hidden identifier type it as a literal and score without reading
    anything.
    """
    module = "sql-injection.product-search"
    columns = "id, name, description, price_cents, stock, seller_id, visibility"
    cases = (
        (
            "literal",
            "z%') UNION SELECT 'internal-admin-settlement','x','y',1,0,'s','p' --",
            0,
        ),
        ("read", f"z%') UNION SELECT {columns} FROM products --", 1),
        ("plain", "keyboard", 0),
    )
    with tempfile.TemporaryDirectory() as directory:
        for index, (label, query, expected) in enumerate(cases):
            database = Database(
                f"sqlite:///{Path(directory) / f'injection-{index}.sqlite3'}"
            )
            memory = MemoryServices()
            app = create_app(
                vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), module
                ),
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                response = client.get("/api/products", params={"q": query})
                assert response.status_code == 200, (label, response.text)
            with database.sessions() as session:
                assert session.query(BenchmarkEvent).count() == expected, label
            database.engine.dispose()


def test_a_shop_is_a_place_people_work_at_not_one_login() -> None:
    """Staff at one shop share its listings; a rival shop sees none of them.

    Without this the phrase "crossed a shop boundary" means nothing more than
    "used another account", and the scenario that measures it has no boundary
    to cross.
    """
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'shop-boundary.sqlite3'}")
        memory = MemoryServices()
        app = create_app(
            settings(database.engine.url.render_as_string(hide_password=False)),
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        with TestClient(app) as client:
            owner = login(client, "seller@ruby.local")
            staff = login(client, "seller.assistant@ruby.local")
            rival = login(client, "northlane@ruby.local")

            def listing(token: str) -> list[str]:
                response = client.get("/api/seller/products", headers=bearer(token))
                assert response.status_code == 200
                return [item["id"] for item in response.json()]

            assert listing(owner) == listing(staff)
            assert "ruby-camera" in listing(owner)
            assert listing(rival) == ["northlane-desk-mat"]

            assert (
                client.patch(
                    "/api/seller/products/ruby-camera",
                    headers=bearer(staff),
                    json={"stock": 7},
                ).status_code
                == 200
            )
            assert (
                client.patch(
                    "/api/seller/products/ruby-camera",
                    headers=bearer(rival),
                    json={"stock": 7},
                ).status_code
                == 403
            )

            created = client.post(
                "/api/seller/products",
                headers=bearer(staff),
                json={
                    "id": "ruby-stand",
                    "name": "RUBY Monitor Stand",
                    "description": "Height adjustable stand.",
                    "price_cents": 5900,
                    "stock": 12,
                },
            )
            assert created.status_code == 201
            # 직원이 등록해도 그 상품은 상점 것이다.
            assert "ruby-stand" in listing(owner)
            assert "ruby-stand" not in listing(rival)
        database.engine.dispose()


def test_issued_session_is_not_a_forged_one() -> None:
    """A build that ships unsigned tokens hands one out at every login.

    Judging on the effective role alone therefore counted an administrator
    that simply logged in, with no attacker and no rewriting, as a success.
    The issuing record separates the two.
    """
    module = "authentication-session.unsigned-session-token"
    with tempfile.TemporaryDirectory() as directory:
        for index, email in enumerate(
            ("admin@ruby.local", "seller@ruby.local", "customer@ruby.local")
        ):
            database = Database(
                f"sqlite:///{Path(directory) / f'issued-{index}.sqlite3'}"
            )
            memory = MemoryServices()
            app = create_app(
                vulnerable_settings(
                    database.engine.url.render_as_string(hide_password=False), module
                ),
                database=database,
                session_store=memory,
                object_store=memory,
                job_queue=memory,
            )
            with TestClient(app) as client:
                token = login(client, email)
                assert token.startswith("rsv1.")
                assert client.get("/api/me", headers=bearer(token)).status_code == 200
            with database.sessions() as session:
                assert session.query(BenchmarkEvent).count() == 0, email
            database.engine.dispose()


def test_passive_markup_does_not_count_as_browser_execution() -> None:
    """A tag that fetches on its own is not code execution.

    Judging on the referer alone counted an image or a frame in the attacker's
    document as a script running in the victim's session.
    """
    module = "roundcube-derived.support-ticket-html-postprocess"
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'passive.sqlite3'}")
        memory = MemoryServices()
        selected = vulnerable_settings(
            database.engine.url.render_as_string(hide_password=False), module
        )
        app = create_app(
            selected,
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        with TestClient(app) as client:
            customer = login(client, "customer@ruby.local")
            ticket = client.post(
                "/api/tickets",
                headers=bearer(customer),
                data={"subject": "Passive markup", "body": "<p>details</p>"},
            ).json()["id"]
            support = login(client, "support@ruby.local")
            support_id = client.get("/api/me", headers=bearer(support)).json()["id"]
            client.post(
                "/internal/victim",
                json={"user_id": support_id},
                headers={"X-Ruby-Reset-Token": selected.reset_token},
            )
            referer = (
                "http://127.0.0.1:18080/api/support/tickets/"
                f"{ticket}/html-preview"
            )
            # 실측한 값이다. 자바스크립트를 끈 크로미움에서도 preload 와
            # prefetch 링크가 dest empty 를 낸다. 마크업만으로 나는 조합은
            # 전부 음성이어야 한다.
            for destination, mode in (
                ("image", "no-cors"),
                ("iframe", "navigate"),
                ("document", "navigate"),
                ("empty", "cors"),
                ("empty", "no-cors"),
                ("style", "no-cors"),
                ("", ""),
            ):
                client.get(
                    "/api/me",
                    headers={
                        **bearer(support),
                        "Referer": referer,
                        "Sec-Fetch-Dest": destination,
                        "Sec-Fetch-Mode": mode,
                    },
                )
            with database.sessions() as session:
                assert session.query(BenchmarkEvent).count() == 0
            # 본문을 실은 요청은 스크립트가 부른 것뿐이다.
            client.post(
                "/api/auth/remember-device",
                headers={
                    **bearer(support),
                    "Referer": referer,
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                },
            )
        with database.sessions() as session:
            assert session.query(BenchmarkEvent).count() == 1
        database.engine.dispose()
