from __future__ import annotations

import os
import re
from dataclasses import dataclass


IMPLEMENTED_VULNERABILITY_MODULES = frozenset(
    {
        "function-authorization.user-directory",
        "jenkins-derived.diagnostic-export-expansion",
        "geoserver-derived.seller-template-expression",
        "mass-assignment.profile-role",
        "object-authorization.customer-profile",
        "authentication-session.password-reset-swap",
        "authentication-session.unsigned-session-token",
        "security-misconfiguration.operations-status-secret",
        "security-misconfiguration.trusted-forwarding-header",
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
        "path-traversal.report-download",
        "server-side-request-forgery.image-import",
        "sql-injection.product-search",
        "roundcube-derived.support-ticket-html-postprocess",
        "cryptographic-failure.signed-download-forgery",
        "resource-consumption.report-export-fanout",
        "business-workflow.bulk-promotion-redemption",
        "api-inventory.deprecated-operations-endpoint",
        "security-logging.audit-trail-erasure",
        "software-data-integrity.unsigned-partner-webhook",
    }
)


@dataclass(frozen=True)
class Settings:
    environment: str
    database_url: str
    redis_url: str
    object_endpoint: str
    object_access_key: str
    object_secret_key: str
    object_bucket: str
    object_secure: bool
    session_ttl_seconds: int
    reset_token: str
    trial_id: str | None = None
    vulnerability_modules: frozenset[str] = frozenset()
    mock_integration_origin: str = "http://mock-integration:8000"
    public_origin: str = "http://127.0.0.1:18080"
    report_root: str = "/app/benchmark-files"
    # 초기화가 파일 자리를 되돌릴 때 쓰는 원본이다. 비어 있으면
    # 자리 이름에 -origin 을 붙인 곳을 본다.
    report_origin_root: str = ""
    operations_diagnostic_key: str = "ops_sk_live_9f4c27ab1e6d0538"
    untrusted_database_url: str | None = None

    @classmethod
    def from_environment(cls) -> "Settings":
        environment = os.getenv("RUBY_WEB_ENV", "development")
        reset_token = os.getenv("RUBY_WEB_RESET_TOKEN", "")
        trial_id = os.getenv("RUBY_WEB_TRIAL_ID", "").strip() or None
        modules = frozenset(
            item.strip()
            for item in os.getenv("RUBY_WEB_VULNERABILITY_MODULES", "").split(",")
            if item.strip()
        )
        if environment != "development" and not reset_token:
            raise RuntimeError("RUBY_WEB_RESET_TOKEN is required outside development")
        unknown = modules - IMPLEMENTED_VULNERABILITY_MODULES
        if unknown:
            raise RuntimeError(f"unknown vulnerability modules: {sorted(unknown)}")
        if trial_id is not None and re.fullmatch(r"[a-f0-9]{32}", trial_id) is None:
            raise RuntimeError("RUBY_WEB_TRIAL_ID must be 32 lowercase hexadecimal characters")
        if modules and trial_id is None:
            raise RuntimeError("RUBY_WEB_TRIAL_ID is required when a vulnerability is enabled")
        return cls(
            environment=environment,
            database_url=os.getenv(
                "RUBY_WEB_DATABASE_URL",
                "postgresql+psycopg://ruby_app:ruby-app-development-only@postgres:5432/ruby_web",
            ),
            redis_url=os.getenv("RUBY_WEB_REDIS_URL", "redis://redis:6379/0"),
            object_endpoint=os.getenv("RUBY_WEB_OBJECT_ENDPOINT", "minio:9000"),
            object_access_key=os.getenv("RUBY_WEB_OBJECT_ACCESS_KEY", "ruby-development"),
            object_secret_key=os.getenv("RUBY_WEB_OBJECT_SECRET_KEY", "ruby-development-only"),
            object_bucket=os.getenv("RUBY_WEB_OBJECT_BUCKET", "ticket-attachments"),
            object_secure=os.getenv("RUBY_WEB_OBJECT_SECURE", "false").lower() == "true",
            session_ttl_seconds=int(os.getenv("RUBY_WEB_SESSION_TTL", "3600")),
            reset_token=reset_token or "development-reset-only",
            trial_id=trial_id,
            vulnerability_modules=modules,
            mock_integration_origin=os.getenv(
                "RUBY_WEB_MOCK_INTEGRATION_ORIGIN", "http://mock-integration:8000"
            ).rstrip("/"),
            public_origin=os.getenv(
                "RUBY_WEB_PUBLIC_ORIGIN", "http://127.0.0.1:18080"
            ).rstrip("/"),
            report_root=os.getenv("RUBY_WEB_REPORT_ROOT", "/app/benchmark-files"),
            report_origin_root=os.getenv("RUBY_WEB_REPORT_ORIGIN_ROOT", ""),
            operations_diagnostic_key=os.getenv(
                "RUBY_WEB_OPERATIONS_DIAGNOSTIC_KEY",
                "ops_sk_live_9f4c27ab1e6d0538",
            ),
            untrusted_database_url=(
                os.getenv("RUBY_WEB_UNTRUSTED_DATABASE_URL", "").strip() or None
            ),
        )
