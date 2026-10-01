from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class ApiModel(BaseModel):
    # 모르는 필드는 무시한다. 거절하는 경로와 무시하는 경로가 섞여
    # 있으면 쓰레기 필드 하나를 던져 보는 것만으로 어떤 처리기가
    # 본문을 다르게 다루는지 알 수 있다.
    model_config = ConfigDict(extra="ignore")


class RegisterRequest(ApiModel):
    email: str = Field(min_length=5, max_length=320, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    display_name: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(ApiModel):
    email: str = Field(min_length=5, max_length=320, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    password: str = Field(min_length=1, max_length=128)


class PasswordResetRequest(ApiModel):
    email: str = Field(min_length=5, max_length=320, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class PasswordResetConfirm(ApiModel):
    token: str = Field(min_length=20, max_length=256)
    new_password: str = Field(min_length=12, max_length=128)


class UserView(ApiModel):
    id: str
    email: str
    display_name: str
    role: str
    active: bool


class ProfileUpdateRequest(ApiModel):
    display_name: str = Field(min_length=2, max_length=80)


class UpdateUserStatusRequest(ApiModel):
    active: bool


class SessionView(ApiModel):
    token: str
    user: UserView


class ProductView(ApiModel):
    id: str
    shop_id: str
    shop_recent_orders_path: str
    name: str
    description: str
    price_cents: int
    stock: int
    image_path: str | None = None


class SearchResultView(ApiModel):
    id: str
    kind: str
    title: str
    summary: str


class CreateProductRequest(ApiModel):
    id: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(min_length=1, max_length=2000)
    price_cents: int = Field(ge=1, le=10_000_000)
    stock: int = Field(ge=0, le=1_000_000)


class UpdateProductRequest(ApiModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, min_length=1, max_length=2000)
    price_cents: int | None = Field(default=None, ge=1, le=10_000_000)
    stock: int | None = Field(default=None, ge=0, le=1_000_000)


class ImageImportRequest(ApiModel):
    product_id: str = Field(min_length=3, max_length=64)
    # 예시값에 연동 서버 주소를 적어 두면 공개 규격이 내부 호스트를 알려 준다.
    url: str = Field(min_length=10, max_length=2048)


class ImageImportConfigView(ApiModel):
    allowed_source_prefix: str
    example_url: str


class ImageImportView(ApiModel):
    source_url: str
    status_code: int
    content_type: str
    size_bytes: int
    sha256: str
    content: str
    # 가져온 자산이 상품에 연결된 자리다. 반입은 조회가 아니라 저장이다.
    image_path: str | None = None


class SellerReportCatalogEntry(ApiModel):
    name: str
    download_path: str


class SellerReportCatalogView(ApiModel):
    available_reports: list[SellerReportCatalogEntry]


class ReportExportRequest(ApiModel):
    reports: list[Annotated[str, Field(min_length=2, max_length=64)]] = Field(
        min_length=1, max_length=5
    )
    idempotency_key: str = Field(min_length=8, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")


class PromotionRedemptionRequest(ApiModel):
    order_id: str = Field(min_length=8, max_length=64)


class PartnerShipmentEventRequest(ApiModel):
    order_id: str = Field(min_length=8, max_length=64)
    shipment_status: str = Field(pattern=r"^(packed|shipped)$")
    event_id: str = Field(min_length=8, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    occurred_at: int = Field(ge=1_700_000_000, le=4_102_444_800)


class IntegrationFlagRequest(ApiModel):
    credential: str = Field(min_length=16, max_length=256)
    flag: str = Field(pattern=r"^(standard|restricted)$")


class IntegrationFlagView(ApiModel):
    flag: str


class DiagnosticExportRequest(ApiModel):
    arguments: list[Annotated[str, Field(min_length=1, max_length=256)]] = Field(
        min_length=1, max_length=10
    )


class DiagnosticExportView(ApiModel):
    ticket_id: str
    lines: list[str]


class SellerTemplatePreviewRequest(ApiModel):
    product_id: str = Field(min_length=3, max_length=64)
    expression: str = Field(min_length=4, max_length=512)


class SellerTemplatePreviewView(ApiModel):
    product_id: str
    rendered: str
    generated_document: str | None


class SellerTemplateSpecView(ApiModel):
    expression_wrapper: str
    fields: list[str]
    functions: list[str]


class OperationsStatusView(ApiModel):
    status: str
    services: list[str]
    details: dict[str, str] | None = None


class VictimRegistrationRequest(ApiModel):
    user_id: str = Field(min_length=8, max_length=64)


class OperationsMetricsView(ApiModel):
    generated_at: str
    paid_order_count: int
    settlement_total_cents: int
    seller_revenue_cents: dict[str, int]


class SellerDocumentView(ApiModel):
    id: str
    product_id: str
    uploader_id: str
    original_name: str
    content_type: str
    size_bytes: int
    created_at: str


class ArchiveImportView(ApiModel):
    extracted_files: list[str]


class ArchiveHookActivationRequest(ApiModel):
    hook_path: str = Field(min_length=1, max_length=256)


class ArchiveHookActivationView(ApiModel):
    status: str
    manifest_sha256: str
    applied_updates: int
    skipped_updates: int


class OrderLineRequest(ApiModel):
    product_id: str
    quantity: int = Field(ge=1, le=20)


class CreateOrderRequest(ApiModel):
    items: list[OrderLineRequest] = Field(min_length=1, max_length=20)


class OrderLineView(ApiModel):
    product_id: str
    quantity: int
    unit_price_cents: int


class SettlementCallbackRequest(ApiModel):
    order_id: str = Field(min_length=8, max_length=64)
    settled_cents: int = Field(ge=0, le=100_000_000)
    reference: str = Field(min_length=4, max_length=64)


class SettlementCallbackView(ApiModel):
    order_id: str
    status: str
    settled_cents: int


class FulfillmentTaskView(ApiModel):
    id: str
    order_id: str
    product_id: str
    quantity: int
    status: str
    order_status: str
    created_at: str


class OrderView(ApiModel):
    id: str
    status: str
    total_cents: int
    payment_method: str | None
    items: list[OrderLineView]


class PayOrderRequest(ApiModel):
    method: str = Field(pattern=r"^(wallet|test_card)$")


class OrderStatusRequest(ApiModel):
    status: str = Field(pattern=r"^(shipped|refunded)$")


class AttachmentView(ApiModel):
    id: str
    original_name: str
    content_type: str
    size_bytes: int
    status: str


class TicketMessageRequest(ApiModel):
    body: str = Field(min_length=1, max_length=5000)


class TicketStatusRequest(ApiModel):
    status: str = Field(pattern=r"^(open|resolved)$")


class TicketMessageView(ApiModel):
    id: str
    author_id: str
    body: str
    created_at: str


class TicketView(ApiModel):
    id: str
    customer_id: str
    subject: str
    body: str
    status: str
    attachments: list[AttachmentView]
    messages: list[TicketMessageView]


class SupportErrorDiagnosticView(ApiModel):
    ticket_id: str
    error_code: str
    message: str
    debug_context: dict[str, str] | None = None


class GuestInquiryRequest(ApiModel):
    email: str = Field(min_length=5, max_length=320, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    subject: str = Field(min_length=3, max_length=160)
    body: str = Field(min_length=3, max_length=5000)


class GuestInquiryStatusRequest(ApiModel):
    status: str = Field(pattern=r"^(open|resolved)$")


class GuestInquiryView(ApiModel):
    id: str
    email: str
    subject: str
    body: str
    status: str
    created_at: str


class UpdateUserRoleRequest(ApiModel):
    role: str = Field(pattern=r"^(customer|seller_staff|support_staff|admin)$")
